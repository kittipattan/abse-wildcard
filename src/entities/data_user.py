from typing import Dict, List
from utils.misc import base_path
from utils.serialize import deserialize_ctk, deserialize_ctkmac
from utils.crypto import aes_decrypt
from charm.core.engine.util import bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import hashlib, hmac

class DataUser():
    def __init__(self, attributes: Dict[str, str], ta_mpk, group, id: int = 0, is_experiment: bool = False):
        self.__attributes = attributes
        self.ta_mpk = ta_mpk
        self.__group = group
        self.id = id    # For debug and experiment
        self.__secret_key = {}
        self.__public_params = {}
        self.__cpabe = CPabe_BSW07(self.__group)
        self.__trapdoor_key = None
        self.attribute_cert = None
        self.is_experiment = is_experiment
        
    @property
    def attributes(self):
        return list(self.__attributes.values())

    @property
    def public_params(self):
        return self.__public_params
    
    @public_params.setter
    def public_params(self, pp):
        if not isinstance(pp, Dict):
            raise TypeError("public_params must be Dict")
        self.__public_params = pp

    @property
    def secret_key(self):
        return self.__secret_key
    
    @secret_key.setter
    def secret_key(self, sk):
        if not isinstance(sk, Dict):
            raise TypeError("secret_key must be Dict")
        self.__secret_key = sk

    def decrypt_ehrs(self, filenames: List[str]):
        filepaths = []
        for filename in filenames:
            path = self.decrypt_ehr(filename)
            filepaths.append(path)
        return filepaths

    def decrypt_ehr(self, filename: str):
        number = filename.split('_')[0]
        enc_file_path = base_path / filename
        with open(enc_file_path, 'rb') as enc_file:
            ctkmac_bytes = enc_file.read()

        ctk_bytes, mac_bytes, policy = deserialize_ctkmac(ctkmac_bytes)

        mac = self.__group.deserialize(mac_bytes)
        # check mac here
        # TODO

        encrypted_key_bytes, ciphertext, iv = deserialize_ctk(ctk_bytes)
        cpabe_key = self.__decrypt_key(encrypted_key_bytes)
        if not cpabe_key:
            raise Exception(f"DU: {self.id} | file: {filename} | decrypt_key: decrypt unsuccessful")
        
        (encrypting_key, mac_key) = self.__derive_keys(cpabe_key)
        try:
            message = aes_decrypt(encrypting_key, ciphertext, iv)
        except:
            raise Exception(f"DU{self.id} decrypt_ehr: decrypt unsuccessful")
        
        decrypted_file_path = base_path / f"{number}_decrypted.txt"

        if not self.is_experiment:
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(message)

        return decrypted_file_path

    def __decrypt_key(self, encrypted_key_bytes):
        encrypted_key = bytesToObject(encrypted_key_bytes, self.__group)
        cpabe_key = self.__cpabe.decrypt(self.ta_mpk, self.__secret_key, encrypted_key)
        return cpabe_key
        
    def __derive_keys(self, cpabe_key):
        cpabe_key_serialized = self.__group.serialize(cpabe_key)
        half_len = len(cpabe_key_serialized) // 2
        encrypting_key = hashlib.sha256(cpabe_key_serialized[:half_len]).digest()      # K_enc
        mac_key = self.__group.deserialize(b'0:' + cpabe_key_serialized[half_len:])    # K_mac
        return (encrypting_key, mac_key)
    
    def recv_enc_trapdoor_key(self, enc_trapdoor_key):
        try:
            trapdoor_key_cpabe = self.__cpabe.decrypt(self.ta_mpk, self.__secret_key, enc_trapdoor_key)
            self.__trapdoor_key = hashlib.sha256(self.__group.serialize(trapdoor_key_cpabe)).digest()
        except:
            raise Exception(f"DU{self.id} recv_enc_trapdoor_key: decrypt unsuccessful")

    def query(self, queries: List[str]) -> List[List[str]]:
        trapdoors = []
        for i, q in enumerate(queries):
            td = self.__gen_trapdoor(q.encode())
            trapdoors.append(td)
            # print(f"\tquery {i}: {q}")
            # print(f"\t\ttrapdoor: {td[0]}")   # only print first character
        return trapdoors

    def __gen_trapdoor(self, keyword: bytes) -> List[str]:
        trapdoor = []
        for i in range(0, len(keyword)):
            if keyword[i] in [42, 63]:  # *, ?
                td = chr(keyword[i])
            else:
                td = hmac.new(self.__trapdoor_key, keyword[0:i+1], hashlib.sha256).hexdigest()

            trapdoor.append(td)

        return trapdoor
    