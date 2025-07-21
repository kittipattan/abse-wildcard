from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import GT
from charm.core.engine.util import objectToBytes, bytesToObject
from utils.mac import HomomorphicMAC, gen_pseudo_policy
from utils.crypto import aes_encrypt, aes_decrypt
from utils.misc import base_path
from utils.serialize import serialize_ctk, serialize_ctkmac
from utils.iwt import IndexWildcardTree
from charm.toolbox.pairinggroup import ZR
from typing import List, Tuple, Any
import hashlib, hmac
from .data_user import DataUser
import pprint, os

global_keywords = ['A+', 'Married', 'Type 2 Diabetes', 'Diabetes', 'Hypertension', 'Chronic Conditions', 'Coronary Artery Disease']

class DataOwner():
    def __init__(self, ta_mpk, group):
        self.ta_mpk = ta_mpk    # MPK from TA
        self.__group = group
        self.public_params = {}
        self.__cpabe = CPabe_BSW07(self.__group)
        self.__iwt = IndexWildcardTree()
        self.__trapdoor_key_cpabe = self.__group.random(GT)  # To be encrypted using CP-ABE
        self.__trapdoor_key = hashlib.sha256(self.__group.serialize(self.__trapdoor_key_cpabe)).digest() # K_td
        self.__pseudo_key = None

    @property
    def cpabe(self):
        return self.__cpabe
    
    @property
    def iwt(self):
        return self.__iwt
    
    @property
    def pseudo_key(self):
        return self.__pseudo_key
    
    @pseudo_key.setter
    def pseudo_key(self, key: bytes):
        self.__pseudo_key = key

    # def encrypt_ehrs(self, pkap: List[Tuple]):
    #     cts = []
    #     for (number, keywords, access_policy) in pkap:
    #         ct = self.__encrypt_ehr(number, keywords, access_policy)
    #         cts.append(ct)
    #     return cts
    
    def encrypt_ehr(self, filename: str, access_policy: str) -> Tuple[str, List]:
        number = filename.split('.')[0].split('_')[-1]
        plain_file_path = base_path / filename
        with open(plain_file_path, 'rb') as plain_file:
            message = plain_file.read()
            
        # Randonly select a secret
        s = self.__group.random(ZR)

        # Derive symmetric encryption key
        # k = self.public_params['H2'](hmac_key, str(s))
        # k_bytes = k.to_bytes(32)
        cpabe_key = self.__group.random(GT)
        (encrypting_key, mac_key) = self.__derive_keys(cpabe_key)

        # Encrypt the message M under the key k
        ciphertext, iv = aes_encrypt(encrypting_key, message)
        
        # Encrypt keys with CP-ABE
        encrypted_key_bytes = self.__encrypt_key(cpabe_key, access_policy)
        ctk_bytes = serialize_ctk(encrypted_key_bytes, ciphertext, iv)
        
        # Generate integrity tag over the ciphertext using HMAC
        mac = self.__gen_mac(ctk_bytes, mac_key)
        mac_bytes = self.__group.serialize(mac)

        # Generate pseudo-policy
        if not self.pseudo_key:
            raise Exception("DO has no pseudo key")
        pseudo_policy = gen_pseudo_policy(self.__pseudo_key, access_policy)

        ctkmac_bytes = serialize_ctkmac(ctk_bytes, mac_bytes, pseudo_policy)

        enc_file_name = f"{number}_encrypted"
        enc_file_path = base_path / enc_file_name
        with open(enc_file_path, 'wb') as enc_file:
            enc_file.write(ctkmac_bytes)

        # Mark as discard
        idx = []
        # for w in keywords:
        #     T = self.public_params['H1'](w) ** s    # Create keyword token
        #     tag = self.__gen_mac(w, mac_key)        # Create Authentication tag
        #     idx.append((self.__group.serialize(T), tag))
        #     # idx.append((T, tag))

        CT = (enc_file_name, idx)  # To be uploaded to Cloud Server
        return CT
    
    def __derive_keys(self, cpabe_key) -> Tuple[bytes, Any]:
        cpabe_key_bytes = self.__group.serialize(cpabe_key)
        half_len = len(cpabe_key_bytes) // 2
        encrypting_key = hashlib.sha256(cpabe_key_bytes[:half_len]).digest()      # K_enc
        mac_key = self.__group.deserialize(b'0:' + cpabe_key_bytes[half_len:])    # K_mac
        return (encrypting_key, mac_key)
    
    def __encrypt_key(self, cpabe_key, access_policy) -> bytes:
        encrypted_key = self.__cpabe.encrypt(self.ta_mpk, cpabe_key, access_policy)
        encrypted_key_bytes = objectToBytes(encrypted_key, self.__group)
        return encrypted_key_bytes

    def __gen_mac(self, message, secret_key) -> Any:
        mac_generator = HomomorphicMAC(self.__group, secret_key)
        hashval = self.__group.hash(message, ZR)
        mac = mac_generator.sign(hashval)
        return mac
    
    def send_enc_trapdoor_key(self, dus: List[DataUser]):
        enc_trapdoor_key = self.__cpabe.encrypt(self.ta_mpk, self.__trapdoor_key_cpabe, '(global)')
        for du in dus:
            du.recv_enc_trapdoor_key(enc_trapdoor_key)

    def construct_iwt(self, kwfile_map: List[Tuple[str, str]]):
        for keyword, filename in kwfile_map:
            trapdoor = self.__gen_trapdoor(keyword)
            self.__iwt.insert(trapdoor, filename)

        # pprint.pprint(self.__iwt.get_word_files_mapping())

    def __gen_trapdoor(self, keyword: str) -> List[str]:
        keyword = keyword.encode()
        trapdoor = []
        for i in range(1, len(keyword)+1):
            td = hmac.new(self.__trapdoor_key, keyword[0:i], hashlib.sha256).hexdigest()
            trapdoor.append(td)
        return trapdoor

    def gen_pseudo_attr(self, attribute: str):
        pass

    def gen_pseudo_policy(self, attributes: str):
        pass