from typing import List, Set, Dict, Tuple
from utils.iwt import IndexWildcardTree
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from utils.serialize import deserialize_ctkmac, deserialize_cert
from utils.misc import base_path, eval_policy
from utils.crypto import ecc_decrypt
import pprint, msgpack

class CloudServer():
    def __init__(self, ta_pubkey):
        self.iwt: IndexWildcardTree = None
        self.__private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.__private_key.public_key()
        self.ta_publickey = ta_pubkey

    def search(self, query: List[str]) -> Set[str]:
        files = self.iwt.search(query)
        pprint.pprint(f"'{query[0]}': {files if files else 'Not found'}")
        return files
    
    def wildcard_search(self, query: List[str], debug: bool = False) -> Dict[str, Set[str]] | Set[str]:
        if debug:
            files = self.iwt.wildcard_search(query)
            print(f"'{query[0]}': {files if files else 'Not found'}")
        else:
            files = self.iwt.wildcard_files_only(query)
            # pprint.pprint(f"{files if files else 'Not found'}")

        return files
    
    def proceed_queries(self, queries: List[List[str]], enc_attribute_cert: dict[str, bytes]) -> Set[str]:
        # Decrypt attribute certificate
        attribute_cert_bytes = ecc_decrypt(self.__private_key, enc_attribute_cert)
        attribute_cert = deserialize_cert(attribute_cert_bytes)
        
        # Verify signature of attribute cert
        pseudo_attributes = self.__verify_cert(attribute_cert, self.ta_publickey)
        if not pseudo_attributes:
            raise Exception("Invalid certificate signature")
        
        files = set()
        for query in queries:
            if files:
                files.intersection_update(self.wildcard_search(query))
            else:
                files.update(self.wildcard_search(query))

        # Check access policy
        final_ref = self.__check_policy(files, pseudo_attributes)
        # final_ref = files

        return final_ref
    
    def __verify_cert(self, attribute_cert: dict[str, List[str] | bytes], ta_pubkey) -> List[str] | False:
        pseudo_attributes = attribute_cert["pseudo_attributes"]
        signature = attribute_cert["signature"]

        try:
            ta_pubkey.verify(signature, msgpack.dumps(pseudo_attributes), ec.ECDSA(hashes.SHA256()))
            return pseudo_attributes
        except:
            return False
    
    def __check_policy(self, file_references: Set[str], pseudo_attributes: List[str]):
        final_ref = set()
        for fileref in file_references:
            # deserialize encrypted file
            enc_file_path = base_path / fileref
            with open(enc_file_path, 'rb') as enc_file:
                ctkmac_bytes = enc_file.read()

            _, __, pseudo_policy = deserialize_ctkmac(ctkmac_bytes)

            if eval_policy(pseudo_policy, pseudo_attributes):
                final_ref.add(fileref)

        return final_ref