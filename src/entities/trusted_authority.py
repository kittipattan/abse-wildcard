from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from utils.mac import prf, gen_pseudo_attr
from typing import List
from .data_user import DataUser
from .data_owner import  DataOwner
import hashlib, hmac, os
import msgpack

# DU attributes set
du0 = {
    "role": "DOCTOR",
    "department": "CARDIOLOGY",
    "certification": "LICENSED",
    "organization": "HOSPITAL_A",
    "clearance": "NONE",
    "shift": "DAY",
    "global": "0"
}

du1 = {
    "role": "NURSE",
    "department": "EMERGENCY",
    "certification": "NONE",
    "organization": "HOSTPITAL_B",
    "clearance": "NONE",
    "shift": "NIGHT",
    "global": "0"
}

du2 = {
    "role": "RESEARCHER",
    "department": "BIOMEDICAL",
    "certification": "PHD",
    "organization": "UNIVERSITY",
    "clearance": "MEDIUM",
    "shift": "NONE",
    "global": "0"
}

du3 = {
    "role": "ADMIN",
    "department": "IT_DEPARTMENT",
    "certification": "NONE",
    "organization": "HOSPITAL_A",
    "clearance": "HIGH",
    "shift": "NONE",
    "global": "0"
}

du4 = {
    "role": "DOCTOR",
    "department": "ONCOLOGY",
    "certification": "LICENSED",
    "organization": "HOSPITAL_C",
    "clearance": "MEDIUM",
    "shift": "DAY",
    "global": "0"
}

class TrustedAuthority():
    def __init__(self):
        # Setup public parameters
        self.group = PairingGroup('SS512')   # Supersingular elliptic curve / Type-A / Symmetric
        self.__g = self.group.random(G1)
        self.__a = self.group.random(ZR)
        self.__e = self.group.pair_prod
        self.__ga = self.__g ** self.__a
        self.__h1 = lambda x : self.group.hash(x, G1)
        self.__h2 = lambda key, message : prf(key, message)
        self.__cpabe = CPabe_BSW07(self.group)
        (self.master_public_key, self.__master_secret_key) = self.__cpabe.setup()
        self.__pseudo_key = os.urandom(32)
        self.__private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.__private_key.public_key()

    @property
    def pseudo_key(self):
        return self.__pseudo_key

    # For initializing DU
    def get_du_attributes(self):
        return [du0]
    
    def send_publicparams(self, ds: List[DataUser | DataOwner]):
        public_params = {
            'G0': G1,
            'G1': GT,
            'e': self.__e,
            'p': self.group.order(),
            'g': self.__g,
            'ga': self.__ga,
            'H1': self.__h1,
            'H2': self.__h2
        }

        for d in ds:
            d.public_params = public_params

    def send_secretkey_and_cert(self, dus: List[DataUser]):
        for du in dus:
            du.secret_key = self.gen_sk(du.attributes)    # Assumed to send secret keys via secure channel
            du.attribute_cert = self.__gen_attr_certs(du.attributes)

    def gen_sk(self, du_attr: List[str]):
        secret_key = self.__cpabe.keygen(self.master_public_key, self.__master_secret_key, du_attr)
        return secret_key

    def __gen_attr_certs(self, du_attr: List[str]):
        pseudo_attributes = []
        for attr in du_attr:
            pseudo_attributes.append(gen_pseudo_attr(self.__pseudo_key, attr))

        return (pseudo_attributes, 
                self.__private_key.sign(msgpack.dumps(pseudo_attributes), ec.ECDSA(hashes.SHA256())))

    def test_serial(self):
        a = self.group.random(GT)
        asr = self.group.serialize(a)
        half_asr = len(asr) // 2

        enc_key = hashlib.sha256(asr[:half_asr]).digest()
        mac_key = self.group.deserialize(b'0:' + asr[half_asr:])

        print('enc_key', enc_key)
        print('mac_key', mac_key)
        print('gt__key', self.group.random(ZR))
        
        return