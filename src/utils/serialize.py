import msgpack
from typing import Tuple, List

def serialize_ctk(encrypted_key_bytes, ciphertext, iv):
    ctk = {
        "encrypted_key_bytes": encrypted_key_bytes,
        "ciphertext": ciphertext,
        "iv": iv
    }
    ctk_bytes = msgpack.packb(ctk)

    return ctk_bytes

def deserialize_ctk(ctk_bytes):
    ctk = msgpack.unpackb(ctk_bytes)
    return (ctk["encrypted_key_bytes"], ctk["ciphertext"], ctk["iv"])

def serialize_ctkmac(ctk_bytes: bytes, mac_bytes: bytes, pseudo_policy: str) -> bytes:
    ctkmac = {
        "ctk": ctk_bytes,
        "mac": mac_bytes,
        "pseudo_policy": pseudo_policy
    }
    ctkmac_bytes = msgpack.packb(ctkmac)

    return ctkmac_bytes

def deserialize_ctkmac(ctkmac_bytes: bytes) -> Tuple[bytes, bytes, str]:
    ctkmac = msgpack.unpackb(ctkmac_bytes)
    return (ctkmac["ctk"], ctkmac["mac"], ctkmac["pseudo_policy"])

def serialize_cert(pseudo_attributes: List[str], signature: bytes) -> bytes:
    return msgpack.packb({
        "pseudo_attributes": pseudo_attributes,
        "signature": signature
    })

def deserialize_cert(cert_bytes: bytes) -> dict[str, List[str] | bytes]:
    return msgpack.unpackb(cert_bytes)

# def serialize_enccert(package: dict[str, bytes]) -> bytes:
#     return msgpack.packb(package)

# def deserialize_enccert(package_bytes: bytes) -> dict[str, bytes]:
#     return msgpack.unpackb(package_bytes)