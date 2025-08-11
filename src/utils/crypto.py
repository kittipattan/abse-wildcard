from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Any
import os

def aes_encrypt(key: bytes, message: str | bytes) -> Tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode() if type(message) == str else message) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return (ciphertext, iv)

def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(decrypted_padded) + unpadder.finalize()

    return message

def ecc_encrypt(recipient_publickey, plaintext: bytes) -> dict[str, bytes | Any]:
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()

    shared = eph_priv.exchange(ec.ECDH(), recipient_publickey)

    hkdf = HKDF(hashes.SHA256(), 32, None, b'enc-attr-cert')
    aes_key = hkdf.derive(shared)

    ct, iv = aes_encrypt(aes_key, plaintext)

    return {
        "eph_pub": eph_pub,
        "ciphertext": ct,
        "iv": iv
    }

def ecc_decrypt(private_key, package: dict[str, bytes | Any]) -> bytes:
    sender_eph_pub = package["eph_pub"]
    ct = package["ciphertext"]
    iv = package["iv"]

    shared = private_key.exchange(ec.ECDH(), sender_eph_pub)
    hkdf = HKDF(hashes.SHA256(), 32, None, b'enc-attr-cert')
    aes_key = hkdf.derive(shared)

    plaintext = aes_decrypt(aes_key, ct, iv)

    return plaintext