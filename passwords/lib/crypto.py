import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def hasher(passwd: str) -> bytes:
    if isinstance(passwd, str):
        salt = bytes(0)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passwd.encode()))
        return key
    else:
        raise TypeError(f"expected str, got {type(passwd)}")


def cryptor(passwd: [bytes, str]) -> Fernet:
    if isinstance(passwd, str):
        key = hasher(passwd)
    elif isinstance(passwd, bytes):
        key = passwd
    else:
        raise TypeError(f"Expected bytes or str, got {type(passwd)}")

    return Fernet(key)
