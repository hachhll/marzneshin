import base64
import hashlib
import uuid

from nacl.public import PrivateKey


def gen_uuid(key: str) -> str:
    try:
        return str(uuid.UUID(key))
    except ValueError:
        digest = hashlib.sha256(key.encode("utf-8")).digest()[:16]
        return str(uuid.UUID(bytes=digest))


def generate_curve25519_pbk(key: str) -> str:
    return base64.b64encode(PrivateKey(key.encode()).encode()).decode()
