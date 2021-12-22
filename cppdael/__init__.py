from typing import Literal, Optional

from .cppdael import (
    decrypt_string,
    decrypt,
    encrypt,
    Rijndael,
    MODE_CFB,
    MODE_CBC,
    MODE_ECB,
)
from .paddings import PaddingBase, ZeroPadding, Pkcs7Padding


BlockCipherMode = Literal[0, 1, 2]
RijndaelBlockSize = Literal[16, 24, 32]


def decrypt_unpad(
    block_cipher_mode: BlockCipherMode,
    block_size: RijndaelBlockSize,
    key: bytes,
    iv: bytes,
    cipher: bytes,
    padding: PaddingBase,
    hard_key_size: Optional[int] = None,
) -> bytes:
    return padding.decode(
        decrypt(block_cipher_mode, block_size, key, iv, cipher, hard_key_size)
    )


def pad_encrypt(
    block_cipher_mode: BlockCipherMode,
    block_size: RijndaelBlockSize,
    key: bytes,
    iv: bytes,
    plain_text: bytes,
    padding: PaddingBase,
    hard_key_size: Optional[int] = None,
) -> bytes:
    return encrypt(
        block_cipher_mode,
        block_size,
        key,
        iv,
        padding.encode(plain_text),
        hard_key_size,
    )


__all__ = [
    "decrypt_string",
    "decrypt",
    "decrypt_unpad",
    "encrypt",
    "pad_encrypt",
    "Rijndael",
    "ZeroPadding",
    "Pkcs7Padding",
    "MODE_CFB",
    "MODE_CBC",
    "MODE_ECB",
]
