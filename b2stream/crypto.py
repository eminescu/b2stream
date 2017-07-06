
from cryptography.hazmat.backends import default_backend
backend = default_backend()

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass, os
def derive_key(salt=None):
    # Salts should be randomly generated
    if not salt:
        salt = os.urandom(16)
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return ( kdf.derive(getpass.getpass().encode("utf-8")), salt )

"""
Encrypted part structure:
---------------
|0xB2
|version (2byte)
|authenticated tag (tag_size)
|data_size (64bit little-endian long long)
|data
--------------
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
import struct
import hashlib
import binascii
import sys
def decrypt(source, key, iv, tag_size, content_sha1, ignore_invalid_tag):
    digest = hashlib.sha1()
    i = 0
    while True:
        header = source.read(3)
        tag = source.read(tag_size)
        #tag = b'\x56' + tag[1:]

        if not header:
            if content_sha1 != 'none' and digest.hexdigest() != content_sha1:
                raise Exception("SHA1 checksum mismatch")
            return

        part_iv = increment_iv(iv,i)

        print("part:", i+1, file=sys.stderr)
        print("iv:", binascii.hexlify(part_iv), file=sys.stderr)
        print("tag:", binascii.hexlify(tag[0:tag_size]), tag_size, file=sys.stderr)

        digest.update(header)
        digest.update(tag)

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(part_iv, tag, tag_size),
            backend=backend
        ).decryptor()

        size = source.read(8)
        digest.update(size)
        size = struct.unpack('>Q', size)[0]
        print("data size:", size, file=sys.stderr)
        while True:
            b = source.read(min(8192,size))
            digest.update(b)
            size -= len(b)
            #print(binascii.hexlify(b[0:16]).decode('ascii'), size, file=sys.stderr)
            yield decryptor.update(b)
            if not size:
                break
        print("sha1checksum:", digest.hexdigest(), file=sys.stderr)
        try:
            yield decryptor.finalize()
        except InvalidTag as e:
            print("!!! Authenticated tag is invalid: data have been altered", file=sys.stderr)
            if not ignore_invalid_tag:
                raise

        i += 1

def generate_iv(iv_size):
    return os.urandom(iv_size)

def increment_iv(iv, n):
    return (int.from_bytes(iv,'big')+n).to_bytes(len(iv),'big',signed=False)

import tempfile
def encrypt_part( upload_source, key, iv, tag_size ):
    cipher_file = tempfile.TemporaryFile("w+b")

    # write header + version
    cipher_file.write(b'\xB2\x00\x01')

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, None, tag_size),
        backend=backend
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    #encryptor.authenticate_additional_data(associated_data)

    # write data
    cipher_file.seek(tag_size+8, 1)
    upload_source.seek(0)
    while True:
        b = upload_source.read(8192)
        if b:
            cipher_file.write( encryptor.update(b) )
        else:
            cipher_file.write( encryptor.finalize() )
            break

    size = cipher_file.tell()
    data_size = upload_source.tell()

    print("iv:", binascii.hexlify(iv))
    print("tag:", binascii.hexlify(encryptor.tag[0:tag_size]), tag_size)
    print("file size:", size)
    print("data size:", data_size)

    # write tag
    cipher_file.seek(3)
    cipher_file.write(encryptor.tag[0:tag_size])

    # write data size
    cipher_file.write(struct.pack('>Q', data_size))

    return (cipher_file, size)
