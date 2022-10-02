
import base64
import logging
import os
import json
import random
import requests
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES, PUBLIC_KEY_TYPES
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding, hashes

from util.container import ENV

log = logging.getLogger()

KEY_SIZE = 32
IV_SIZE = 16

# generates AES256 keys.
class AESKey():
    def __init__(self, key: bytes = None, iv: bytes = None):
        if (key is None):
            self.key = os.urandom(KEY_SIZE)
        if (iv is None):
            self.iv = os.urandom(IV_SIZE)
        
        pass

    def __eq__(self, __o: object) -> bool:
        pass
    
    # writes the key as a dict of key and iv encoded with b64
    def to_json(self):
        return json.dumps({
            'key': base64.b64decode(self.key),
            'iv': base64.b64encode(self.iv)
        })

    @classmethod
    def from_json(cls, data: str):
        d = json.dumps(data)
        k = base64.b64decode(d['key'])
        i = base64.b64decode(d['id'])
        return AESKey(k, i)

    # Encrypts this AES key with a private key
    def to_encrypt(self, public_key: PUBLIC_KEY_TYPES):
        return public_key.encrypt(
            AESKey.serialize(self.key),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Decrypts an AES key with a private key
    @classmethod
    def from_encrypt(cls, data, private_key: PRIVATE_KEY_TYPES):
        return AESKey.deserialize(
                private_key.decrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )
            

    @classmethod
    def serialize(cls, key: "AESKey"):
        return base64.b64encode(key.to_json())

    @classmethod
    def deserialize(cls, data):
        return AESKey.from_json(base64.b64decode(data))

    @classmethod
    def from_b64(cls, data: bytes):
        d = base64.b64decode(data)
        return cls.from_json(d)
        

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data['key'], data['iv'])

    @classmethod
    def from_list(cls, data: list or tuple):
        return cls(data[0], data[1])

    def __eq__(self, __o: object) -> bool:
        if type(__o) is not AESKey: return
        return self.key == __o.key and self.iv == __o.iv

    def get_cipher(self, algo=algorithms.AES, mode=modes.CBC):
        return Cipher(algo(self.key), mode(self.iv))

    # encrypt data with this key
    def encrypt(self, data):
        padder = padding.PKCS7(KEY_SIZE * 4).padder()
        if (type(data) == str):
            data = data.encode()
        padded_data = padder.update(data) + padder.finalize()
        cipher = self.get_cipher()
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    # decrypt data with this key
    def decrypt(self, data):
        cipher = self.get_cipher()
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(KEY_SIZE * 4).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def verify_decrypt(self, data_to_decrypt: bytes, data_result: bytes):
        return self.decrypt(data_to_decrypt) == data_result

    def verify_encrypt(self, data_to_encrypt: bytes, data_result: bytes):
        return self.encrypt(data_to_encrypt) == data_result

class RSAKey():
    def __init__(self) -> None:
        self.public_key = None
        self.private_key = None
    
    def generate_keys(self):
        if (self.private_key):
            log.info("Keys already generated!")
            return
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, data: bytes):
        return self.public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, data: bytes):
        return self.private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def private_key_to_pem(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def public_key_to_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    


    @classmethod
    def from_pem_file(cls, file="private_key.pem"):
        log.info(f"Loading private key {file}..")
        if (not os.path.exists(file)):
            key = RSAKey()
            log.info(f"No private key to load! Generating key for {file}..")
            key.generate_keys()
            log.info(f"Saving newly generated key: {file}..")
            key.save(file)
            return key
        else:            
            with open(file, 'rb') as f:
                key = RSAKey()
                key.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
                key.public_key = key.private_key.public_key()
                return key

   
    def save(self, file="private_key.pem"):
        if (not self.private_key):
            raise ValueError("No private key to save")

        with open(file, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
                )
            )

        


class KeyCommunicator():

    @classmethod 
    def receive_enc_aes_key(self, data: str, dec_key: PRIVATE_KEY_TYPES):
        log.debug("Getting key from JSON POST...")

        data = json.loads(data)
        key = (data['key'])
        # verify the AES key
        v = data['validator']
        if (key.verify_decrypt(v[0], v[1])):
            log.debug("Key is valid, returning...")
            return key
        else:
            log.debug("Key is not valid, returning...")
            return None
        pass

    @classmethod
    def get_aes_key(cls, id=None):
        if (id is None): return

    @classmethod
    def get_public_key(cls):
        r = requests.get(
            f"http://{ENV.ENCRYPT_SERVER_HOST}:{ENV.ENCRYPT_SERVER_PORT}/key")
        
        if (r.status_code == 200):
            key = serialization.load_pem_public_key(r.content)
            return key

        return None

    def send_aes_key(self, public_key: PUBLIC_KEY_TYPES, aes_key: AESKey, id: str):
        if (public_key is None or 
            aes_key is None or
            id is None): return

        
        # encrypt some data with aes key for validating on the other end

        validator_bytes = os.urandom(32)
        validator = aes_key.encrypt(validator_bytes)        # send encrypted aes key to server
        r = requests.post(
            url=f"http://{ENV.ENCRYPT_SERVER_HOST}:{ENV.ENCRYPT_SERVER_PORT}/key",
            data=json.dumps({
            'id': base64.b64encode(id),
            'key': AESKey.encrypt(aes_key, public_key),
            'validator': [base64.b64encode(validator), base64.b64encode(validator_bytes)] 
            })
        )

        if (requests.get(r.status_code) == 200):
            return True


        pass
        
      


class Keygen():
    @classmethod
    def get_private_key_pem(key: PRIVATE_KEY_TYPES):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def get_private_key_der(key: PRIVATE_KEY_TYPES):
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def get_public_key_pem_string(key):
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    @classmethod
    def get_private_key_pem_string(key):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    @classmethod
    def get_public_key_der_string(key):
        return key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    @classmethod
    def get_private_key_der_string(key):
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    @classmethod
    def get_public_key_pem_file(key, file_name):
        with open(file_name, 'wb') as f:
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    @classmethod
    def rsa_private_key_from_pem(cls, pem):
        return serialization.load_pem_private_key(
            pem,
            password=None
        )
        

    @classmethod
    def rsa_public_key_from_pem(cls, pem: bytes):
        return serialization.load_pem_public_key(
            pem
            )

    @classmethod
    def generate_aes_key(cls):
        return AESKey()



# Used to store/retrieve AES-256 keys to a file.
class KeyStore():

    _keys = None

    @classmethod
    def get_key(cls, key_name):
        return cls._keys[key_name]
    
    @classmethod
    def save_key(cls, key_name, key):
        cls._keys[key_name] = key
        pass
    

    @classmethod 
    def load_keys_from_file(cls):
        if (os.exists(ENV.KEYSTORE_FILE)):
            with open(ENV.KEY_STORE_FILE, 'r') as f:
                d = json.load(f)
                
                cls._keys = d
        else:
            cls._keys = dict()

        return cls._keys

    @classmethod
    def save_keys_to_file(cls):
        with open(ENV.KEYSTORE_FILE, 'w') as f:
            json.dump(cls._keys, f)
        pass
    
