from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

def security_setup():
    privatekey = RSA.generate(2048)
    publickey = privatekey.publickey()

    return privatekey, publickey

def decrypt_rsa(sock, privatekey, ciphertext):
    cipherrsa = PKCS1_OAEP.new(privatekey)
    plaintext = cipherrsa.decrypt(ciphertext)
    return plaintext

def decrypt_session(sessionkey, ciphertext):
    iv = ciphertext[:16]
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext)
    plaintext = plaintext[16:]
    return plaintext

def encrypt_session(sessionkey, plaintext):
    iv = Random.new().read(16)
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    return ciphertext

def get_key(login, password):
    return SHA.new(login + password).digest()