import socket
from Crypto.Cipher import AES


HOST = '127.0.0.1'  
PORT = 12345       

encrypted_key = b""
key = ""
iv = b"eYvMRdCsQeXMkkXX"

def decrypt_key():
    global key, encrypted_key
    decipher = AES.new(b'zabcdefghijklmno', AES.MODE_ECB)
    key = decipher.decrypt(encrypted_key)

def unpadding(plaintext):
    while plaintext[-1] == ord(' '):
        plaintext = plaintext[:-1]
    return plaintext

def xor(var, key):
        return bytes(a ^ b for a, b in zip(var, key))

def cfb_round(cipher_block, plaintext):
    sub_cipher = cipher_block[:16]
    ciphertext = xor(sub_cipher, plaintext)
    shift_iv(sub_cipher)
    return ciphertext

def shift_iv(cipher):
    global iv
    iv = iv[:-16] + cipher

def decrypt(alg):
    data = b""
    plaintext = b""
    decipher = AES.new(key, AES.MODE_ECB)
    if alg == "ECB":
        data = s.recv(16)
        while data != b"stopstopstopstop":
            plaintext += decipher.decrypt(data)
            data = s.recv(16)
        plaintext = unpadding(plaintext)
        print(plaintext)
    else:
        data = s.recv(16)
        while data != b"stopstopstopstop":
            plaintext += cfb_round(decipher.encrypt(iv), data)
            data = s.recv(16)
        plaintext = unpadding(plaintext)
        print(plaintext)




with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    data = s.recv(3)
    encrypted_key = s.recv(16)
    decrypt_key()
    if data == b'ECB':
        decrypt("ECB")
    else:
        decrypt("CFB")
