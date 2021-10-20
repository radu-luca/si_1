import socket
import random
import string
from Crypto.Cipher import AES


HOST = '127.0.0.1'  
PORT = 12345       


def generate_key(length):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    key = bytes(generate_key(16),'utf-8')
    print(key)
    key2 = bytes("zabcdefghijklmno",'utf-8')
    cipher = AES.new(key2, AES.MODE_ECB)
    encrypted = cipher.encrypt(key)
    s.sendall(encrypted)
