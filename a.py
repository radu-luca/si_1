#!/usr/bin/env python3

from os import sendfile
import socket
import selectors
import types

from Crypto.Cipher import AES

sel = selectors.DefaultSelector()
decrypted_key = b""
encrypted_key = b""
mode = "CFB"
text_sent = False
iv = b"eYvMRdCsQeXMkkXX"

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print("accepted connection from", addr)
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def decrypt_key(encrypted_key):
    global decrypted_key
    decipher = AES.new(b'zabcdefghijklmno', AES.MODE_ECB)
    decrypted_key = decipher.decrypt(encrypted_key)
    print(decrypted_key)

def padding(plaintext, n):
    plaintext = bytes(plaintext,'utf-8')
    while len(plaintext) % n != 0:
        plaintext += b" "
    return plaintext

def read_plaintext():
    file = open('plaintext.txt',mode='r')
    plaintext = file.read()
    file.close()
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

def encrypt(plaintext):
    global decrypted_key, mode, iv
    ciphertext = []
    cipher_ecb = AES.new(decrypted_key, AES.MODE_ECB)
    plaintext = padding(plaintext, 16)
    _blocks = [plaintext[i:i+16]for i in range(0, len(plaintext), 16)]

    if mode == "ECB":
        for block in _blocks:
            ciphertext.append(cipher_ecb.encrypt(block))
    else:
        for block in _blocks:
            ciphertext.append( cfb_round(cipher_ecb.encrypt(iv), block) )
    return ciphertext

def service_connection(key, mask, i):
    sock = key.fileobj
    data = key.data
    if i == 1:
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024) 
            if recv_data:
                global encrypted_key
                encrypted_key = recv_data
                decrypt_key(recv_data)
            else:
                print("closing connection to", data.addr)
                sel.unregister(sock)
                sock.close()
        
    elif i == 2:
        global text_sent, mode
        if mask & selectors.EVENT_WRITE:
            if not text_sent:
                # mode = input("ECB or CFB: ")
                sent = sock.send(bytes(mode,'utf-8'))
                sent = sock.send(encrypted_key)
                cipher_blocks = encrypt(read_plaintext())
                for block in cipher_blocks:
                    sock.send(block)
                sock.send(b"stopstopstopstop")
                text_sent = True
            else:
                print("closing connection to", data.addr)
                sel.unregister(sock)
                sock.close()
            
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)  # Should be ready to read
            if recv_data:
                data.outb += recv_data
            else:
                print("closing connection to", data.addr)
                sel.unregister(sock)
                sock.close()
       

host, port = '127.0.0.1', 12345
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print("listening on", (host, port))
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    i = 0
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
                i += 1
            else:
                service_connection(key, mask, i)
except KeyboardInterrupt:
    print("caught keyboard interrupt, exiting")
finally:
    sel.close()