import socket
import Tkinter as tk
import tkSimpleDialog
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

RESPREGEX = r'.+?(?=&)'
NONCEREGEX = r'\&(.*)'
ROOT = tk.Tk()
ROOT.withdraw()

err = "ERROR"
succ = "SUCCESS"

host = '192.168.57.40'
port = 5025
  
with open("keys/public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
    
def encrypt_message(msg):
    return public_key.encrypt(
    msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    
s = socket.socket(socket.AF_INET,
                  socket.SOCK_STREAM)
  
s.connect((host, port))
  
msg = s.recv(1024).decode()
  
while True:
    domain = re.findall(RESPREGEX, msg)[0]
    nonce = re.findall(NONCEREGEX, msg)[0]
    if domain != succ:
        print(msg)
        USER_INP = tkSimpleDialog.askstring(title="Suspicious Domain Detected!",
                        prompt=("Did you mean to access domain:\n" + domain + "\nIf yes please enter password below:"))
        plaintext = (USER_INP + "&" + nonce).encode()
        print(plaintext)
        s.send(encrypt_message(plaintext))

        msg = s.recv(1024).decode()
        resp = re.findall(RESPREGEX, msg)[0]
        nonce = re.findall(NONCEREGEX, msg)[0]
        
        while resp == err:
            USER_INP = tkSimpleDialog.askstring(title="Suspicious Domain Detected!",
                        prompt=("Wrong password entered!\nDid you mean to access domain:\n" + domain + "\nIf yes please enter password below:"))
            plaintext = (USER_INP + "&" + nonce).encode()
            s.send(encrypt_message(plaintext))
            msg = s.recv(1024).decode()
            resp = re.findall(RESPREGEX, msg)[0]
            nonce = re.findall(NONCEREGEX, msg)[0]
    else:
        msg = s.recv(1024)