from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import socket
from thread import *
from threading import Lock
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from tensorflow import keras
from sklearn.feature_extraction.text import CountVectorizer
import tensorflow as tf
import logging
from getmac import get_mac_address as gma

#model class from Ari Gold, 2019 - https://stackoverflow.com/questions/51127344/tensor-is-not-an-element-of-this-graph-deploying-keras-model
class Model:
    def __init__(self):
        self.session = tf.Session()
        self.graph = tf.get_default_graph()
        self.model = None
        # for some reason in a flask app the graph/session needs to be used in the init else it hangs on other threads
        with self.graph.as_default():
            with self.session.as_default():
                try:
                    self.model = keras.models.load_model('ext/domain_classifier')
                    logging.info("Neural Network loaded: ")
                except Exception as e:
                    logging.exception(e)

    def predict(self, x):
        with self.graph.as_default():
            with self.session.as_default():
                y = self.model.predict(x)
        return y

NONCE = 0
THRESHOLD = 0.6
LOCK = Lock()
RESPREGEX = r'.+?(?=&)'
NONCEREGEX = r'\&(.*)'
password = "abcdef"
ERROR = "ERROR"
SUCCESS = "SUCCESS"
nonces = {}
port = 5012
c_mac = gma("eth1")
r = "(?<=q\? )(.*?)(?= A)"
import time
clients = {} # ip:domain map to use as single length channel (think: golang channels)
blocked = set() # set of blocked mac addresses
whitelist = set()
host = '192.168.57.40'

with open("ext/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    backend=default_backend()
)

model = Model()

vocabchars = [char for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"]
count_vect = CountVectorizer(preprocessor=lambda x:x,
                                 tokenizer=lambda x:x, vocabulary=vocabchars)

#https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/ key guide in case i want to add public keys for 2way encryption
        

#packet handler
def dnsinspector(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')
    udp_packet = packet.find('udp')

    #drop packets from blocked unless unblocker packet
    if packet.src in blocked or packet.dst in blocked:       
        tcp_packet = packet.find('tcp')

        if (ip_packet is None or tcp_packet is None or tcp_packet.dstport != port or str(ip_packet.dstip) != host) and packet.src != c_mac:
            event.halt = True
            return

    dns_packet = packet.find('dns')
    
    if dns_packet is None or ip_packet is None:
        return
	
    #if response
    if udp_packet.dstport != 53:
        return

    domain = re.findall(r, str(dns_packet))[0] #obtain domain
	
    if domain in whitelist:
        return

    tokenized = [[char for char in domain]]
    X = count_vect.fit_transform(tokenized)
	
    y_pred = model.predict(X)
    print("Domain: " + domain + " y_pred: " + str(y_pred) + " | " + str(packet.payload.srcip))

    if y_pred[0][0] > THRESHOLD:
        blocked.add(packet.src)
        event.halt = True
        print("Client blocked: " + str(packet.payload.srcip))

        clients[str(packet.payload.srcip)] = [domain, packet.src]


	
	
#handles password responses
def pass_resp_handler(c, hwsrc, domain):
    global NONCE

    response = ""

    while response == "":
        response = private_key.decrypt(
            c.recv(1024),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    
    resp = re.findall(RESPREGEX, response)[0]
    nonce = re.findall(NONCEREGEX, response)[0]
    
    LOCK.acquire()
    if resp == password and nonce == str(nonces[c]):
        print("Password entered successfully")
        msg = SUCCESS + "&" + str(NONCE)
        nonces[c] = NONCE
        NONCE += 1
        LOCK.release()
        
        c.send(msg.encode())

        whitelist.add(domain)
        blocked.remove(hwsrc)
    else:
        print("Incorrect password entered")
        msg = ERROR + "&" + str(NONCE)
        nonces[c] = NONCE
        NONCE += 1
        LOCK.release()
        
        c.send(msg.encode())
        pass_resp_handler(c)
        
def handle_connection(c, ip): 
    global NONCE

    while True:
        if ip in clients:
            domain = clients[ip][0]
            hwsrc = clients[ip][1]

            LOCK.acquire()
            msg = domain + "&" + str(NONCE)
            nonces[c] = NONCE
            NONCE += 1
            LOCK.release()
            
            c.send(msg.encode())

            print("Unblocker message sent.")

            clients.pop(ip, None)
            pass_resp_handler(c, hwsrc, domain)

        time.sleep(0.0001) #sleep .1ms
        
def run_server():
    s = socket.socket(socket.AF_INET,
		          socket.SOCK_STREAM)
	      
    s.bind(('', port))
	    
    s.listen(5000)
	  
    while True:
        c, addr = s.accept()
        
        print("Connected:", str(addr))
	    
        start_new_thread(handle_connection, (c, addr[0], ))
	    
def launch():
	start_new_thread(run_server, ())
	core.openflow.addListenerByName("PacketIn", dnsinspector, priority = 20000)
