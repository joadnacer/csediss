import pandas as pd
import csv
import whois
from contextlib import suppress
import time
import concurrent.futures
import os
import subprocess
import re
import socket
import ssl
#RETURN ORDER OF BENIGN>COMP>RANSOMWARE BUT CREATE RANSOMWARE AND COMP DICTIONARIES BEFORE GETTING DATA
CONNECTIONS = 1000 #issue is that there's no result so row remains the same
ping_r = 'time=(.*) ms'
writer = csv.writer(open('top1mf.csv', 'a'))
df = pd.read_csv("top-1m.csv", header=None, usecols=[1])
dfc = pd.read_csv("compromised_domains_full.txt", header=None, usecols=[0])
rf = pd.read_csv("ransomwaref", usecols=[1])

start = time.time()
sites = []
cset = set() #set of compromised domains
vset = set() #set of domains in validation (ransomware) set


#gets ping time for a url
def get_ping(row):
	ping = 9999 #non-response value
	print(row[1])
	command = subprocess.Popen("ping -c 1 " + row[1], stdout = subprocess.PIPE,stderr = subprocess.PIPE, shell=True)
	response = command.communicate()[0].decode()
	if bool(re.search(ping_r, response)):
		ping = re.findall(ping_r, response)[0]
	row = row + (ping, )
	return row

		 
#returns a row for benign data
def get_benign(url):
		try:
			print(url[0])
			nullcount = 0
			with suppress(Exception): #dont want exception for no DNS records
				w = whois.whois(url[0])
			#count number of null values in whois results
			for elem in w:
				if w[elem] is None:
					nullcount += 1
			return ("benign",url[0],nullcount)
		except:
			return ("benign",url[0],9999)
	

#returns a row for compromised data
def get_comp(url):
	try:
		print(url[0])
		for i in range(0,len(dfc)):
			nullcount = 0
			with suppress(Exception): #dont want exception for no DNS records
				w = whois.whois(url[0])
			#count number of null values in whois results
			for elem in w:
				if w[elem] is None:
					nullcount += 1
			return ("compromised",url[0],nullcount)
	except:
		return("compromised",url[0],9999)

def get_val(url):
	try:
		print(url[0])
		for i in range(0,len(rf)):
			nullcount = 0
			with suppress(Exception): #dont want exception for no DNS records
				w = whois.whois(url[0])
			#count number of null values in whois results
			for elem in w:
				if w[elem] is None:
					nullcount += 1
			return ("compromised",url[0],nullcount)
	except:
		return("compromised",url[0],9999)

#check ssl cert of domain
def get_ca(row):
	try:
		#get ip address of the domain
		ip = socket.getaddrinfo(row[1],443)[0][4][0]
		print("url: " + row[1])
		#print(ip)
		
		#connect socket
		sock = socket.socket()
		sock.settimeout(10)
		try:
			sock.connect((ip,443))
		except socket.timeout: #timeout - site down?
			row = row + (1, ) 
			return row
			

		#add ssl support to socket
		try:
			sock = ssl.wrap_socket(sock,cert_reqs=ssl.CERT_REQUIRED, ca_certs="cacert.pem")
		except: #self signed
			row = row + (2,)
			return row

		#get and check cert
		try:
			cert = sock.getpeercert()
		except: #no cert?
			row = row + (3, )
			return row
		#how to check hostname match?
		
		row = row + (0, )
		return row
	except: #no ip (i think)
		row = row + (1, )
		return row

#create val set (to avoid duplicates in compromised and benign set)
for domain in rf.values:
	vset.add(domain[0])

#create compromised set (to avoid duplicates in benign set):
for domain in dfc.values:
	cset.add(domain[0])

#get whois records concurrently
with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
    #get benign set
    future_to_whois = (executor.submit(get_benign, url) for url in df.values[:115000])
    for future in concurrent.futures.as_completed(future_to_whois):
    	try: #get row
    		row = future.result()
    	except Exception as exc: #pass exception
    		pass
    	finally: #append row to array
    		if row[1] not in vset and row[1] not in cset: #not a compromised domain
	    		sites.append(row)
	    		print(len(sites))
	    		
    #get compromised set
    future_to_whois = (executor.submit(get_comp, url) for url in dfc.values)
    for future in concurrent.futures.as_completed(future_to_whois):
    	try: #get row
    		row = future.result()
    	except Exception as exc: #pass exception
    		pass
    	finally: #append row to array
    		if row[1] not in vset: #not already in validation set
	    		sites.append(row)
	    		print(len(sites))
	    		
    #get validation set
    future_to_whois = (executor.submit(get_val, url) for url in rf.values)
    for future in concurrent.futures.as_completed(future_to_whois):
    	try: #get row
    		row = future.result()
    	except Exception as exc: #pass exception
    		pass
    	finally: #append row to array
    		sites.append(row)
    		print(len(sites))
    		
    
    #get ping times
    sites = executor.map(get_ping, sites)
    sites = list(sites)
    
    #get ca status times
    sites = executor.map(get_ca, sites)
    sites = list(sites)
 
#write rows to dataset csv
writer.writerows(sites)



