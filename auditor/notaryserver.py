#!/usr/bin/env python
from __future__ import print_function
import base64, binascii, hashlib, hmac, os
import socket, sys, time
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import subprocess

#file system setup.
datadir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(datadir))
installdir = os.path.dirname(datadir)
time_str = time.strftime("%d-%b-%Y-%H-%M-%S", time.gmtime())

#Globals
rs_choice = 0
tlsns = None

def sign_data(data_to_be_signed):
    #TODO clean up
    with open('tempsigfile','wb') as f: f.write(data_to_be_signed)
    pkl = os.path.expanduser('~/sim_rem/taas_privkey.pem')
    return subprocess.check_output(['openssl','dgst','-ecdsa-with-SHA1',
    '-sign',pkl,'-keyform','PEM', 'tempsigfile'])
    

class myHandler(BaseHTTPRequestHandler):
    #Handler for the GET requests
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"
    def respond(self, headers):
	# we need to adhere to CORS and add extra headers in server replies
	keys = [k for k in headers]
	self.send_response(200)
	self.send_header('Access-Control-Allow-Origin', '*')
	self.send_header('Access-Control-Expose-Headers', ','.join(keys))
	for key in headers:
	    self.send_header(key, headers[key])
	self.end_headers()
    
    def do_HEAD(self):                
	print ('minihttp received ' + self.path + ' request',end='\r\n')
	# example HEAD string "/page_marked?accno=12435678&sum=1234.56&time=1383389835"
	resp, dat = process_messages(self.path[1:])
	dat = base64.b64encode(dat)
	self.respond({'response': resp, 'data': dat})
	#TODO handle unexpected requests
		
def process_messages(msg):
    global tlsns
    if msg.startswith('rcr_rsr_rsname_n:'):                
	msg_data = base64.b64decode(msg[len('rcr_rsr_rsname_n:'):])
	tlsns = shared.TLSNClientSession()
	rss = shared.TLSNClientSession()
	rss.client_random = msg_data[:32]
	rss.server_random = msg_data[32:64]
	global rs_choice
	rs_choice_first5 = msg_data[64:69]
	print ('Got rschoice: ', rs_choice_first5)
	rs_choice = [k for k in  shared.reliable_sites.keys() if k.startswith(rs_choice_first5)][0]
	if not rs_choice:
	    raise Exception('Unknown reliable site', rs_choice_first5)
	n = msg_data[69:]
	rss.server_modulus, rss.server_exponent = (int(shared.reliable_sites[rs_choice][1],16),65537)
	#TODO currently can only handle 2048 bit keys for 'reliable site'
	rss.server_mod_length = shared.bi2ba(256)
	rss.set_auditor_secret()
	rss.set_enc_second_half_pms()           
	rrsapms = shared.bi2ba(rss.enc_second_half_pms)

	tlsns.auditor_secret, tlsns.auditor_padding_secret=rss.auditor_secret, rss.auditor_padding_secret
	tlsns.server_mod_length, tlsns.server_modulus = shared.bi2ba(len(n)), shared.ba2int(n)
	tlsns.set_enc_second_half_pms()            
	return 'rrsapms_rhmac_rsapms:',rrsapms+rss.p_auditor+shared.bi2ba(tlsns.enc_second_half_pms)            
	  
    elif msg.startswith('cs_cr_sr_hmacms_verifymd5sha:'): 
	print (time.strftime('%H:%M:%S', time.localtime()) + ': Processing data from the auditee.')
	request = base64.b64decode(msg[len('cs_cr_sr_hmacms_verifymd5sha:'):])
	assert len(request) == 125
	tlsns.chosen_cipher_suite = int(request[:1].encode('hex'),16)
	tlsns.client_random = request[1:33]
	tlsns.server_random = request[33:65]
	md5_hmac1_for_ms=request[65:89]
	verify_md5 = request[89:105]
	verify_sha = request[105:125]
	tlsns.set_auditor_secret()
	tlsns.set_master_secret_half(half=1,provided_p_value=md5_hmac1_for_ms)         
	garbageized_hmac = tlsns.get_p_value_ms('auditor',[2]) #withhold the server mac
	hmac_verify_md5 = tlsns.get_verify_hmac(verify_sha, verify_md5, half=1) 
	if not tlsns.auditor_secret: 
	    raise Exception("Auditor PMS secret data should have already been set.")            
	hmacms_hmacek_hmacverify = tlsns.p_auditor[24:]+garbageized_hmac+hmac_verify_md5
	return 'hmacms_hmacek_hmacverify:',hmacms_hmacek_hmacverify
    
    elif msg.startswith('verify_md5sha2:'):
	md5sha2 = base64.b64decode(msg[len('verify_md5sha2:'):])
	md5hmac2 = tlsns.get_verify_hmac(md5sha2[16:],md5sha2[:16],half=1,is_for_client=False)
	return 'verify_hmac2:', md5hmac2
    
    elif msg.startswith('commit_hash:'):
	commit_hash = base64.b64decode(msg[len('commit_hash:'):])
	response_hash = commit_hash[:32]
	data_to_be_signed = response_hash + tlsns.pms2
	signature = sign_data(data_to_be_signed)
	return 'pms2:',tlsns.pms2 + signature
    else:
	assert False, "received invalid argument to process_messages"
        
if __name__ == "__main__":
    import shared
    shared.load_program_config()
    shared.import_reliable_sites(os.path.join(installdir,'shared'))
    try:
	server = HTTPServer(('',8080), myHandler)
	server.serve_forever()
    except KeyboardInterrupt:
	print ('caught keyboard interrupt')
	server.socket.close()

    