#!/usr/bin/env python
from __future__ import print_function
import base64, binascii, hashlib, hmac, os
import socket, sys, time, subprocess
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

mps = {}

def sign_data(data_to_be_signed):
    #TODO clean up
    with open('tempsigfile','wb') as f: f.write(data_to_be_signed)
    pkl = os.path.expanduser('~/sim_rem/taas_privkey.pem')
    return subprocess.check_output(['openssl','rsautl','-sign','-inkey',pkl,'-keyform','PEM', '-in','tempsigfile'])

class myHandler(BaseHTTPRequestHandler):
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
	global mps
	print ('minihttp received ' + self.path + ' request',end='\r\n')
	client_id = self.path[1:7] #6 char 'unique' id - TODO
	if client_id not in mps:
	    if len(mps) > 100:
		self.respond({'response':'busy','data':'too many clients'})
		return
	    mps[client_id] = MessageProcessor(client_id)
	    print ('now serving ', len(mps), 'clients')
	resp, dat = mps[client_id].process_messages(self.path[7:])
	if self.path[7:].startswith('commit_hash'): del mps[client_id]
	dat = base64.b64encode(dat)
	self.respond({'response': resp, 'data': dat})

class MessageProcessor(object):
    def __init__(self, id):
	self.id = id
	self.tlsns = shared.TLSNClientSession()
	self.state = 0
	
    def process_messages(self, msg):
	if msg.startswith('rcr_rsr_rsname_n:') and self.state == 0:                
	    msg_data = base64.b64decode(msg[len('rcr_rsr_rsname_n:'):])
	    rss = shared.TLSNClientSession()
	    rss.client_random = msg_data[:32]
	    rss.server_random = msg_data[32:64]
	    rs_choice_first5 = msg_data[64:69]
	    print ('Got rschoice: ', rs_choice_first5)
	    self.rs_choice = [k for k in  shared.reliable_sites.keys() if k.startswith(rs_choice_first5)][0]
	    if not self.rs_choice:
		raise Exception('Unknown reliable site', rs_choice_first5)
	    n = msg_data[69:]
	    rss.server_modulus, rss.server_exponent = (int(shared.reliable_sites[self.rs_choice][1],16),65537)
	    #TODO currently can only handle 2048 bit keys for 'reliable site'
	    rss.server_mod_length = shared.bi2ba(256)
	    rss.set_auditor_secret()
	    rss.set_enc_second_half_pms()           
	    rrsapms = shared.bi2ba(rss.enc_second_half_pms)
    
	    self.tlsns.auditor_secret, self.tlsns.auditor_padding_secret=rss.auditor_secret, rss.auditor_padding_secret
	    self.tlsns.server_mod_length, self.tlsns.server_modulus = shared.bi2ba(len(n)), shared.ba2int(n)
	    self.tlsns.set_enc_second_half_pms()            
	    return 'rrsapms_rhmac_rsapms:',rrsapms+rss.p_auditor+shared.bi2ba(self.tlsns.enc_second_half_pms)            
	      
	elif msg.startswith('cs_cr_sr_hmacms_verifymd5sha:') and self.state == 0:
	    self.state += 1
	    request = base64.b64decode(msg[len('cs_cr_sr_hmacms_verifymd5sha:'):])
	    assert len(request) == 125
	    self.tlsns.chosen_cipher_suite = int(request[:1].encode('hex'),16)
	    self.tlsns.client_random = request[1:33]
	    self.tlsns.server_random = request[33:65]
	    md5_hmac1_for_ms=request[65:89]
	    verify_md5 = request[89:105]
	    verify_sha = request[105:125]
	    self.tlsns.set_auditor_secret()
	    self.tlsns.set_master_secret_half(half=1,provided_p_value=md5_hmac1_for_ms)         
	    garbageized_hmac = self.tlsns.get_p_value_ms('auditor',[2])
	    hmac_verify_md5 = self.tlsns.get_verify_hmac(verify_sha, verify_md5, half=1) 
	    hmacms_hmacek_hmacverify = self.tlsns.p_auditor[24:]+garbageized_hmac+hmac_verify_md5
	    return 'hmacms_hmacek_hmacverify:',hmacms_hmacek_hmacverify
	
	elif msg.startswith('verify_md5sha2:') and self.state == 1:
	    self.state += 1
	    md5sha2 = base64.b64decode(msg[len('verify_md5sha2:'):])
	    return 'verify_hmac2:', self.tlsns.get_verify_hmac(md5sha2[16:],md5sha2[:16],half=1,is_for_client=False)
	
	elif msg.startswith('commit_hash:') and self.state == 2:
	    commit_hash = base64.b64decode(msg[len('commit_hash:'):])
	    response_hash = commit_hash[:32]
	    data_to_be_signed = hashlib.sha256(response_hash + self.tlsns.pms2 + shared.bi2ba(self.tlsns.server_modulus)).digest()
	    signature = sign_data(data_to_be_signed)
	    return 'pms2:', self.tlsns.pms2 + signature
	else:
	    return 'busy:','invalid request'
    
if __name__ == "__main__":
    proj_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    sys.path.append(proj_dir)    
    import shared
    shared.load_program_config()
    shared.import_reliable_sites(os.path.join(proj_dir,'shared'))
    try:
	server = HTTPServer(('',8080), myHandler)
	server.serve_forever()
    except KeyboardInterrupt:
	print ('caught keyboard interrupt')
	server.socket.close()

    