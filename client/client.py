#!/usr/bin/env python3

# important links
# Cryptography docs on asymmetric keys being used: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
# Signal protocol for x3df: https://signal.org/docs/specifications/x3dh/

import json
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CONST_SERVER_URL = 'http://127.0.0.1:5000'
CONST_ONE_TIME_KEYS_NUM = 100

class Client:
	def __init__(self):
		self.username = input('Username: ')
		self.password = input('Password: ')

		print('Generating keys ...')
		self.generate_keys()
			
		print('Sending key bundle to server')
		r = self.publish_keys()
		if r.status_code != 200:
			raise Exception(r.text)

	def generate_keys(self):
		self.id_key = Ed25519PrivateKey.generate()
		self.pk_sig = Ed25519PrivateKey.generate()

		# sign the prekey signature with the identify key so that other users can use this to guarantee that they are really talking to me
		self.spk_sig = self.id_key.sign(self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
		
		self.ot_pks = []
		for _ in range(CONST_ONE_TIME_KEYS_NUM):
			self.ot_pks.append(Ed25519PrivateKey.generate())

	def publish_keys(self):
		data = {}
		data['username'] = self.username
		data['password'] = self.password
		data['identity'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		data['pk_sig'] = self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		data['signed_pk'] = self.spk_sig.hex()
		data['prekeys'] = []
		for i, key in enumerate(self.ot_pks):
			data['prekeys'].append((i, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()))
		
		return requests.post(CONST_SERVER_URL + '/signup', data=data)

	def send_text_message(self, to, text):
		r = requests.get(CONST_SERVER_URL + '/keybundle/' + to)
		if r.status_code != 200:
			raise Exception(r.text)
		
		key_bundle = json.loads(r.text)
		id_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['identity']))
		prekey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['prekey']))
		pk_sig = bytes.fromhex(key_bundle['pk_sig'])
		signed_pk = bytes.fromhex(key_bundle['signed_pk'])

		# authenticate the receptient of the message (guarantees that the message will be sent to the write person)
		# (verify() raises Exception if verification fails)
		id_key.verify(signed_pk, pk_sig)



if __name__ == '__main__':
	client = Client()
	client.send_text_message('alice', 'text test')
