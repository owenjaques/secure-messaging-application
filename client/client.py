#!/usr/bin/env python3

# important links
# Cryptography docs on asymmetric keys being used: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
# Signal protocol for x3df: https://signal.org/docs/specifications/x3dh/

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
		self.spk_sig = self.id_key.sign(self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
		
		self.ot_pks = []
		for _ in range(CONST_ONE_TIME_KEYS_NUM):
			self.ot_pks.append(Ed25519PrivateKey.generate())

	def publish_keys(self):
		data = {}
		data['username'] = self.username
		data['password'] = self.password
		data['identity'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
		data['pk_sig'] = self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
		data['signed_pk'] = self.spk_sig
		data['prekeys'] = []
		for i, key in enumerate(self.ot_pks):
			data['prekeys'].append((i, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
		
		return requests.post(CONST_SERVER_URL + '/signup', data=data)

	def send_text_message(self, to, text):
		r = requests.get(CONST_SERVER_URL + '/keybundle/' + to)
		if r.status_code != 200:
			raise Exception(r.text)
		
		# key_bundle = r.json()
		# id_key = Ed25519PublicKey.from_public_bytes(key_bundle['identity'])
		# pk_sig = Ed25519PublicKey.from_public_bytes(key_bundle['pk_sig'])


client = Client()
client.send_text_message('test', 'text test')
