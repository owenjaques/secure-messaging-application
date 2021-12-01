#!/usr/bin/env python3

# important links
# Cryptography docs on asymmetric keys being used: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
# Signal protocol for x3df: https://signal.org/docs/specifications/x3dh/

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CONST_ONE_TIME_KEYS_NUM = 100

class Client:
	def __init__(self):
		self.username = input('Username: ')
		# TODO: time permitting add username duplicate verification with server

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
		data['identity'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
		data['pk_sig'] = self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
		data['signed_pk'] = self.spk_sig
		data['prekeys'] = []
		for key in self.ot_pks:
			data['prekeys'].append(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
		
		return requests.post('http://127.0.0.1:5000/signup', data=data)

client = Client()
