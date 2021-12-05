#!/usr/bin/env python3

# important links
# Cryptography docs on asymmetric keys being used: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
# Signal protocol for x3df: https://signal.org/docs/specifications/x3dh/

"""
Note that while this class does authenticate that the client is sending/receiving messages from the real owners of identity keys fetched
from the server it is impossible to guarantee that the owners of the identify keys fetched from the server are infact the people that 
the client wishes to send/receive messages to/from. To do this users of the app would have to trade their public keys through another 
secure channel then store these public keys securely so they could compare them to the identity keys fetched from the server before 
sending/receiving messages. Implementing this is out of scope for this prototype as it is not considered in the X3DH implementation 
(https://signal.org/docs/specifications/x3dh/) and will not be considered further.
"""

import json
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
		self.id_key = X25519PrivateKey.generate()
		self.sign_id_key = Ed25519PrivateKey.generate()
		self.pk_sig = X25519PrivateKey.generate()

		# sign the prekey signature with the signing identify key so that other users can use this to guarantee that they are really talking to me
		self.spk_sig = self.sign_id_key.sign(self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
		
		self.ot_pks = []
		for _ in range(CONST_ONE_TIME_KEYS_NUM):
			self.ot_pks.append(X25519PrivateKey.generate())

	def publish_keys(self):
		data = {}
		data['username'] = self.username
		data['password'] = self.password
		data['identity'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		data['signing_id'] = self.sign_id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
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
		id_key = X25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['identity']))
		sign_id_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['signing_id']))
		prekey = X25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['prekey']))
		pk_sig_bytes = bytes.fromhex(key_bundle['pk_sig'])
		pk_sig = X25519PublicKey.from_public_bytes(pk_sig_bytes)
		signed_pk = bytes.fromhex(key_bundle['signed_pk'])

		# authenticate the receptient of the message (guarantees that the message will be sent to the write person)
		# (verify() raises Exception if verification fails)
		sign_id_key.verify(signed_pk, pk_sig_bytes)

		# generate an ephemeral key pair
		eph_key = X25519PrivateKey.generate()
		
		# generate the four diffie helman keys - first two provide mutual authentication whereas the next two provide forward secrecy
		dh1 = self.id_key.exchange(pk_sig)
		dh2 = eph_key.exchange(id_key)
		dh3 = eph_key.exchange(pk_sig)
		dh4 = eph_key.exchange(prekey)

		# generate shared key
		hkdf_input = b'\xff'*32 + dh1 + dh2 + dh3 + dh4
		shared_key = HKDF(hashes.SHA256(), 32, b'\0'*32, b'shared key').derive(hkdf_input)

		# Finally encrypt the text with the computed shared key
		cipher = Cipher(algorithms.AES(shared_key), modes.CBC(b'\0'*16))
		encryptor = cipher.encryptor()

		encode_text = text.encode('utf-8')
		while len(encode_text) % 16 != 0:
			encode_text += b'\0'
		cipher_text = encryptor.update(encode_text) + encryptor.finalize()

		# send the encrypted text as well as the eph key to the server
		data = {}
		data['from'] = self.username
		data['identity_key'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		data['ephemeral_key'] = eph_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		data['to'] = to
		data['prekey_index'] = key_bundle['prekey_idx']
		data['message'] = cipher_text
		data['is_image'] = False

		return requests.post(CONST_SERVER_URL + '/send', data=data)


if __name__ == '__main__':
	client = Client()
	client.send_text_message('alice', 'text test')
	pass
