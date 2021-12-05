#!/usr/bin/env python3

# important links
# Cryptography docs on asymmetric keys being used: https://cryptography.io/en/latest/hazmat/primitives/
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
from ujson import dumps, loads
import requests
from os import path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
sys.path.append("../shared/")
from Message import Message
from cryptography.hazmat.primitives import hashes
from fe25519 import fe25519
from ge25519 import ge25519, ge25519_p3

CONST_SERVER_URL = 'http://127.0.0.1:5000'
CONST_ONE_TIME_KEYS_NUM = 100

class Client:
	def __init__(self):
		self.username = input('Username: ')
		self.password = input('Password: ') 

		if not os.path.exists(f"messages_{self.username}.json"):
			with open(f"messages_{self.username}.json", "w") as f:
				f.write("{}")

		print('Generating keys ...')
		self.generate_keys()
			
		print('Sending key bundle to server')
		r = self.publish_keys()
		if r.status_code != 200:
			raise Exception(r.text)

	def generate_keys(self):
		self.sign_id_key = Ed25519PrivateKey.generate()
		self.pk_sig = X25519PrivateKey.generate()

		# the identity key used for encryption utilizes the same key pair as the identity key used for signing as per the X3DH standard
		self.encrypt_id_key = X25519PrivateKey.from_private_bytes(private_ed25519_to_x25519(self.sign_id_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())))

		# sign the prekey signature with the identify key so that other users can use this to guarantee that they are really talking to me
		self.spk_sig = self.sign_id_key.sign(self.pk_sig.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
		
		self.ot_pks = []
		for _ in range(CONST_ONE_TIME_KEYS_NUM):
			self.ot_pks.append(X25519PrivateKey.generate())

	def publish_keys(self):
		data = {}
		data['username'] = self.username
		data['password'] = self.password
		data['identity'] = self.sign_id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
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
		sign_id_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_bundle['identity']))
		encrypt_id_key = X25519PublicKey.from_public_bytes(public_ed25519_to_x25519(bytes.fromhex(key_bundle['identity'])))
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
		dh1 = self.encrypt_id_key.exchange(pk_sig)
		dh2 = eph_key.exchange(encrypt_id_key)
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
		# data = {}
		# data['from'] = self.username
		# data['identity_key'] = self.id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		# data['ephemeral_key'] = eph_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
		# data['to'] = to
		# data['prekey_index'] = key_bundle['prekey_idx']
		# data['message'] = cipher_text
		# data['is_image'] = False

		msg = Message(
			recepient=to,
			sender=self.username,
			sender_identity_key=self.encrypt_id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
			ephemeral_key=eph_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
			ciphertext=cipher_text,
			pk_idx=key_bundle['prekey_idx'],
			is_image=False
		)

		return requests.post(CONST_SERVER_URL + '/send', data=msg.to_dict())

	def save_message(self, msg):
		# Decrypt/create message store
		file_name = f"messages_{self.username}.json"
		with open(file_name, 'w+') as f:
			enc_data = f.read()

			pw_padding = (16 - len(self.password)) * "a"
			pw = self.password + pw_padding
			cipher = Cipher(algorithms.AES(pw), modes.CBC(b'\0'*16))
			decryptor = cipher.decryptor()
			dec = decryptor.update(enc_data) + decryptor.finalize()
			try:
				messages = json.loads(dec)
			except:
				print("Error decrypting messages file!")

			messages.append(msg.to_dict())

			# Re-encrypt message store after appending message
			encryptor = cipher.encryptor()
			enc = encryptor.update(json.dumps(messages)) + encryptor.finalize()

			f.seek(0)
			f.write(enc)



	def check_inbox(self):
		data = {'username': self.username, 'password': self.password, 'to_get': 'new'}
		r = requests.post(CONST_SERVER_URL + '/inbox', data=data)
		if r.status_code != 200:
			raise Exception(r.text)
		
		bundle = json.loads(r.text)
		for message in bundle:
			self.decrypt_message(message)
			#TODO build Message object, pass to save_message

	def decrypt_message(self, message):
		cipher_text = bytes.fromhex(message['ciphertext'])
		eph_key = X25519PublicKey.from_public_bytes(bytes.fromhex(message['ephemeral_key']))
		sender_id_key = X25519PublicKey.from_public_bytes(bytes.fromhex(message['sender_identity_key']))
		pk_idx = int(message['pk_idx'])
		prekey_used = self.ot_pks[pk_idx]

		# generate the shared key used to encrypt the cipher text
		dh1 = self.pk_sig.exchange(sender_id_key)
		dh2 = self.encrypt_id_key.exchange(eph_key)
		dh3 = self.pk_sig.exchange(eph_key)
		dh4 = prekey_used.exchange(eph_key)

		hkdf_input = b'\xff'*32 + dh1 + dh2 + dh3 + dh4
		shared_key = HKDF(hashes.SHA256(), 32, b'\0'*32, b'shared key').derive(hkdf_input)

		# delete one time pre key for forward secrecy
		self.ot_pks[pk_idx] = None

		# Finally decrypt the text with the computed shared key
		cipher = Cipher(algorithms.AES(shared_key), modes.CBC(b'\0'*16))
		decryptor = cipher.decryptor()
		byte_text = decryptor.update(cipher_text) + decryptor.finalize()
		
		# unpad and decode text
		text = byte_text.split(b'\0')[0].decode('utf-8')

		print('New message from ' + message['sender'] + ': ' + text)

"""
unfortunately conversion between ed25519 keys and x25519 keys is not directly supported in the cryptography library yet so these next two 
functions were generously provided by @reaperhulk and @chrysn in an issue thread (https://github.com/pyca/cryptography/issues/5557) 
within the cryptography github page
"""
def private_ed25519_to_x25519(data):
	hasher = hashes.Hash(hashes.SHA512())
	hasher.update(data)
	h = bytearray(hasher.finalize())
	# curve25519 clamping
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return bytes(h[0:32])

def public_ed25519_to_x25519(data):
	if ge25519.has_small_order(data) != 0:
		raise RuntimeError("Doesn' thave small order")

	# frombytes in libsodium appears to be the same as
	# frombytes_negate_vartime; as ge25519 only implements the from_bytes
	# version, we have to do the root check manually.
	A = ge25519_p3.from_bytes(data)
	if A.root_check:
		raise RuntimeError("Root check failed")

	if not A.is_on_main_subgroup():
		raise RuntimeError("It's on the main subgroup")

	one_minus_y = fe25519.one() - A.Y
	x = A.Y + fe25519.one()
	x = x * one_minus_y.invert()
	return bytes(x.to_bytes())
"""
end of borrowed functions from https://github.com/pyca/cryptography/issues/5557
"""

if __name__ == '__main__':
	alice = Client()
	bob = Client()
	bob.send_text_message('alice', 'this is a test')
	alice.check_inbox()
	pass
