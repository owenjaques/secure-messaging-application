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
import requests
import os
from os import path
from pathlib import Path
import io
from copy import copy
from PIL import Image
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
	def __init__(self, username = None, password=None):
		self.username = username or input('Username: ')
		self.password = password or input('Password: ') 

		print('Generating keys ...')
		self.generate_keys()
			
		print('Sending key bundle to server')
		r = self.publish_keys()
		if r.status_code != 200:
			raise Exception(r.text)

	def conversation_history(self, other_user):
		messages = self.read_convo(other_user)
		if len(messages) == 0:
			print(f"No conversation history for {other_user}")
		else:
			for msg in messages:
				img_idx = 0
				send_dir = 'Sent:' if msg.sender == self.username else 'Received:'
				if msg.is_image in ['True', True]:
					print(f"{send_dir} Image {str(img_idx)}")
					image = Image.open(io.BytesIO(bytes.fromhex(msg.plaintext)))
					image.show()
					img_idx += 1
				else:
					pt = bytes.fromhex(msg.plaintext) if type(msg.plaintext) == bytes else msg.plaintext
					if pt[0].isnumeric() or pt[-1].isnumeric():
						pt = bytes.fromhex(pt).decode('utf-8')
					print(f"{send_dir} {pt}")

	def generate_keys(self):
		"""
		Generates all relevant keys to be used for the lifetime of the client.
		"""
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
		"""
		Publishes all keys needed by the X3DF protocol to the server.
		"""
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
		"""
		Sends a text message to another user.
		"""
		return self.send_message(to, text.encode('utf-8'), False)

	def send_image_message(self, to, filename):
		"""
		Sends an image loaded from disk to another user.
		"""
		with open(filename, 'rb') as f:
			b = f.read()
		return self.send_message(to, b, True)

	def send_message(self, to, byte_str, is_image):
		"""
		Encrypts a message to be sent to another user using X3DF then sends it to the server.
		"""
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

		# pad string to 16 bytes
		byte_str_padded = copy(byte_str)
		padding_needed = 16 - (len(byte_str) % 16)
		for _ in range(padding_needed):
			byte_str_padded += bytes([padding_needed])
		
		# Finally encrypt the text with the computed shared key
		cipher = Cipher(algorithms.AES(shared_key), modes.CBC(b'\0'*16))
		encryptor = cipher.encryptor()
		cipher_text = encryptor.update(byte_str_padded) + encryptor.finalize()

		msg = Message(
			recepient=to,
			sender=self.username,
			sender_identity_key=self.encrypt_id_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
			ephemeral_key=eph_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
			ciphertext=cipher_text.hex(),
			pk_idx=key_bundle['prekey_idx'],
			is_image=is_image,
			plaintext=byte_str.hex()
		)

		self.save_message(msg)
		return requests.post(CONST_SERVER_URL + '/send', data=msg.to_dict())

	def save_message(self, msg):
		# Decrypt/create message store
		file_name = f"messages_{self.username}.json"

		if not path.exists(file_name):
			Path(file_name).touch()

		with open(file_name, 'rb+') as f:
			enc_data = f.read()
			pw_padding = (16 - len(self.password)) * "a"
			pw = self.password + pw_padding
			cipher = Cipher(algorithms.AES(bytearray(pw, 'utf-8')), modes.CBC(b'\0'*16))

			if len(enc_data) > 0:
				decryptor = cipher.decryptor()
				dec = decryptor.update(enc_data) + decryptor.finalize()
				dec = dec[:-dec[-1]]
			else:
				# File is empty
				dec = '{"messages": []}'

			try:
				messages = json.loads(dec)
			except:
				print("Error decrypting messages file!")

			messages["messages"].append(msg.to_dict())

			# Re-encrypt message store after appending message
			byte_str = json.dumps(messages).encode('utf-8')
			encryptor = cipher.encryptor()
			# pad string to 16 bytes
			padding_needed = 16 - (len(byte_str) % 16)
			for _ in range(padding_needed):
				byte_str += bytes([padding_needed])
			enc = encryptor.update(byte_str) + encryptor.finalize()

			f.seek(0)
			f.write(enc)

		return

	def delete_convo(self, other_user):
		"""
		Returns a list of Message objects between self.username and other_user
		"""
		try:
			with open(f"messages_{self.username}.json", "wb+") as f:
				enc_data = f.read()
				pw_padding = (16 - len(self.password)) * "a"
				pw = self.password + pw_padding
				cipher = Cipher(algorithms.AES(bytearray(pw, 'utf-8')), modes.CBC(b'\0'*16))

				if len(enc_data) > 0:
					decryptor = cipher.decryptor()
					dec = decryptor.update(enc_data) + decryptor.finalize()
					# unpad text
					dec = dec[:-dec[-1]]
				else:
					# File is empty
					return

				messages = []
				for message in json.loads(dec.decode('utf-8'))['messages']:
					msg = Message.from_dict(message)
					if other_user not in [msg.recepient, msg.sender]:
						messages.append(msg)


				# Re-encrypt message store after appending message
				byte_str = json.dumps(messages).encode('utf-8')
				encryptor = cipher.encryptor()
				# pad string to 16 bytes
				padding_needed = 16 - (len(byte_str) % 16)
				for _ in range(padding_needed):
					byte_str += bytes([padding_needed])
				enc = encryptor.update(byte_str) + encryptor.finalize()

				f.seek(0)
				f.write(enc)


		except FileNotFoundError:
			print(f"No conversation history for {self.username} and {other_user}")

	def read_convo(self, other_user):
		"""
		Returns a list of Message objects between self.username and other_user
		"""
		try:
			with open(f"messages_{self.username}.json", "rb") as f:
				enc_data = f.read()
			pw_padding = (16 - len(self.password)) * "a"
			pw = self.password + pw_padding
			cipher = Cipher(algorithms.AES(bytearray(pw, 'utf-8')), modes.CBC(b'\0'*16))

			if len(enc_data) > 0:
				decryptor = cipher.decryptor()
				dec = decryptor.update(enc_data) + decryptor.finalize()
				# unpad text
				dec = dec[:-dec[-1]]
			else:
				# File is empty
				dec = '{"messages": []}'
				raise Exception('user conversation not found')

			messages = []
			for message in json.loads(dec.decode('utf-8'))['messages']:
				msg = Message.from_dict(message)
				if other_user == None or other_user in [msg.recepient, msg.sender]:
					messages.append(msg)
			return messages

		except FileNotFoundError:
			print(f"No conversation history for {self.username} and {other_user}")
		# except Exception as e:
		# 	print(f"Error decrypting message history!?!: {e}")

	def check_inbox(self):
		"""
		Checks the client's inbox on the server for any messages.
		"""
		data = {'username': self.username, 'password': self.password, 'to_get': 'new'}
		r = requests.post(CONST_SERVER_URL + '/inbox', data=data)
		if r.status_code != 200:
			raise Exception(r.text)
		
		bundle = json.loads(r.text)
		for message in bundle:
			plaintext = self.decrypt_message(message)
			message['plaintext'] = plaintext.hex() if type(plaintext) == bytes else plaintext
			msg = Message.from_dict(message)
			self.save_message(msg)
			if not message['is_image'] or message['is_image'] == 'False':
				print('New message from ' + message['sender'] + ': ' + plaintext)
			else:
				print(f'New picture message from {message["sender"]}')

	def decrypt_message(self, message):
		"""
		Decrypts the ciphertext in a given message object and returns the resulting plaintext. If the message is
		an image it will leave the plaintext as a byte sequence but if it is a normal text it will put it in utf-8.
		"""
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
		
		# unpad text
		padding_used = byte_text[-1]
		byte_text = byte_text[:-padding_used]
		
		if not message['is_image'] or message['is_image'] == 'False':
			return byte_text.decode('utf-8')
		else:
			return byte_text

	def delete_self(self):
		"""
		Sends a request to the server to delete all of its data on the user as well as clears local message history.
		"""
		filename = 'messages_' + self.username + '.json'
		if os.path.exists(filename):
			os.remove(filename)

		return requests.post(CONST_SERVER_URL + '/delete_user', data={'username': self.username, 'password': self.password})

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
	### end-to-end-test ###

	# create two clients
	alice = Client()
	bob = Client('bob', 'test')

	# bob sends alice several messages (wow chill out Bob)
	bob.send_text_message('alice', 'hey')
	bob.send_text_message('alice', 'hey Alice')
	bob.send_text_message('alice', 'Alice answer me!')

	# alice checks her inbox and responds
	alice.check_inbox()
	alice.send_text_message('bob', 'leave me alone Bob')

	# bob callously sends a picture in reply
	bob.check_inbox()
	bob.send_image_message('alice', 'test_img.png')

	# alice checks her inbox and sees that there is an image
	alice.check_inbox()

	# she checks her conversation history to see what the image is
	# (check out the messages_alice.json file to see how they are kept encrypted at rest!)
	alice.conversation_history('bob')

	# alice deletes her conversation with bob then makes sure its gone
	alice.delete_convo('bob')
	try:
		alice.conversation_history('bob')
	except Exception as e:
		print(e)

	# unfortunately this does not prevent bob from sending her another message
	bob.send_text_message('alice', 'get beaned lol')

	# alice leaves the platform making it so that bob cannot message her anymore and presumably makes a new account
	alice.check_inbox()
	alice.delete_self()

	# bob tries to message her but is prevented
	try:
		bob.send_text_message('alice', 'hey alice what you up to tonight?')
	except Exception as e:
		print(e)

	### end of test ###
	pass
