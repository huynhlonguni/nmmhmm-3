import asn1, os, subprocess
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

class OpenSSLWork:
	@staticmethod
	def get_paths():
		private_path = "test_priv.pem"
		public_path = "test_pub.pem"
		plain_path = "test_plain.txt"
		cipher_path = "test_cipher.bin"
		message_path = "test_message.bin"
		sign_path = "test_sign.bin"

		return private_path, public_path, plain_path, cipher_path, message_path, sign_path

	@staticmethod
	def gen_key(num_bits = 512):
		private_path, public_path, plain_path, cipher_path, message_path, sign_path = OpenSSLWork.get_paths()

		subprocess.call(["openssl", "genpkey", "-out", private_path, "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{num_bits}"], stderr=open(os.devnull, 'wb'))
		subprocess.call(["openssl", "pkey", "-in", private_path, "-out", public_path, "-pubout"])

		with open(private_path, "r") as f:
			private_key_text = f.read()
		with open(public_path, "r") as f:
			public_key_text = f.read()

		os.remove(private_path)
		os.remove(public_path)

		return private_key_text, public_key_text

	@staticmethod
	def rsa_encrypt(public_key_text, plain_data):
		private_path, public_path, plain_path, cipher_path, message_path, sign_path = OpenSSLWork.get_paths()

		with open(public_path, "w") as f:
			f.write(public_key_text)
		with open(plain_path, "wb") as f:
			f.write(plain_data)

		subprocess.call(["openssl", "pkeyutl", "-in", plain_path, "-out", cipher_path, "-inkey", public_path, "-pubin", "-encrypt"])

		with open(cipher_path, "rb") as f:
			cipher_data = f.read()

		os.remove(public_path)
		os.remove(plain_path)
		os.remove(cipher_path)

		return cipher_data

	@staticmethod
	def rsa_decrypt(private_key_text, cipher_data):
		private_path, public_path, plain_path, cipher_path, message_path, sign_path = OpenSSLWork.get_paths()

		with open(private_path, "w") as f:
			f.write(private_key_text)
		with open(cipher_path, "wb") as f:
			f.write(cipher_data)

		subprocess.call(["openssl", "pkeyutl", "-in", cipher_path, "-out", plain_path, "-inkey", private_path, "-decrypt"])

		with open(plain_path, "rb") as f:
			plain_data = f.read()

		os.remove(private_path)
		os.remove(cipher_path)
		os.remove(plain_path)

		return plain_data

	@staticmethod
	def rsa_sign(private_key_text, message_data):
		private_path, public_path, plain_path, cipher_path, message_path, sign_path = OpenSSLWork.get_paths()

		with open(private_path, "w") as f:
			f.write(private_key_text)
		with open(message_path, "wb") as f:
			f.write(message_data)

		subprocess.call(["openssl", "pkeyutl", "-in", message_path, "-out", sign_path, "-inkey", private_path, "-sign"])

		with open(sign_path, "rb") as f:
			sign_data = f.read()

		os.remove(private_path)
		os.remove(message_path)
		os.remove(sign_path)

		return sign_data

	@staticmethod
	def rsa_verify(public_key_text, message_data, sign_data):
		private_path, public_path, plain_path, cipher_path, message_path, sign_path = OpenSSLWork.get_paths()

		with open(public_path, "w") as f:
			f.write(public_key_text)
		with open(message_path, "wb") as f:
			f.write(message_data)
		with open(sign_path, "wb") as f:
			f.write(sign_data)

		ret = subprocess.call(["openssl", "pkeyutl", "-in", message_path, "-sigfile", sign_path, "-inkey", public_path, "-pubin", "-verify"], stdout=open(os.devnull, 'wb'))

		os.remove(public_path)
		os.remove(message_path)
		os.remove(sign_path)

		return ret == 0

class CryptoWork:
	@staticmethod
	def parse_rsa_private_key(private_key_text):
		private_key = serialization.load_pem_private_key(private_key_text.encode(), password=None)
		n = private_key.public_key().public_numbers().n
		e = private_key.public_key().public_numbers().e
		d = private_key.private_numbers().d
		p = private_key.private_numbers().p
		q = private_key.private_numbers().q
		dmp1 = private_key.private_numbers().dmp1
		dmq1 = private_key.private_numbers().dmq1
		inv = pow(q, -1, p)

		return n, e, d, p, q, dmp1, dmq1, inv

	@staticmethod
	def parse_rsa_public_key(public_key_text):
		public_key = serialization.load_pem_public_key(public_key_text.encode())
		n = public_key.public_numbers().n
		e = public_key.public_numbers().e

		return n, e

	@staticmethod
	def rsa_encrypt(public_key_text, plain_data):
		public_key = serialization.load_pem_public_key(public_key_text.encode())
		cipher = public_key.encrypt(plain_data, padding.PKCS1v15())
		return cipher

	@staticmethod
	def rsa_decrypt(private_key_text, cipher_data):
		private_key = serialization.load_pem_private_key(private_key_text.encode(), password=None)
		plain = private_key.decrypt(cipher_data, padding.PKCS1v15())
		return plain

	@staticmethod
	def rsa_sign(private_key_text, message_data):
		raise NotImplementedError

		private_key = serialization.load_pem_private_key(private_key_text.encode(), password=None)
		signature = private_key.sign(message_data, padding.PKCS1v15(), hashes.SHA256())
		return signature

	@staticmethod
	def rsa_verify(public_key_text, message_data, sign_data):
		raise NotImplementedError

		public_key = serialization.load_pem_public_key(public_key_text.encode())
		verified = public_key.verify(sign_data, message_data, padding.PKCS1v15(), hashes.SHA256())

class ManualWork:
	@staticmethod
	def parse_pem_file(text):
		lines = text.splitlines()
		lines = lines[1:-1] # Skip --Begin-- and --End-- lines
		encoded_data = ''.join(lines)
		return b64decode(encoded_data)

	@staticmethod
	def pkcs1_type_1_pad(message, block_size):
		pad_len = block_size - 3 - len(message)

		padded_message = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + message
		return padded_message

	@staticmethod
	def pkcs1_type_1_unpad(padded_message, block_size):
		padded_bytes = padded_message.to_bytes(block_size, byteorder='big')

		if padded_bytes[0:2] != b'\x00\x01':
			raise ValueError("Invalid PKCS#1 type 1 padding")

		separator_index = padded_bytes.find(b'\x00', 2)

		if separator_index == -1:
			raise ValueError("Invalid PKCS#1 type 1 padding")

		return padded_bytes[separator_index + 1:]

	@staticmethod
	def pkcs1_type_2_pad(message, block_size):
		pad_len = block_size - 3 - len(message)

		padding = os.urandom(pad_len)
		while b'\x00' in padding:
			padding = os.urandom(pad_len)

		padded_message = b'\x00\x02' + padding + b'\x00' + message
		return padded_message

	@staticmethod
	def pkcs1_type_2_unpad(padded_message, block_size):
		padded_bytes = padded_message.to_bytes(block_size, byteorder='big')

		if padded_bytes[0:2] != b'\x00\x02':
			raise ValueError("Invalid PKCS#1 type 2 padding")

		separator_index = padded_bytes.find(b'\x00', 2)

		if separator_index == -1:
			raise ValueError("Invalid PKCS#1 type 2 padding")

		return padded_bytes[separator_index + 1:]

	@staticmethod
	def calc_block_size(n):
		return (n.bit_length() + 7) // 8

	# n, e, d, p, q, dmp1, dmq1, inv
	@staticmethod
	def parse_rsa_private_key(private_key_text):
		data = ManualWork.parse_pem_file(private_key_text)

		decoder = asn1.Decoder()
		decoder.start(data)

		tag, value = decoder.read()

		# PKCS8 Sequence
		if tag.nr == asn1.Numbers.Sequence:
			decoder.start(value)

			# Version Integer
			tag, value = decoder.read()
			version = value

			# Algorithm sequence
			tag, value = decoder.read()
			if tag.nr == asn1.Numbers.Sequence:
				algo_decoder = asn1.Decoder()
				algo_decoder.start(value)

				# Algorithm ObjectIdentifier
				tag, value = algo_decoder.read()
				algorithm = value #1.2.840.113549.1.1.1 is RSA

				# NULL
				tag, value = algo_decoder.read()

			# Private key Octet String
			tag, value = decoder.read()
			if tag.nr == asn1.Numbers.OctetString:
				key_decoder = asn1.Decoder()
				key_decoder.start(value)

				tag, value = key_decoder.read()

				# Sequence
				if tag.nr == asn1.Numbers.Sequence:
					key_decoder.start(value)

					tag, value = key_decoder.read()
					version = value

					tag, value = key_decoder.read()
					n = value

					tag, value = key_decoder.read()
					e = value

					tag, value = key_decoder.read()
					d = value

					tag, value = key_decoder.read()
					p = value

					tag, value = key_decoder.read()
					q = value

					tag, value = key_decoder.read()
					dmp1 = value

					tag, value = key_decoder.read()
					dmq1 = value

					tag, value = key_decoder.read()
					inv = value

					return n, e, d, p, q, dmp1, dmq1, inv

	# n, e
	@staticmethod
	def parse_rsa_public_key(public_key_text):
		data = ManualWork.parse_pem_file(public_key_text)

		decoder = asn1.Decoder()
		decoder.start(data)

		tag, value = decoder.read()

		# PKCS8 Sequence
		if tag.nr == asn1.Numbers.Sequence:
			decoder.start(value)

			# Algorithm sequence
			tag, value = decoder.read()
			if tag.nr == asn1.Numbers.Sequence:
				algo_decoder = asn1.Decoder()
				algo_decoder.start(value)

				# Algorithm ObjectIdentifier
				tag, value = algo_decoder.read()
				algorithm = value #1.2.840.113549.1.1.1 is RSA

				# NULL
				tag, value = algo_decoder.read()

			# Public key Bit String
			tag, value = decoder.read()
			if tag.nr == asn1.Numbers.BitString:
				key_decoder = asn1.Decoder()
				key_decoder.start(value)

				tag, value = key_decoder.read()

				# Sequence
				if tag.nr == asn1.Numbers.Sequence:
					key_decoder.start(value)

					tag, value = key_decoder.read()
					n = value

					tag, value = key_decoder.read()
					e = value

					return n, e

	@staticmethod
	def rsa_encrypt(public_key_text, plain_data):
		n, e = ManualWork.parse_rsa_public_key(public_key_text)
		block_size = ManualWork.calc_block_size(n)

		padded_data = ManualWork.pkcs1_type_2_pad(plain_data, block_size)
		padded = int.from_bytes(padded_data, byteorder="big")

		cipher = pow(padded, e, n)

		return cipher.to_bytes(length=ManualWork.calc_block_size(cipher), byteorder="big")

	@staticmethod
	def rsa_decrypt(private_key_text, cipher_data):
		n, e, d, p, q, dmp1, dmq1, inv = ManualWork.parse_rsa_private_key(private_key_text)
		block_size = ManualWork.calc_block_size(n)

		cipher = int.from_bytes(cipher_data, byteorder="big")
		padded = pow(cipher, d, n)
		try:
			plain = ManualWork.pkcs1_type_2_unpad(padded, block_size)
		except ValueError:
			print("Decryption failed! Invalid padding")
			return 0

		return plain

	@staticmethod
	def rsa_sign(private_key_text, message_data):
		n, e, d, p, q, dmp1, dmq1, inv = ManualWork.parse_rsa_private_key(private_key_text)
		block_size = ManualWork.calc_block_size(n)

		padded_data = ManualWork.pkcs1_type_1_pad(message_data, block_size)
		padded = int.from_bytes(padded_data, byteorder="big")

		sign = pow(padded, d, n)

		return sign.to_bytes(block_size, byteorder="big")

	@staticmethod
	def rsa_verify(public_key_text, message_data, sign_data):
		n, e = ManualWork.parse_rsa_public_key(public_key_text)
		block_size = ManualWork.calc_block_size(n)

		sign = int.from_bytes(sign_data, byteorder="big")
		padded = pow(sign, e, n)
		try:
			plain = ManualWork.pkcs1_type_1_unpad(padded, block_size)
		except ValueError:
			return False

		return message_data == plain

if __name__ == "__main__":
	plain_data = b"The quick brown fox jumps over the lazy dog"
	
	# Init
	private_key_text, public_key_text = OpenSSLWork.gen_key()

	# Test key parsing
	assert CryptoWork.parse_rsa_private_key(private_key_text) == ManualWork.parse_rsa_private_key(private_key_text)
	assert CryptoWork.parse_rsa_public_key(public_key_text) == ManualWork.parse_rsa_public_key(public_key_text)

	# Encrypt
	openssl_enc = OpenSSLWork.rsa_encrypt(public_key_text, plain_data)
	crypto_enc = CryptoWork.rsa_encrypt(public_key_text, plain_data)
	manual_enc = ManualWork.rsa_encrypt(public_key_text, plain_data)

	# Test decrypt
	assert plain_data == OpenSSLWork.rsa_decrypt(private_key_text, openssl_enc)
	assert plain_data == OpenSSLWork.rsa_decrypt(private_key_text, crypto_enc)
	assert plain_data == OpenSSLWork.rsa_decrypt(private_key_text, manual_enc)

	assert plain_data == CryptoWork.rsa_decrypt(private_key_text, openssl_enc)
	assert plain_data == CryptoWork.rsa_decrypt(private_key_text, crypto_enc)
	assert plain_data == CryptoWork.rsa_decrypt(private_key_text, manual_enc)

	assert plain_data == ManualWork.rsa_decrypt(private_key_text, openssl_enc)
	assert plain_data == ManualWork.rsa_decrypt(private_key_text, crypto_enc)
	assert plain_data == ManualWork.rsa_decrypt(private_key_text, manual_enc)

	# Test sign
	openssl_sign = OpenSSLWork.rsa_sign(private_key_text, plain_data)
	# crypto_sign = CryptoWork.rsa_sign(private_key_text, plain_data) # Cant get Cryptography to work identically
	manual_sign = ManualWork.rsa_sign(private_key_text, plain_data)

	assert openssl_sign == manual_sign

	# Test verify
	assert OpenSSLWork.rsa_verify(public_key_text, plain_data, openssl_sign)
	assert OpenSSLWork.rsa_verify(public_key_text, plain_data, manual_sign)

	assert ManualWork.rsa_verify(public_key_text, plain_data, openssl_sign)
	assert ManualWork.rsa_verify(public_key_text, plain_data, manual_sign)


