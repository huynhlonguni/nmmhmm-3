from util import *
import sys

if __name__ == "__main__":
	key = sys.argv[1]
	process = sys.argv[2]
	result = sys.argv[3]
	with open(key, "r") as f:
		key_text = f.read()
	with open(process, "rb") as f:
		other_data = f.read()

	if "PRIVATE" in key_text:
		private_key_text = key_text
		cipher_data = other_data
		plain_data = ManualWork.rsa_decrypt(private_key_text, cipher_data)
		with open(result, "wb") as f:
			f.write(plain_data)
	else:
		public_key_text = key_text
		plain_data = other_data
		cipher_data = ManualWork.rsa_encrypt(public_key_text, plain_data)
		with open(result, "wb") as f:
			f.write(cipher_data)
