from util import *
import sys

if __name__ == "__main__":
	key = sys.argv[1]
	message = sys.argv[2]
	sign = sys.argv[3]
	with open(key, "r") as f:
		key_text = f.read()
	with open(message, "rb") as f:
		message_data = f.read()

	if "PRIVATE" in key_text:
		private_key_text = key_text
		sign_data = ManualWork.rsa_sign(private_key_text, message_data)
		with open(sign, "wb") as f:
			f.write(sign_data)
	else:
		public_key_text = key_text
		with open(sign, "rb") as f:
			sign_data = f.read()

		if ManualWork.rsa_verify(public_key_text, message_data, sign_data):
			print("The message signature is valid")
		else:
			print("The message signature is NOT valid")
