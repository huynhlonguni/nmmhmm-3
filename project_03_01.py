from util import *
import sys

if __name__ == "__main__":
	key = sys.argv[1]
	with open(key, "r") as f:
		key_text = f.read()

	if "PRIVATE" in key_text:
		n, e, d, p, q, dmp1, dmq1, inv = ManualWork.parse_rsa_private_key(key_text)
		print(f"Read private key file: {key}")
		print(f"Modulus: {n}")
		print(f"Public exponent: {e}")
		print(f"Private exponent: {d}")
		print(f"Prime #1: {p}")
		print(f"Prime #1: {q}")
		print(f"d mod (p - 1): {dmp1}")
		print(f"d mod (q - 1): {dmq1}")
		print(f"q^-1 mod p: {inv}")
	else:
		n, e = ManualWork.parse_rsa_public_key(key_text)
		print(f"Read public key file: {key}")
		print(f"Modulus: {n}")
		print(f"Public exponent: {e}")
