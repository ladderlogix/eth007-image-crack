import zlib
from Crypto.Cipher import AES


def deobfuscate_data(datum, key):
	if not datum:
		# Empty data, nothing to deobfuscate
		return None

	try:
		# Decode the hex data
		datum = bytes.fromhex(datum)
	except ValueError as e:
		raise Exception(f"crypto: failed to deobfuscate datum hex: {str(e)}")

	# XOR with the key
	datum = bytes([b ^ key[i % len(key)] for i, b in enumerate(datum)])

	return datum


def toss_keys():
	# Return all possible keys
	return [
		b"q\xf4\xb9\x1bG3%\xb8q\xfb0\x11\xfdL\xcb\xc5\x02\xa5^\xa1kB\xb1w\xdd\xfc?:\xa9q\x84Tq\xf4\xb9\x1bG3%\xb8q\xfb0\x11\xfdL\xcb\xc5\x02\xa5^\xa1kB\xb1w\xdd\xfc?:\xa9q\x84T",
		b"q\xf4\xb9\x1bG3%\xb8q\xfb0\x11\xfdL\xcb\xc5\x02\xa5^\xa1kB\xb1w\xdd\xfc?:\xa9q\x84T",
		b"q\xf4\xb9\x1bG3%\xb8q\xfb0\x11\xfdL\xcb\xc5\x02\xa5^\xa1kB\xb1w\xdd\xfc?:\xa9q\x84T\xd4Q\x1c\xbe\xe2\x96\x80\x1d\xd4^\x95\xb4X\xe9n`\xa7\x00\xfb\x04\xce\xe7\x14\xd2xY\x9a\x9f\x0c\xd4!\xf1"
	]


def xor(key: str, data: str) -> str:
	"""Perform XOR operation between the key and data."""
	key_cycle = (key * ((len(data) // len(key)) + 1))[:len(data)]
	return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key_cycle))


def decrypt_aes_gcm(data, key):
	"""AES-GCM decryption."""
	nonce = data[:12]
	ciphertext = data[12:-16]
	tag = data[-16:]

	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	try:
		decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
		return decrypted_data
	except ValueError as e:
		raise ValueError(f"Decryption failed: {e}")


def full_decrypt(data, aes_key, xor_key):
	"""Full decryption pipeline: AES-GCM -> XOR -> zlib decompression."""
	# Step 1: AES-GCM decryption
	aes_decrypted = decrypt_aes_gcm(data, aes_key)
	# print(f"AES Decrypted: {aes_decrypted}")

	# Step 2: XOR operation
	xor_decrypted = xor(xor_key, aes_decrypted.decode('latin1'))
	# print(f"XOR Decrypted: {xor_decrypted}")

	# Step 3: zlib decompression
	try:
		decompressed_data = zlib.decompress(xor_decrypted.encode('latin1')).decode()
		# print(f"Decompressed Data: {decompressed_data}")
		return decompressed_data
	except zlib.error as e:
		raise ValueError(f"Zlib decompression failed: {e}")


def sliding_window_decrypt(data, key, xor_key):
	"""Sliding window decryption attack with full decryption pipeline."""
	for nonce_start in range(len(data) - 28):  # 12 bytes for nonce + 16 bytes for tag
		nonce = data[nonce_start:nonce_start + 12]
		for tag_start in range(nonce_start + 12, len(data) - 16):
			ciphertext = data[nonce_start + 12:tag_start]
			tag = data[tag_start:tag_start + 16]

			try:
				# Construct potential AES-GCM encrypted block
				candidate_block = nonce + ciphertext + tag

				# Attempt AES-GCM decryption
				decrypted_data = decrypt_aes_gcm(candidate_block, key)
				# print(f"Decryption succeeded with nonce at {nonce_start} and tag at {tag_start}")

				# Perform full decryption pipeline
				final_data = full_decrypt(candidate_block, key, xor_key)
				return final_data
			except ValueError:
				continue

	# print("Sliding window attack failed to decrypt the data.")
	return None


# AES Key (256-bit)
aes_key = b"\x01i'z\xd2\xac\x01\xd2\x8c\xceS)\xbb\xb8\xe3H\xf3U\x80\xfe\xbcq\x7fQ\xc7nB\xe7\x8a-\x86|"

# XOR Key
xor_key = "6572b3875e103bb2eaef4f1860a4b8d5deeb048a0fa4cf1a0c5306dae0082918521e10569bf68719e0efb19404746ff8d802dffad9bd59eaa12e03f5a2f66652011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd166500051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f0000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"

# Encrypted data (example)
data = b"j\xd1s\x11\xab\xe3\x9a\x9b\x0f\x81\x8a\xdey\xe2\xc9)$\xf6\xeb\xbd\x86\xab\xd3\x0c.\xdb\xa5\xf5?\x1b\xbb?\xe9\xd4]\x1eu\xba%\xbe(\xa3\x1e#\xbe\xb9\xc0\xc1\xb0?V3_@\xe7Z\xe3J\x15\xe1\x1f\xd5\x9e\xe6Gfj\xc5\xfb\x9a@\xbdT\x9d'\xc2\x076\xd8j\xce\n\xae\n\xfb\xba\x9b&i6Ea\x00\x00\x00\x00"

# Attempt deobfuscation with all keys

while True:

	todecrypt = input("Encrypted: ")

	deobfuscated_data = None
	for key in toss_keys():
		deobfuscated_data = deobfuscate_data(todecrypt,
		                                     key) + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		# print("Deobfuscated Data:", deobfuscated_data)

		if deobfuscated_data:
			# Perform sliding window attack and full decryption
			result = sliding_window_decrypt(deobfuscated_data, aes_key, xor_key)
			if result:
				print(result)
				break
			else:
				# print("Decryption failed.")
				pass
		else:
			# print("Deobfuscation failed for all keys.")
			pass
