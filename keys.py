import secrets
import ecdsa
import binascii
import hashlib, base58

"""All keys generated will be compressed by default"""
class KeyGen:
	def __init__(self):
		self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16) # The order of secp256k1
		self.KEY_SIZE = 32 # The size (in bytes) of the private key

		self.__candidate_key = [0] * self.KEY_SIZE # List of 32 bytes that will form the private key
		self.__key_pointer = 0
		self.__randomise_private_key()
	
	def __randomise_private_key(self):
		"""Initialise the candidate key list with random numbers"""
		for _ in range(self.KEY_SIZE):
			rand_byte = secrets.randbits(8)
			self.__randomise_byte(rand_byte)

	def __randomise_byte(self, num):
		"""Randomise an element in the candidate key list"""
		self.__candidate_key[self.__key_pointer] ^= num & 255
		self.__key_pointer += 1
		if self.__key_pointer == self.KEY_SIZE:
			self.__key_pointer = 0

	def __validate_private_key(self, private_key):
		"""Checks if the key is between 1 and self.CURVE_ORDER - 1"""
		private_key_int = int(private_key, 16)
		return 1 < private_key_int and private_key_int < self.CURVE_ORDER - 1

	def __seed_private_key(self, text):
		"""
		Introduces entropy into the key-generation with human input

		Parameters:
			text (String): A string of random characters entered by the user.
						   To ensure security, the string should be at least 32 characters long
		"""
		for char in text:
			self.__randomise_byte(ord(char))

	def __generate_valid_private_key(self):
		"""
		Generates valid private keys until one that satisfies the size criteria is found

		Returns:
			A valid private key
		"""
		valid_priv_key = False

		while not valid_priv_key:
			private_key = ""
			self.__randomise_private_key()
			for byte in self.__candidate_key:
				private_key += hex(byte)[2:] # slice to cut out the 0x

			valid_priv_key = self.__validate_private_key(private_key)		

		return private_key.zfill(self.KEY_SIZE * 2)

	def encode(self, payload, type):
		"""
		Encodes the given payload in base58Check and attaches the appropriate prefix

		Parameters:
			payload (String): the text to encode
			type (String): the type of the data being encoded - determines the prefix

		Returns:
			The payload & attached prefix, encoded in base58Check
		"""
		prefix = {
			"address": "00",
			"wif"	 : "80",
		}
		payload_bytes = binascii.unhexlify(prefix[type] + payload)
		encoded_payload = base58.b58encode_check(payload_bytes).decode() # encodes the bytes then decodes to string
		return encoded_payload

	def __compress_key(self, public_key):
		"""
		Return the compressed public key

		Parameters:
			public_key (String): The public key (in hex) to be compressed

		Returns:
			The compressed public key
		"""
		key = public_key[2:] # Exclude the prefix
		x_coord = key[:len(key) // 2]
		# Check if y value is odd/even and assign appropriate prefix
		if int(key, 16) % 2 == 0: 
			prefix = "02"
		else:
			prefix = "03"

		return prefix + x_coord

	def private_key(self, randomised_text="", compressed=True):
		"""
		Generates a cryptographically secure private key

		Parameters:
			randomised_text (String): Input from the user to further randomise the key
			compressed (Boolean): True if the key is to be compressed, false otherwise

		Returns:
			The private key in hexadecimal (String)
		"""
		self.__seed_private_key(randomised_text)
		private_key = self.__generate_valid_private_key()
		
		if compressed:
			private_key += "01" # To signify it's compressed
		return private_key

	def public_key(self, private_key, compressed=True):
		""" 
		Generate the public key from the private key.  Public key is compressed by default

		Paramters:
			private_key (String): The private key in hexadecimal
			compressed (Boolean): True if the key is to be compressed, false otherwise

		Returns:
			The public key in hexadecimal (String)
		"""
		private_key_bytes = binascii.unhexlify(private_key[:64]) # if compressed, remove the "01"
		public_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
		public_key_string = "04" + binascii.hexlify(public_key.to_string()).decode()

		if compressed:
			public_key_string = self.__compress_key(public_key_string)
		return public_key_string

	def address(self, public_key):
		"""
		Generates a bitcoin address for the given public key

		Parameters:
			public_key (String): The public key in hexadecimal

		Returns:
			The bitcoin address as a string
		"""
		public_key_bytes = binascii.unhexlify(public_key)
		# Hash the pub key with sha256
		sha256_hash = hashlib.sha256(public_key_bytes).digest()
		# Hash the sha256 hash with ripemd160
		ripemd160 = hashlib.new("ripemd160")
		ripemd160.update(sha256_hash)
		public_key_hash = ripemd160.hexdigest() # Final hash with bitcoin prefix
		# Generate the address
		bitcoin_address = self.encode(public_key_hash, "address") 
		return bitcoin_address


def vanity_address(custom_text, position="start"):
	"""
	Generates a compressed bitcoin address that starts with/contains custom text.

	Parameters:
		custom_text (String): The text to be contained within the address
		position (String): Determines whether the custom text must be at the 
						   start of/anywhere in the bitcoin address
						   Two options: "start" and "inside"

	Returns:
		(private_key, public_key, address): The private key, public key, and address
							if a suitable address has been found
	"""
	if (position not in ["start", "inside"]):
		raise ValueError("Given position is not valid.  Must be either 'start' or 'inside'")

	address_found = False
	gen = KeyGen()

	while not address_found:
		private_key = gen.private_key()
		public_key = gen.public_key(private_key)
		address = gen.address(public_key)

		if position == "start":
			# Check if the custom text immediately follows the '1'
			if address[1:len(custom_text)+1] == custom_text: 
				address_found = True
		else:
			# Check if the custom text is in the address
			if custom_text in address:
				address_foud = True

	return (private_key, public_key, address)


### Testing
string_seed = ""
gen = KeyGen()
priv_key = gen.private_key()
priv_key_uncomp = gen.private_key(compressed=False)
pub_key = gen.public_key(priv_key)
pub_key_uncomp = gen.public_key(priv_key_uncomp, compressed=False)
address = gen.address(pub_key)
address_uncomp = gen.address(pub_key_uncomp)
print("Private Key:", priv_key)
print("Public Key:       ", pub_key)
print("uncomp Public Key:", pub_key_uncomp)
print("BTC Address:      ", len(address))
print("uncomp BTC Address", len(address_uncomp))
print("Private (wif-compressed):", gen.encode(priv_key, type="wif"))
print("Private (wif):", gen.encode(priv_key_uncomp, type="wif"))