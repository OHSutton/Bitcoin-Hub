"""
Provides the functionality to generate private/public keys and bitcoin addresses
"""
import secrets
import ecdsa
import hashlib
from ..core import base58
from ..core.utilities import hash160


CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16) # The order of secp256k1


def encode(payload, type):
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
	payload_bytes = bytes.fromhex((prefix[type] + payload))
	encoded_payload = str(base58.b58encode_check(payload_bytes), 'utf-8')
	
	return encoded_payload

def get_private_key(compressed=False):
	"""
	Generates a cryptographically secure private key

	Parameters:
		compressed (Boolean): True if the key is to be compressed, false otherwise

	Returns:
		The private key in hexadecimal as a string
	"""
	valid_priv_key = False
	
	
	while not valid_priv_key:
		private_key_int = secrets.randbits(256)
		valid_priv_key = 1 < private_key_int and private_key_int < CURVE_ORDER - 1
	
	private_key = hex(private_key_int)[2:].zfill(64) # truncates the '0x' prefix, 64 is length in hex of the key

	if compressed:
		private_key += "01" # To signify it's compressed
	return private_key

def get_public_key(private_key, compressed=True):
	""" 
	Generate the public key from the private key.  Public key is compressed by default

	Paramters:
		private_key (String): The private key in hexadecimal
		compressed (Boolean): True if the key is to be compressed, false otherwise

	Returns:
		The public key in hexadecimal (String)
	"""
	private_key_bytes = bytes.fromhex(private_key[:64]) # if compressed priv key, remove the "01"
	public_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
	public_key_string = (public_key.to_string()).hex()

	# Compress and attach appropriate prefix
	if compressed:
		public_key_string = public_key_string[:len(public_key_string) // 2]
		
		if int(public_key_string, 16) % 2 == 0: 
			prefix = "02"
		else:
			prefix = "03"
	else:
		prefix = "04"
		
	return prefix + public_key_string

def get_address(public_key):
	"""
	Generates a bitcoin address for the given public key

	Parameters:
		public_key (String): The public key in hexadecimal

	Returns:
		The bitcoin address as a string
	"""
	public_key_bytes = bytes.fromhex(public_key)
	public_key_hash = hash160(public_key_bytes).hex()
	# Generate the address
	bitcoin_address = encode(public_key_hash, "address") 
	return bitcoin_address

def get_vanity_address(custom_text, position="start"):
	"""
	Generates a compressed bitcoin address that starts with/contains custom text.

	Parameters:
		custom_text (String): The text to be contained within the address
		position    (String): Determines whether the custom text must be at the 
								start of/anywhere in the bitcoin address
								Two options: "start" and "inside"

	Returns:
		(private_key, public_key, address): The private key, public key, and address
							if a suitable address has been found
	
	"""
	if (position not in ["start", "inside"]):
		raise ValueError("Given position is not valid.  Must be either 'start' or 'inside'")

	address_found = False
	
	while not address_found:
		private_key = get_private_key()
		public_key = get_public_key(private_key)
		address = get_address(public_key)

		if position == "start":
			# Check if the custom text immediately follows the '1'
			if address[1:len(custom_text)+1] == custom_text: 
				address_found = True
		else:
			# Check if the custom text is in the address
			if custom_text in address:
				address_found = True

	return (private_key, public_key, address)