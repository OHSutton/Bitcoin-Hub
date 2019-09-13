import hashlib

# Constant
CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16) # The order of secp256k1

def PBKDF2(self, mnemonic, salt=""):
        """
        Uses the PBKDF2 key-stretching function to stretch the mnemonic to a 512-bit value.  The use
        of salt is optional

        Parameters:
            mnemonic (String): the mnemonic code words to stretch
            salt     (String): An additional security factor to protect the resulting seed

        Returns:
            The 512-bit seed created from the 2048 rounds of hashing of the mnemoni and salt 
        
        """
        mnemonic_bytes = mnemonic.encode()
        salt_bytes = ("mnemonic" + salt).encode()
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt_bytes, 2048)
        return seed.hex()

def hash160(data_as_bytes):
    """
    Hashes the data with Hash160 (RIPEMD160 after SHA256):
    
    Parameters:
        data_as_bytes (bytes): the data to hash, as bytes
    
    Returns:
        The hash in bytes
    """
    #Hash the pub key with sha256
    sha256_hash = hashlib.sha256(data_as_bytes).digest()
	# Hash the sha256 hash with ripemd160
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    data_hash = ripemd160.digest() 
    return data_hash