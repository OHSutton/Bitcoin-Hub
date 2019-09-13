"""Will contain functionality for a bitcoin wallet"""
import secrets
from ..core.utilities import PBKDF2
from hashlib import sha256


class Wallet:    
    def get_mnemonic(self, passphrase=""):
        """
        Gemerates a BIP39 mnemonic and corresponding seed.  Used to import/export private keys
        
        Parameters:
            passphrase (String): An additional string to strengthen the seed's encryption
        
        Returns:
            (mnemonic, seed): The mnemonic and seed
        """
        rand_seq = hex(secrets.randbits(256))[2:] # Random 256-bit sequence in hexadecimal
        rand_seq_checksum = sha256(bytes.fromhex(rand_seq)).hexdigest()[:2]
        rand_seq += rand_seq_checksum
        
        # Convert rand_key to binary, remove the '0b' prefix, and fill to full length (264 bits)
        rand_key_binary = bin(int(rand_seq, 16))[2:].zfill(264)
        # Split binary into sections of 11 bits
        mnemonic_binary = [rand_key_binary[i:i+11] for i in range(0, 264, 11)]
        mnemonic = " ".join(self._assign_words(mnemonic_binary))
        return (mnemonic, PBKDF2(mnemonic, passphrase))
    
    def _assign_words(self, mnemonic_binary):
        """ 
        Maps the 11-bit values in the binary list to one of 2048 predefined words

        Parameters:
            mnemonic_binary (List(Strings)): list of 11-bit binary strings
        Returns:

            A list of the mnemonic words corresponding to the given binary values 
        """
        mnemonic_ints = [int(binary, 2) for binary in mnemonic_binary]
        max_mnemonic_int = max(mnemonic_ints)
        ints_to_mnemonic = {}

        with open("bitcoin/wordlist.txt") as wordlist:
            for line_index, word in enumerate(wordlist.readlines()):
                if line_index > max_mnemonic_int:
                    break

                if line_index in mnemonic_ints:
                    ints_to_mnemonic[line_index] = word.strip()

        mnemonic = list(map(ints_to_mnemonic.get, mnemonic_ints)) 
        return mnemonic