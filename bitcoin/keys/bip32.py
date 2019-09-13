"""
In this implementation of BIP32, I chose to distinguish between Private and Public nodes
which instead inherit some core functionality from the BIP32Node.
This was to better segregate the different functions of each type of node, as well as 
provide a cleaner interface.

For example, a PrivateNode can produce both PrivateNode and PublicNode children however a 
PublicNode is neutered in the sense that it can only produce public node children. Additionally, 
PublicNodes only store a public key whereas the PrivateNodes only store a private key
but can generate public keys.

BIP32 is outlined in detail at:
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

Still need TODO:
    - Full Docs
    - Key generation given a path.  Ex return key at path m/2h/3/4
    - Further key formatting checks, ex correct size, check public key is valid public key
    - Codebase wide switch from using hexadecimal to bytes? Probs not for a while
    - Rigorous testing to ensure no bugs
"""

import hashlib
import hmac
from ..core import base58
from .keys import get_public_key
from ..core.utilities import hash160, CURVE_ORDER


def is_private(key):
    """
    Checks if the given serialised key corresponds to a private bip32 node.
    """
    return key[:4] in ("xprv", "tprv")


class InvalidKeyException(Exception):
    """
    Raised when a bip32 serialised key is incorrectly formatted, or the 
    X-coordinate in the public key does not lie on the Secp256k1 curve
    """
    pass


class _BIP32Key:
    """ 
    Do not use this class, it only implements several core functions required in a BIP32 Node.
    Instead use the PrivateNode and PublicNode classes below.
    """
    def __init__(self, depth=0, index=0, parent_fingerprint="00000000",   
            chain_code=None, key=None, is_private=False, path=None):
        if chain_code == None or key == None:
            raise ValueError("Chain code and Key should be hexadecimal")
        self._chain_code = chain_code
        self._key = None
        self._index = index # index of this node
        # The first 8 hex digits of the hash160 of the parent's public key.
        self._parent_fingerprint = parent_fingerprint 
        self._depth = depth
        self._is_private = is_private
        self._path = path

    def serialize_key(self, testnet=False):
        """
        Exports this node's private/public key in the format specified in bip32.  
        
        The serialization structure is below with the preceding number representing the 
        number of bytes, and + representing concatenation.

        | 4: Prefix | 1: Depth | 4: Parent_fingerprnt | 4: child_index |
            32: Chain_Code | 33: PublicKey or (0x00+PrivateKey) |

        Parameters:
            type_of_node (String): The type of this Node.  Must be either: 
                "public", "private", "test-private", "test-public"

            key (String): The public/private key (in hex) associated with this node.
        
        Returns:
            The serialised node encoded in base58Check.
        """   
        type_of_node = "test-" if testnet else ""
        type_of_node += "private" if self._is_private else "public"
        
        prefix = {
            "private"     : "0488ADE4",
            "public"      : "0488B21E",
            "test-private": "04358394",
            "test-public" : "043587CF",
        }

        node_as_hex = [
            prefix[type_of_node],
            hex(self._depth)[2:].zfill(2), 
            self._parent_fingerprint.zfill(8), 
            hex(self._index)[2:].zfill(8), 
            self._chain_code.zfill(64) 
        ]
        if self._is_private:
            node_as_hex.append("00" + self._key.zfill(64))
        else: 
            node_as_hex.append(self._key.zfill(66))

        node_as_hex = ''.join(node_as_hex)
        serialised_node = base58.b58encode_check(bytes.fromhex(node_as_hex))
        return serialised_node.decode()

    def index(self):
        return self._index
    
    def chain_code(self):
        return self._chain_code
    
    def parent_fingerprint(self):
        return self._parent_fingerprint

    def depth(self):
        return self._depth
    
    def is_private(self):
        return self._is_private
    
    def path(self):
        return self._path


class PrivateNode(_BIP32Key):
    """
    Implement a Hierarchial deterministic wallet as specified in BIP32.
    
    
    """
    def __init__(self, depth=0, index=0, parent_fingerprint="00000000",   
            chain_code=None, private_key=None, is_hardened=False, path='M'):
        super().__init__(depth, index, parent_fingerprint, chain_code, 
                private_key, is_private=True)

        self._is_hardened = is_hardened

    @classmethod
    def deserialize_key(cls, key):
        if key[:4] not in ("xprv", "tprv"):
            raise InvalidKeyException("Key not correctly formatted")
        
        key = base58.b58decode_check(key)[8:].hex() # Remove the prefix
        return cls(
            int(key[:2], 16), # depth
            int(key[2:10], 16), # fingerprint
            int(key[10, 18], 16), # index
            key[18:50], # chain code
            key[52:])

    @classmethod
    def from_seed(cls, seed):
        private_key = seed[:len(seed) // 2]
        chain_code = seed[len(seed) // 2:]
        return cls(chain_code=chain_code, private_key=private_key)

    def id(self):
        return hash160(bytes.fromhex(get_public_key(self._key))).hex()

    def public_copy(self):
        return PublicNode(self._depth, self._index, self._parent_fingerprint, 
                self._chain_code, get_public_key(self._key), False)

    def derive_private_child(self, index, is_hardened=False):
        """
        Full docs is a TODO        
        """
        if is_hardened:
            hash_msg = "00" + self._key + hex(self._index)[2:].zfill(8)
        else: 
            hash_msg = get_public_key(self._key) + hex(self._index)[2:].zfill(8)

        hash_msg = bytes.fromhex(hash_msg)
        hash_key = bytes.fromhex(self.chain_code)
        child_hash = hmac.HMAC(key=hash_key, msg=hash_msg, 
                digestmod=hashlib.sha512).digest().hex()
        
        I_L = child_hash[:64]
        chain_code = child_hash[64:]
        
        if int(I_L, 16) >= CURVE_ORDER:
            return self.derive_private_child(index + 1, is_hardened)

        priv_key = ((int(I_L, 16) + int(self._key, 16)) % CURVE_ORDER)[2:]
        if priv_key == 0:
            return self.derive_private_child(index + 1, is_hardened)

        depth = self._depth + 1
        fingerprint = self.id()[:8]
        if is_hardened:
            path = self._path + f'/{index}h'
        else:
            path = self._path + f'/{index}'

        return self.__class__(private_key=hex(priv_key)[2:], chain_code=chain_code, 
                index=index, is_hardened=True, depth=depth, path=path, 
                parent_fingerprint=fingerprint)
    
    def derive_public_child(self, index):
        if self._is_hardened:
            return self.derive_private_child(index).public_copy()
        else:
            return self.public_copy().derive_public_child(index)

    def is_hardened(self):
        return self._is_hardened


class PublicNode(_BIP32Key):
    
    def __init__(self, depth=0, index=0, parent_fingerprint="00000000",   
            chain_code=None, public_key=None, is_private=False, path=None):
        """
        Note that public_key uses SEC1's compressed form.
        Both public key, chain code are in hexadecimal.
        Fingerprint is the first 4 bytes of the hash160 of the public key.
        """
        super().__init__(depth, index, parent_fingerprint, chain_code, 
                public_key, False, path)

    @classmethod
    def deserialize_key(cls, key):
        if key[:4] not in ("xpub", "tpub"):
            raise InvalidKeyException("Key not correctly formatted")
        
        key = base58.b58decode_check(key).hex()[8:] # Remove the prefix
        return cls(
            int(key[:2], 16), # depth
            key[2:10], # fingerprint
            int(key[10, 18], 16), # index
            key[18:50], # chain code
            key[50:] # key
        )
    
    def id(self):
        return hash160(bytes.fromhex(self._key)).hex()

    def derive_public_child(self, index):
        """
        Index ranges from 0 to 2^31 - 1.  Public children cannot be hardened.
        """
        hash_msg = bytes.fromhex(self._key + hex(self._index)[2:].zfill(8))
        hash_key = bytes.fromhex(self.chain_code)

        child_hash = hmac.HMAC(key=hash_key, msg=hash_msg, 
                digestmod=hashlib.sha512).digest().hex()
        
        I_L = child_hash[:64]
        chain_code = child_hash[64:]
        
        child_key = int(I_L, 16) + int(self._key, 16)

        depth = self._depth + 1
        # Fingerprint is first 4 bytes of hash160 of parent's public key (compressed)
        fingerprint = self.id()[:8]
        path = self._path + f'/{index}'

        return self.__class__(public_key=hex(child_key)[2:], chain_code=chain_code, 
                index=index, depth=depth, parent_fingerprint=fingerprint, path=path)
    