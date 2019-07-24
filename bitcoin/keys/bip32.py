import hashlib
import hmac
from ..core import base58
from .keys import get_public_key, get_private_key
from ..core.utilities import hash160

# Constant
CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16) # The order of secp256k1

class KeyNode:
    """
    Implement a Hierarchial deterministic wallet as specified in BIP32.
    
    
    """
    def __init__(self, chain_code, private_key=None, public_key=None, 
                 index=0,  depth=0, parent_fingerprint="00000000"):

        self.__chain_code          = chain_code
        self.__priv_key            = private_key
        self.__pub_key             = public_key
        self.__index               = index # index of this node
        self.__parent_fingerprint  = parent_fingerprint # the first 8 hex digits of the hash160 of the parent's public key.
        self.__depth               = depth

        self.__is_private          = private_key is not None # Whether this node can produce private nodes
        
        if self.__is_private:
            self.__fingerprint = hash160(bytes.fromhex(get_public_key(self.__priv_key)))[:8]
        else:
            self.__fingerprint = hash160(self.__pub_key)[:8]

    @classmethod
    def from_master_seed(cls, seed):
        private_key = seed[:len(seed) // 2]
        chain_code = seed[len(seed) // 2:]
        return cls(chain_code, private_key)
    
    @classmethod
    def from_extended_key(cls, extended_key):
        """
        Creates a KeyNode from a base58Check encoded extended key

        Parameters:
            extended_key (String): The base58Check encoded extended key
        """


    def serialize_node(self, version):
        if version == "private" and self.__is_private == False:
            raise ValueError("Cannot serialize public node as private")
        elif version == "public" and self.__is_private == True:
            raise ValueError("Cannot serialize private node as public")
    
        prefix = {
            "private"     : "0488ADE4",
            "public"      : "0488B21E",
            "test-private": "04358394",
            "test-public" : "043587CF",
        }    
        node_hex = prefix[version] + hex(self.__depth)[2:].zfill(2) # 4 bytes for version and  1 byte for depth
        node_hex += self.__parent_fingerprint.zfill(8) # 4 bytes for parent's fingerprint
        node_hex += hex(self.__index)[2:].zfill(8) # 4 bytes for index (Child Number)
        node_hex += self.__chain_code.zfill(64) # 32 bytes for the chain code

        if version == "private" or version == "test-private":
            node_hex += "00" + self.__priv_key.zfill(64) # 33 bytes for private key
        else: 
            node_hex += self.__pub_key.zfill(66)
        serialised_node = base58.b58encode_check(bytes.fromhex(node_hex))
        return serialised_node.decode()
        
    def get_key(self):
        if self.__is_private:
            return self.__priv_key
        else:
            return self.__pub_key

    def index(self):
        return self.__index
    
    def path(self):
        path = ""
        return path
        
    def derive_child_private_key(self, index, is_hardened=False):
        """
        Derives the child node at index i

        Parameters:
            index (int): The child node number, ranges from 0 to 2^31 - 1.  If child is
                         hardened, then index is added to 2^31.
            is_hardened (Boolean): True if the child node is to be hardened.  False otherwise
        
        """
        if is_hardened:
            index += (2 ** 31)
            data = "00" + self.__priv_key + hex(index)[2:]
        else:
            data = get_public_key(self.__priv_key) + hex(index)[2:].zfill(32)

        data_bytes = bytes.fromhex(data)
        chain_code_bytes = bytes.fromhex(self.__chain_code)

        extended_child_key = hmac.HMAC(key=chain_code_bytes, msg=data_bytes, digestmod=hashlib.sha512).hexdigest()
        left_half = extended_child_key[:64]
        child_priv_key_int = (int(left_half, 16) + int(self.__priv_key, 16)) % CURVE_ORDER
        
        child_property_dict = dict(
            chain_code=extended_child_key[64:],
            private_key=hex(child_priv_key_int)[2:],
            public_key=get_public_key(extended_child_key[64:]),
            index=index,
            parent_fingerprint=self.__fingerprint,
            depth=self.__depth + 1
        )

        return KeyNode(**child_property_dict)
