from Crypto.Hash import SHA512, MD2, MD4, MD5
import hashlib
import blake3
import rhash
import hashbase

def ed2k_hash(text: str):
    return rhash.hash_msg(text, rhash.ED2K)

def has160_hash(text: str):
    return rhash.hash_msg(text, rhash.HAS160)

def AICH_hash(text: str):
    return rhash.hash_msg(text, rhash.AICH)

def BTIH_hash(text: str):
    return rhash.hash_msg(text, rhash.BTIH)

def tiger_hash(text: str):
    return rhash.hash_msg(text, rhash.TIGER)

def whirlpool_hash(text: str):
    return rhash.hash_msg(text, rhash.WHIRLPOOL)

class RIPEMD:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text
    
    def ripemd128_hash(self):
        return hashbase.RIPEMD128().generate_hash(self.text)
    
    def ripemd160_hash(self):
        return hashbase.RIPEMD160().generate_hash(self.text)
    
    def ripemd256_hash(self):
        return hashbase.RIPEMD256().generate_hash(self.text)
    
    def ripemd320_hash(self):
        return hashbase.RIPEMD320().generate_hash(self.text)

class SNEFRU:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text
    def snefru128_hash(self):
        return rhash.hash_msg(self.text, rhash.SNEFRU128)
    def snefru256_hash(self):
        return rhash.hash_msg(self.text, rhash.SNEFRU256)

class SHA:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text.encode()

    def sha1_hash(self):
        return hashlib.sha1(self.text).hexdigest()

    def sha224_hash(self):
        return hashlib.sha224(self.text).hexdigest()

    def sha256_hash(self):
        return hashlib.sha256(self.text).hexdigest()

    def sha384_hash(self):
        return hashlib.sha384(self.text).hexdigest()

    def sha512_hash(self):
        return hashlib.sha512(self.text).hexdigest()

    def sha512_224_hash(self):
        h = SHA512.new(data=self.text)
        return h.digest()[:28].hex()

    def sha512_256_hash(self):
        h = SHA512.new(data=self.text)
        return h.digest()[:32].hex()

    def sha3_224_hash(self):
        return hashlib.sha3_224(self.text).hexdigest()

    def sha3_256_hash(self):
        return hashlib.sha3_256(self.text).hexdigest()

    def sha3_384_hash(self):
        return hashlib.sha3_384(self.text).hexdigest()

    def sha3_512_hash(self):
        return hashlib.sha3_512(self.text).hexdigest()

    def shake128_hash(self, length=32):
        shake = hashlib.shake_128()
        shake.update(self.text)
        return shake.hexdigest(length)

    def shake256_hash(self, length=64):
        shake = hashlib.shake_256()
        shake.update(self.text)
        return shake.hexdigest(length)

class BLAKE:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text.encode()

    def blake2b_hash(self):
        return rhash.hash_msg(self.text, rhash.BLAKE2B)

    def blake2s_hash(self):
        return rhash.hash_msg(self.text, rhash.BLAKE2S)

    def blake3_hash(self):
        return blake3.blake3(self.text).hexdigest()

class MD:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text.encode()

    def md2_hash(self):
        h = MD2.new(data=self.text)
        return h.hexdigest()

    def md4_hash(self):
        h = MD4.new(data=self.text)
        return h.hexdigest()

    def md5_hash(self):
        h = MD5.new(data=self.text)
        return h.hexdigest()

class GOST:
    def __init__(self, text: str):
        if isinstance(text, bytes):
            self.text = text
        else:
            self.text = text.encode()

    def gost94_hash(self):
        return rhash.hash_msg(self.text, rhash.GOST94)

    def gost12_256_hash(self):
        return rhash.hash_msg(self.text, rhash.GOST12_256)

    def gost12_512_hash(self):
        return rhash.hash_msg(self.text, rhash.GOST12_512)