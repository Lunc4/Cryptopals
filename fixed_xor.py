# zipped invoer a en b en XORed vervolgens een voor een alle bytes 

def xor_bytes(a:bytes,b:bytes) -> bytes:
    return bytes(x ^ y for x,y in zip(a,b))
    
