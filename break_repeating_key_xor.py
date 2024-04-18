from dataclasses import dataclass, astuple
from typing import Optional
from itertools import combinations
from frequencies import NL_uc as frequencies
## some basic functions required to break xor

def xor_bytes(in1:bytes, in2:bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(in1, in2))

def repeating_key_xor(orig_bytes: bytes, key_bytes: bytes) -> bytes:
    expanded_key = bytearray()
    for i in range(len(orig_bytes)):
        expanded_key.append(key_bytes[i % len(key_bytes)])
    return xor_bytes(orig_bytes, expanded_key)

# make a hamming weight lookup table. 
# we save a lot of time by pre computing these values 

def hamming_distance(a:bytes, b: bytes) -> int:
    return sum(weights[byte] for byte in xor_bytes(a,b))

def _get_hamming_weights():
    weights = {0: 0}
    pow_2 = 1
    for _ in range(8):
        for k, v in weights.copy().items():
            weights[k+pow_2] = v + 1
        pow_2 <<= 1
    return weights

weights = _get_hamming_weights()


### repeating single byte xor

@dataclass(order=True)
class ScoredGuess:
    score: float = float("inf")
    key: Optional[int] = None # key as int
    ciphertext : Optional[bytes] = None
    plaintext: Optional[bytes] = None

    @classmethod
    def from_key(cls, ct, key_val):
        full_key = bytes([key_val]) * len(ct)
        pt = xor_bytes(ct,full_key)
        score = score_text(pt)
        return cls(score, key_val, ct, pt)

### actualy making stuff that can break xor
def crack_single_byte_xor(ct: bytes) -> ScoredGuess:
    best_guess = ScoredGuess()

    ct_len = len(ct)
    ct_freqs = {b: ct.count(b) / ct_len for b in range(256)}
    for possible_key in range(256):
        score = 0 
        for latter, frequency_expected in frequencies.items():
            score += abs(frequency_expected - ct_freqs[ord(latter) ^ possible_key])
        guess = ScoredGuess(score, possible_key)
        best_guess = min(best_guess, guess)
    
    best_guess.ciphertext = ct
    best_guess.plaintext= xor_bytes(ct, bytes([best_guess.key]) * len(ct))
    
    return best_guess


MAX_KEYSIZE = 40

def crack_repeating_key_xor(ciphertext: bytes, keysize: int) -> tuple[float, bytes]:
    chunks = [ciphertext[i::keysize] for i in range(keysize)]
    cracks = [crack_single_byte_xor(chunk) for chunk in chunks]

    combined_score = sum(guess.score for guess in cracks) / keysize
    key = bytes(guess.key for guess in cracks) 
    return combined_score, key

def guess_keysize(ct: bytes, num_guesses: int = 1) -> list[tuple[float, int]]:
    def get_score(size: int) -> float:
        chunks = (ct[:size],
                  ct[size:2 * size],
                  ct[2 * size:3 * size],
                  ct[3 * size:4 * size])
        avg = sum(hamming_distance(a, b) for a, b in combinations(chunks, 2)) / 6  # 6 because we 4 blocks and get all combinations of len 2
        return avg / size  # normalize by dividing by the size

    scores = [(get_score(size), size) for size in range(2, MAX_KEYSIZE + 1)]
    scores.sort()
    return scores[:num_guesses]
