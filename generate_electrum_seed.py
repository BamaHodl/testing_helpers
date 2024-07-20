import hashlib
import hmac
import math
import secrets
import argparse
from embit import bip39
from seedsigner.models.settings_definition import SettingsConstants


def randrange(bound: int) -> int:
    return secrets.randbelow(bound - 1) + 1

def prefix_matches(mnemonic_str: str, prefix: str) -> bool:
    s = hmac.digest(b"Seed version", mnemonic_str.encode('utf8'), hashlib.sha512).hex()
    return s.startswith(prefix)

def mnemonic_encode(i: int) -> str:
    n = len(bip39.WORDLIST)
    words = []
    while i:
        x = i % n
        i = i//n
        words.append(bip39.WORDLIST[x])
    return ' '.join(words)

def make_seed(prefix: str = None, num_words: int = 12) -> str:
        bpw = math.log(len(bip39.WORDLIST), 2)
        num_bits = num_words*11
        entropy = 1
        while entropy < pow(2, num_bits - bpw):  # try again if seed would not contain enough words
            entropy = randrange(pow(2, num_bits))
        # brute-force seed that has correct prefix
        nonce = 0
        while True:
            nonce += 1
            i = entropy + nonce
            seed = mnemonic_encode(i)
            if prefix_matches(seed, prefix):
                return seed

parser = argparse.ArgumentParser("generate_electrum_seed")
parser.add_argument('-w', '--num_words', required=True, type=int)
parser.add_argument('-l', '--legacy',
                    action='store_true')
args = parser.parse_args()
if args.num_words == 13:
    if not args.legacy:
        raise Exception("Only legacy electrum seeds can be 13 words")
elif args.num_words != 12:
        raise Exception("Electrum seeds can only be 12 or 13 words")
s = make_seed(SettingsConstants.ELECTRUM_SEED_STANDARD if args.legacy else SettingsConstants.ELECTRUM_SEED_SEGWIT, args.num_words)
print(s)
