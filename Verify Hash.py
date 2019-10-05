#!/usr/bin/python3

'''
 ' Hash Verifier in Python 3
 ' Author: Sanjan Geet Singh <>
'''

import sys
import hashlib
import datetime

md5_len = 32
sha1_len = 40
sha224_len = 56
sha256_len = 64
sha384_len = 96
sha512_len = 128

def error(msg, code=-1):
    print("Error:", msg)
    exit(code)

def readFile(file):
    try:
        f = open(file, 'rb')
        c = f.read()
        f.close()
        return c
    except FileNotFoundError:
        error("File {} Not Found.".format(file))

def now():
    return datetime.datetime.now()

def usage():
    print('Usage: python3 "Verify Hash.py" [file] [hash]')
    exit(0)

def main(arg):
    start_time = now()

    if len(arg) != 2:
        usage()

    file = arg[0]
    file_contents = readFile(file)
    given_hash = arg[1].lower()
    l = len(given_hash)

    if l == md5_len:
        print("Algorithm Detected: MD5")
        generated_hash = hashlib.md5(file_contents)
    elif l == sha1_len:
        print("Algorithm Detected: SHA1")
        generated_hash = hashlib.sha1(file_contents)
    elif l == sha224_len:
        print("Algorithm Detected: SHA224")
        generated_hash = hashlib.sha224(file_contents)
    elif l == sha256_len:
        print("Algorithm Detected: SHA256")
        generated_hash = hashlib.sha256(file_contents)
    elif l == sha384_len:
        print("Algorithm Detected: SHA384")
        generated_hash = hashlib.sha384(file_contents)
    elif l == sha512_len:
        print("Algorithm Detected: SHA512")
        generated_hash = hashlib.sha512(file_contents)
    else:
        error("Unknown Algorithm.")

    generated_hash = generated_hash.hexdigest()
    print("Input Hash:", given_hash)
    print("Generated Hash:", generated_hash)

    if generated_hash == given_hash:
        print("[+] Hashes Matched")
    else:
        print("[-] Hashes Mismatched")

    stop_time = now()
    print("Time Elapsed:", stop_time-start_time)

if __name__ == '__main__':
    sys.argv.pop(0)
    main(sys.argv)
