#!/usr/bin/python3

'''
 ' Hash Generator in Python 3
 ' Author: Sanjan Geet Singh <>
'''

import hashlib
import sys
import datetime

hash_functions = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

def error(msg, code=-1):
    print("Error:", msg)
    exit(code)

def now():
    return datetime.datetime.now()

def readFile(filename):
    try:
        file = open(filename, 'rb')
        contents = file.read()
        file.close()
        return contents
    except FileNotFoundError:
        error("File {} Not Found.".format(filename))

def usage():
    print('Usage: python3 "Generate Hash.py" [file] [hash function]')
    print('Supported Algorithms:')
    for i in hash_functions:
        print('     {}'.format(i))
    exit(0)

def main(args):
    start_time = now()

    file = args[0]
    hash_func = args[1].lower()

    if (hash_func in hash_functions) == False:
        error("Unknown Algorithm.")

    file_contents = readFile(file)

    if hash_func == 'md5':
        hash = hashlib.md5(file_contents)
    elif hash_func == 'sha1':
        hash = hashlib.sha1(file_contents)
    elif hash_func == 'sha224':
        hash = hashlib.sha224(file_contents)
    elif hash_func == 'sha256':
        hash = hashlib.sha256(file_contents)
    elif hash_func == 'sha384':
        hash = hashlib.sha384(file_contents)
    elif hash_func == 'sha512':
        hash = hashlib.sha512(file_contents)

    hash = hash.hexdigest()
    stop_time = now()

    print("Hash:", hash)
    print("Time Elapsed:", stop_time-start_time)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    else:
        args = sys.argv
        args.pop(0)
        main(args)
