#!/bin/python3
import argparse
from crypter.toggle import CypherHandler

if __name__ == '__main__':
    

    parser = argparse.ArgumentParser(
        description="Encrypt and decrypter software developed in python using SHA-512",
        prog="Encrypt_Cowboy",
    )

    parser.add_argument("-e", type=str, help='Encrypt files/folders')
    parser.add_argument("--encrypt", type=str, help='Encrypt files/folder set PATH')
    parser.add_argument("--decrypt", type=str, help='Decrypt files/folders set PATH')
    parser.add_argument("-d", type=str, help='Decrypt files/folders')
    parser.add_argument("-P", type=str, help='Set password')
    parser.add_argument("--password", type=str, help='Set password')

    args = parser.parse_args()
    password = args.password if args.password else args.P 
    cypher_handler = CypherHandler(password)

    if args.encrypt or args.e:
        decrypt_or_encrypt = False # True = decrypt , False = encrypt
        path = args.encrypt if args.encrypt else args.e
        print("[+] Encrypt the files and folders.")
    elif args.decrypt or args.d:
        decrypt_or_encrypt = True # True = decrypt , False = encrypt
        path = args.decrypt if args.decrypt else args.d
        print("[+] Decrypt the files and folders.")

    cypher_handler.encrypter(path, decrypt_or_encrypt)

    #password = 0000
    #crypt_handler = CypherHandler(password)

