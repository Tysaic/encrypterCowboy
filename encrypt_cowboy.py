#!/bin/python3
import argparse
import os
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
    parser.add_argument("--create-credentials", type=str, help='Create a credentials file')
    parser.add_argument("--set-creds", type=str, help='Create a credentials file')

    args = parser.parse_args()
    password = args.password if args.password else args.P
    #cypher_handler = CypherHandler(password)
    credentials_files = args.set_creds if args.set_creds else ""
    if args.set_creds:
        cypher_handler = CypherHandler(credentials_files=credentials_files)

    """
    List of options.
    Encrypt - Decrypt - Creating credentials file
    """
    if args.encrypt or args.e:
        decrypt_or_encrypt = False # True = decrypt , False = encrypt
        path = args.encrypt if args.encrypt else args.e
        print("[+] Encrypt the files and folders.")
    elif args.decrypt or args.d:
        decrypt_or_encrypt = True # True = decrypt , False = encrypt
        path = args.decrypt if args.decrypt else args.d
        print("[+] Decrypt the files and folders.")
    elif args.create_credentials:
        #Provisional
        cypher_handler = CypherHandler(password=password, credentials_files=None)
        # Provisional
        print("Creating credentials file")
    
    cypher_handler.encrypter(path, decrypt_or_encrypt)







    #cypher_handler.encrypter(path, decrypt_or_encrypt, credentials_files)

    #password = 0000
    #crypt_handler = CypherHandler(password)

