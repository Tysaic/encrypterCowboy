#!/bin/python3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
import base64
import os


class CypherHandler:
    """
    False => encrypt
    True => decrypt
    """

    def __init__(self, password):

        # Generating key
        self.password = bytes(password, 'utf-8') 
        print("password:", self.password)
        kdf = PBKDF2HMAC(
                algorithm = hashes.SHA512(),
                length = 32,
                #salt = os.urandom(16),
                salt = b'\xa36&\xf9\xcc\xaan\x0f\x8c\x80\xb5I\xe2?\x15\xcd',
                iterations = 480000,
        )
        #self.key = Fernet.generate_key()
        self.key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cypher_suite = Fernet(self.key)

    def get_cypher_keys(self):
        """
        Return  Simple Key
        [self.key, self.cyphersuite]
        """

        return (self.key, self.cyphersuite)

    def get_cypher_suite(self):

        """
        Return cipher suite
        """
        return self.cypher_suite

    def file_directory_checker(self, path):

        is_file = os.path.isfile(path) 
        is_dir = os.path.isdir(path)
        is_exists_path = os.path.exists(path)

        return {'is_file': is_file, 'is_dir': is_dir, 'is_exists': is_exists_path}


    
    def encrypter(self, path, cypher_type = False):

        """
        This function encrypts files and directories every content and their names.
        """
        #is_file = os.path.isfile(path) 
        #is_directory = os.path.isdir(path)
        checker = self.file_directory_checker(path)


        ### Where are here!
        # It is possible to encrypt but not to decrypt

        # Check if there are a simple file or directory
        if checker['is_exists']:

            if checker['is_file']:
                # Encrypting single file
                self.encrypt_file(path, cypher_type)
                # Rename File
                print("Called")
                #self.rename_encrypter_fname(path, cypher_type)

            elif checker['is_dir']:
                # Order the tree from last point to the root
                tree = iter(os.walk(path, topdown=False))
                for absolute_path_item, dirnames_item, filesnames_item in tree:
                    # Encrypting files
                    for file_item in filesnames_item:
                        self.encrypt_file(os.path.join(absolute_path_item, file_item), cypher_type)
                    # Encrypting directories
                    for dir_item in dirnames_item:
                        self.encrypt_file(os.path.join(absolute_path_item, dir_item), cypher_type)

                print("[!] Recursive item are encrypted.")

        else:

            print("[-] File doesn't exists! ")


    def encrypt_file(self, path, flag_cypher = False):
        """
        Encrypter and decrypter function 
        path: relative or absolute path where store the data to handler
        flag_cypher = False to encrypt by default, True to decrypt 
        """
        # Checking if is file or folder
        checker = self.file_directory_checker(path) 
        # Defining local encrypt just file data
        def encrypt_data(path, flag_cypher):
            with open(path, 'rb') as delta_file:
                if flag_cypher:
                    print("DECRYPT")
                    crypted_data = self.cypher_suite.decrypt(delta_file.read())
                else:
                    print("ENCRYPT")
                    crypted_data = self.cypher_suite.encrypt(delta_file.read())
                with open(path, 'wb') as file_to_write:
                    file_to_write.write(crypted_data)

        # If file encrypt data is folder just change the name encrypter
        if checker['is_exists']:

            if checker['is_file']:
                encrypt_data(path, flag_cypher)
                #self.rename_encrypter_fname(path, flag_cypher)
                print("ENCRYPTED FILE")

            elif checker['is_dir']:
                #self.rename_encrypter_fname(path, flag_cypher)
                pass



    def rename_encrypter_fname(self, absolute_path, encrypt_file = False):
        """
        Encrypting the name as the folder and the files.
        encrypt_or_decrypt => False default to encrypt, True to decrypt
        """
        single_name = os.path.basename(absolute_path)
        # True encrypt file False to decrypt
        if encrypt_file:
            new_name = self.cypher_suite.decrypt(single_name.encode()).decode()
        else:
            new_name = self.cypher_suite.encrypt(single_name.encode()).decode()

        full_path_new_name = os.path.join(os.path.dirname(absolute_path), new_name)
        os.rename(absolute_path, full_path_new_name)
        return print("[+] Files encrypted")



if __name__ == '__main__':
    password = input("Enter password: ")
    cypher_handler = CypherHandler(password)
    path = "/opt/github-tools/encrypter_cowboy/crypter/file_to_encrypt.txt"
    decrypt_or_encrypt = True # True = decrypt , False = encrypt
    cypher_handler.encrypter(path, decrypt_or_encrypt)
