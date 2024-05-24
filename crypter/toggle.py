#!/bin/python3
from cryptography.fernet import Fernet
import os


class CypherHandler:

    def __init__(self, password):

        # Generating key
        self.password = password
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.generate_key = self.cipher_suite.encrypt( self.password.encode() )

    def get_keys(self):
        """
        Return  Simple Key and Generate_key
        [self.generate_key, self.key]
        """

        return (self.key, self.generate_key)

    def get_cipher_suite(self):

        """
        Return cipher suite
        """
        return self.cipher_suite

    def file_directory_checker(self, path):

        is_file = os.path.isfile(path) 
        is_dir = os.path.isdir(path)
        is_exists_path = os.path.exists(path)

        return {'is_file': is_file, 'is_dir': is_dir, 'is_exists': is_exists_path}


    
    def encrypter(self, path):

        """
        This function encrypts files and directories every content and their names.
        """
        #is_file = os.path.isfile(path) 
        #is_directory = os.path.isdir(path)
        checker = self.file_directory_checker(path)

        # Check if there are a simple file or directory
        if checker['is_exists']:

            if checker['is_file']:
                # Encrypting single file
                self.encrypt_file(path)
                # Rename File
                self.rename_encrypter_fname(path, True)

            elif checker['is_dir']:
                # Order the tree from last point to the root
                tree = iter(os.walk(path, topdown=False))
                for absolute_path_item, dirnames_item, filesnames_item in tree:
                    # Encrypting files
                    for file_item in filesnames_item:
                        self.encrypt_file(os.path.join(absolute_path_item, file_item), False)
                    # Encrypting directories
                    for dir_item in dirnames_item:
                        self.encrypt_file(os.path.join(absolute_path_item, dir_item), False)

                print("[!] Recursive item are encrypted.")


    def encrypt_file(self, path, flag_cypher = False):
        """
        Encrypter and decrypter function 
        path: relative or absolute path where store the data to handler
        flag_cypher = False to encrypt by default, True to decrypt 
        """
        # Checking if is file or folder
        checker = self.file_directory_checker(path)
        
        # Defining local encrypt just file data
        def encrypt_data(path):
            with open(path, 'rb') as delta_file:
                if flag_cypher:
                    print(self.get())
                    #crypted_data = self.cipher_suite.decrypt(delta_file.read())
                else:
                    crypted_data = self.cipher_suite.encrypt(delta_file.read())
                with open(path, 'wb') as file_to_write:
                    file_to_write.write(crypted_data)

        # If file encrypt data is folder just change the name encrypter
        if checker['is_exists']:

            if checker['is_file']:
                encrypt_data(path)
                self.rename_encrypter_fname(path, True)

            elif checker['is_dir']:
                self.rename_encrypter_fname(path, True)



    def rename_encrypter_fname(self, absolute_path, encrypt_file = True):
        """
        Encrypting the name as the folder and the files.
        encrypt_or_decrypt => True default to encrypt, False to decrypt
        """
        single_name = os.path.basename(absolute_path)
        if encrypt_file:
            new_name = self.cipher_suite.encrypt(single_name.encode()).decode()
        else:
            new_name = self.cipher_suite.decrypt(single_name.encode()).decode()

        full_path_new_name = os.path.join(os.path.dirname(absolute_path), new_name)
        os.rename(absolute_path, full_path_new_name)
        return print("[+] Files encrypted")


password = input("Enter password: ")
cypher_handler = CypherHandler(password)
path = "/opt/github-tools/encrypter_cowboy/crypter/folder_to_encrypt"
cypher_handler.encrypter(path)



"""
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data)
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    
    with open(encrypted_file_path[:-4], 'wb') as f:  # remove '.enc' from file name
        f.write(decrypted_data)

# Example usage
password = input("Enter password: ")
encrypted_password, key = generate_key(password)

encrypt_file("example.txt", key)
print("File encrypted successfully!")

# Decrypting the file
decrypt_file("example.txt.enc", key)
print("File decrypted successfully!")

"""
