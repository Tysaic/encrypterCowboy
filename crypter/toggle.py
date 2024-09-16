#!/bin/python3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
import base64
import os
import binascii
import secrets

class CypherHandler:
    """
    False => encrypt
    True => decrypt
    """

    def __init__(self, password=None, credentials_files=None):
        # Generating key
        if not credentials_files:
            
            if not password:
                self.password = bytes(secrets.token_urlsafe(16), 'utf-8')
            else:
                self.password = bytes(password, 'utf-8')

            self.salt = os.urandom(16) 
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA512(),
                length = 32,
                salt = os.urandom(16),
                #salt = b'\xa36&\xf9\xcc\xaan\x0f\x8c\x80\xb5I\xe2?\x15\xcd',
                iterations = 480000,
            )
            print("[!] There are not salts and any credentials file. [!]")
            print("[!] The salt would be difficult and get wrong decrypt function if not set.")
            print("[!] Credentials built with random salt and password if the case.")
            print("[+] Please save the document called 'credentials.txt' to future decrypt and encryptions.")
            print("[+] Save the file in a site where only you can access no anybody else.")
            self.credentials_builder()
        else:
            # Read the credentials file
            with open(credentials_files, "r") as file:
                lines = file.readlines()
                # Extract the password and salt from the file
                password = lines[0].strip().split(":")[1]
                salt = lines[1].strip().split(":")[1]
                # Convert the salt from string to bytes
                self.salt  = binascii.unhexlify(salt)
                # Set the password and salt in the key derivation function
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=self.salt,
                    iterations=480000,
                )
                self.password = bytes(password, 'utf-8')

        self.key = base64.urlsafe_b64encode(kdf.derive(self.password))
        self.cypher_suite = Fernet(self.key)

    def get_cypher_keys(self) -> tuple:
        """
        Return  Simple Key
        [self.key, self.cyphersuite]
        """

        return (self.key, self.cyphersuite)

    def get_cypher_suite(self):
        """
        Return the cipher suite used by the encrypter.

        Returns:
            str: The cipher suite used by the encrypter.
        """
        return self.cypher_suite
    
    def salt_password_combination(self, password, salt) -> str:
        pass


    def file_directory_checker(self, path) -> dict:
        """
        Check if the given path is a file, a directory, or if it exists.

        Args:
            path (str): The path to be checked.

        Returns:
            dict: A dictionary containing the following information:
                - is_file (bool): True if the path is a file, False otherwise.
                - is_dir (bool): True if the path is a directory, False otherwise.
                - is_exists (bool): True if the path exists, False otherwise.
        """

        is_file = os.path.isfile(path) 
        is_dir = os.path.isdir(path)
        is_exists_path = os.path.exists(path)

        return {'is_file': is_file, 'is_dir': is_dir, 'is_exists': is_exists_path}


    
    def encrypter(self, path, cypher_type = False) -> None:

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


    def encrypt_file(self, path, flag_cypher = False) -> bool:
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
        
        return True



    def rename_encrypter_fname(self, absolute_path, encrypt_file = False) -> None:
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
        print("[+] Files encrypted")

    def credentials_builder(self) -> None :
        """
        Create a text file and save a randomly generated salt.
        """
        # Generate a random salt
        #salt = os.urandom(16) #.hex()
        salt = self.salt
        # Convert the password to a string
        password = "secret_password:" + self.password.decode("utf-8")

        # Convert the salt to a string
        _salt = binascii.hexlify(salt).decode('utf-8')
        string_salt = "secret_salt:" + _salt

        # Write the password and salt to the credentials file
        with open("credentials.txt", "w") as file:
            for item in [password, string_salt,]:
                file.write(item + "\n")

        # Print a message indicating that the credentials file is created
        print("[+] Credentials file is created")

    def convert_hex_to_bytes(self, hex_string):
        print("HEX:", hex_string)
        return binascii.unhexlify(hex_string)

if __name__ == '__main__':
    password = input("Enter password: ")
    cypher_handler = CypherHandler(password)
    #path = "/opt/github-tools/encrypter_cowboy/crypter/file_to_encrypt.txt"
    #decrypt_or_encrypt = True # True = decrypt , False = encrypt
    #cypher_handler.encrypter(path, decrypt_or_encrypt)
    cypher_handler.credentials_builder()

