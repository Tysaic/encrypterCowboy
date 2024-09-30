import unittest
from crypter.toggle import CypherHandler
import os

class TestSetCreds(unittest.TestCase):
    """
    Define test to the follow examples:
    * Creating credentials with password
    * Creating credentials without password
    * Encrypt files and folders with credentials in memory
    * Encrypt files and folders with credentials from set creds
    * Decrypt files and folders with credentials in memory
    * Decrypt files and folders with credentials from set creds
    
    Run: python -m unittest tests/test.py
    """
    def setUp(self):
        self.password = "$$abcd1234"
        self.handler = CypherHandler(password=self.password)

    def test_create_credentials_with_password(self):
        self.handler.credentials_builder()
        with open("credentials.txt", "r") as file:
            """
            Testing Command:
                python encrypter_cowboy.py --create-credentials --password <password>
            """
            lines_to_read = file.readlines()
            self.assertIn("secret_password:", lines_to_read[0])
            self.assertTrue("secret_password:"+self.password+"\n", lines_to_read[0])
            self.assertIn("secret_salt:", lines_to_read[1])
            self.assertTrue(lines_to_read[1].startswith("secret_salt:"))
        
        os.remove(os.getcwd()+"/credentials.txt")
        print("[T+] Testing create credentials with password is Done!")
    
    def test_credentials_without_password(self):
        """
        Testing Command:
            python encrypter_cowboy.py --create-credentials
        """
        handler = CypherHandler(password=None)
        handler.credentials_builder()
        with open("credentials.txt", "r") as file:
            lines_to_read = file.readlines()
            self.assertIn("secret_password:", lines_to_read[0])
            self.assertTrue("secret_password:"+lines_to_read[0]+"\n")
            self.assertIn("secret_salt:", lines_to_read[1])
            self.assertTrue("secret_salt:"+lines_to_read[1]+"\n")
        os.remove(os.getcwd()+"/credentials.txt")
        print("[T+] Testing create credentials without password is Done!")
    
    def test_encrypting_single_file(self):
        """
        python encrypter_cowboy.py --encrypt <file_or_folder_path> --password <password>
        """
        file_to_encrypt = os.getcwd()+"/tests/file_to_encrypt.txt"
        original_content = "This is a test file to encrypt"
        with open(file_to_encrypt, "w") as file_path:
            file_path.write(original_content)
        self.handler.encrypter_decrypter(file_to_encrypt, cypher_type=False)
        with open(file_to_encrypt, "r") as file_path:
            encrypted_content = file_path.read()
        self.assertNotEqual(original_content, encrypted_content)
        print("[T+] Testing encrypting single file is Done!")
    
    def test_decrypting_single_file(self):
        """
        python encrypter_cowboy.py --decrypt <file_or_folder_path> --password <password>
        """
        file_to_decrypt = os.getcwd()+"/tests/file_to_decrypt.txt"
        original_content = "This is a test file to decrypt"

        with open(file_to_decrypt, "w") as file_path:
            file_path.write(original_content)
        self.handler.encrypter_decrypter(file_to_decrypt, cypher_type=False)
        with open(file_to_decrypt, "r") as file_path:
            encrypted_content = file_path.read()

        decryted_file = self.handler.encrypter_decrypter(file_to_decrypt, cypher_type=True)
        with open(file_to_decrypt, "r") as file_path:
            decrypted_content = file_path.read()
        self.assertEqual(original_content, decrypted_content)
        print("[T+] Testing decrypting single file is Done!")


if __name__ == '__main__':
    unittest.main()