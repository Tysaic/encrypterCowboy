import unittest

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
    def test_set_creds(self):
        self.assertTrue(True)

if __name__ == '__main__':
    unittest.main()