from cryptography.fernet import Fernet

def generate_key(password):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode()), key

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

