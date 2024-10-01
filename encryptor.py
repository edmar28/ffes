import os
import shutil
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Derive encryption key from password
def get_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)

    with open(file_path, 'wb') as f:
        f.write(nonce + encrypted_data)

# Decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()

    nonce = data[:12]
    encrypted_data = data[12:]
    aesgcm = AESGCM(key)

    try:
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        return True
    except:
        return False

# Encrypt all files in a folder recursively
def encrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            encrypt_file(os.path.join(root, file), key)

# Decrypt all files in a folder recursively
def decrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if not decrypt_file(os.path.join(root, file), key):
                return False
    return True

# Delete file or folder
def delete_file_or_folder(path):
    if os.path.isfile(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    print(f"{path} has been permanently deleted.")

# Main function to encrypt
def encrypt(path):
    password = getpass.getpass("Set a password to encrypt the file or folder: ")
    salt = os.urandom(16)  # Random salt for password derivation
    key = get_key_from_password(password, salt)

    # Save salt to a file for later decryption
    with open(f"{path}.salt", 'wb') as f:
        f.write(salt)

    if os.path.isfile(path):
        encrypt_file(path, key)
        print(f"File {path} has been encrypted.")
    elif os.path.isdir(path):
        encrypt_folder(path, key)
        print(f"Folder {path} has been encrypted.")
    else:
        print("Invalid file or folder path")

# Main function to decrypt
def decrypt(path):
    attempts = 0
    max_attempts = 3

    if not os.path.exists(f"{path}.salt"):
        print("Salt file not found. Decryption is impossible.")
        return

    # Read the salt from the file
    with open(f"{path}.salt", 'rb') as f:
        salt = f.read()

    while attempts < max_attempts:
        password = getpass.getpass("Enter the decryption password: ")
        key = get_key_from_password(password, salt)

        if os.path.isfile(path):
            if decrypt_file(path, key):
                print(f"File {path} has been decrypted.")
                return
        elif os.path.isdir(path):
            if decrypt_folder(path, key):
                print(f"Folder {path} has been decrypted.")
                return
        else:
            print("Invalid file or folder path")
            return

        attempts += 1
        print(f"Incorrect password. {max_attempts - attempts} attempt(s) remaining.")

    # If all attempts fail, delete the file or folder
    delete_file_or_folder(path)
    os.remove(f"{path}.salt")  # Remove the salt file as well

# Entry point
if __name__ == "__main__":
    action = input("Do you want to (e)ncrypt or (d)ecrypt?: ").lower()
    path = input("Enter the file or folder path: ")

    if action == 'e':
        encrypt(path)
    elif action == 'd':
        decrypt(path)
    else:
        print("Invalid option selected.")
