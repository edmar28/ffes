
# File/Folder Encryption Script

This project is a Python script that encrypts files or folders using AES-GCM encryption. It provides password-based decryption and includes a mechanism to permanently delete the encrypted file or folder if the user fails to provide the correct password within three attempts.




## Features

- File/Folder Encryption: Encrypt files or folders using a password.
- Password-Based Decryption: Decrypt files or folders only with the correct password.
- Deletion After 3 Failed Attempts: After three incorrect password attempts, the encrypted file or folder is permanently deleted, along with the salt file.
- AES-GCM Encryption: Ensures data confidentiality, integrity, and authentication.


## Requirements
- Python 3.x
- The cryptography library

Install the cryptography library via pip if you haven't already:
```bash
  pip install cryptography
```


## Usage
### Encrypt a File or Folder
To encrypt a file or folder, run the script and select the encryption option:
```bash
  python encryptor.py
```

You will be prompted to enter the file or folder path and set a password for encryption. The script generates a salt file (with a .salt extension) and stores it in the same directory as the encrypted file or folder.

    
## Decrypt a File or Folder
To decrypt an encrypted file or folder, run the script and select the decryption option:
```bash
  python encryptor.py
```
You will be prompted to provide the decryption password. If you fail to provide the correct password within three attempts, the encrypted file or folder, along with its salt file, will be permanently deleted.

# How It Works
## Encryption
1. A password is provided by the user and is used to derive a 256-bit key via PBKDF2 (Password-Based Key Derivation Function 2) with a random salt.
2. The file or folder is encrypted using AES-GCM (Galois/Counter Mode), which provides confidentiality and authenticity.
3. The encrypted data overwrites the original file or folder, making it inaccessible without the correct password.
4. A salt file (<filename>.salt) is generated and saved, which is needed for decryption.

## Decryption
1. The user must provide the correct password to decrypt the file or folder.
2. The password is used to regenerate the encryption key, and the file or folder is decrypted.
3. If the password is incorrect, the user has three attempts before the file or folder is deleted

## After 3 Failed Attempts
- If the password is incorrect after three attempts, the script will delete both the encrypted file/folder and the associated salt file, leaving no trace of the original content.


#Example
## Encrypting a File:
```bash
Do you want to (e)ncrypt or (d)ecrypt?: e
Enter the file or folder path: /path/to/myfile.txt
Set a password to encrypt the file or folder: *****
File /path/to/myfile.txt has been encrypted.
```

## Decrypting a File:
```bash
Do you want to (e)ncrypt or (d)ecrypt?: d
Enter the file or folder path: /path/to/myfile.txt
Enter the decryption password: *****
Incorrect password. 2 attempt(s) remaining.
Enter the decryption password: *****
Incorrect password. 1 attempt(s) remaining.
Enter the decryption password: *****
File /path/to/myfile.txt has been permanently deleted.
```

## Limitations
- Loss of Salt File: If the salt file is deleted or lost, decryption is impossible, as the key cannot be regenerated.
- No Folder Compression: The script encrypts the contents of folders but does not compress them. Each file inside the folder is individually encrypted.

## Future Improvements
- Support for file/folder compression before encryption.
- Adding a log file to track failed attempts (without storing passwords).
- Extending to support other encryption algorithms or modes.****












