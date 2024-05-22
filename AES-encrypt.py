import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_key():
    #opens private key file.
    #"rb" makes it read the file in binary
    with open("private_key.bin", "rb") as file:
        #save the key as a variable
        key = file.read()
    return key

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

        #take the initialization vector from the text
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        #create a cipher object to decrypt
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        #decrypt the cipher
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        with open(output_file, "wb") as f:
            f.write(plaintext)


def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()#Makes plaintext = file contents

    iv = os.urandom(16)  # Initialization Random iv, Makes the ciphertext random every time its generated
    #Makes cipher equal to the Cipher object in the liabry specifiying AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    #Makes it so the ecryptor object will encrypt text given to it.
    encryptor = cipher.encryptor()
    #encrypts plain text
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    #add the initialization vector to the cipher
    ciphertext_with_iv = iv + ciphertext


    with open(output_file, 'wb') as f:
        f.write(ciphertext_with_iv)

# runs 
#checks if this is a libary or module, If its not it will run as the main funcction
if __name__ == "__main__":
    # Looks for arguments 
    if len(sys.argv) != 3:
        print("Usage: python3 AES-encrypt.py input_file, Function(en , dn) for encryption and decryption")
        sys.exit(1)

    input_file = sys.argv[1]
    function = sys.argv[2]
    key = read_key()
    if function == "en":
        encrypt_file(input_file, 'encrypted_files.txt', key)
    elif function == "dn":
       decrypt_file(input_file, 'decrypted_files.txt', key)
