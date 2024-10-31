import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature

def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 біт для AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

password = b'rasp!332ddarYA#'
salt = os.urandom(16)
key = generate_key(password, salt)
iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

def pad_data(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

data = b"Example data to encrypt"
padded_data = pad_data(data)

encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
mac = h.finalize()

with open('encrypted_file.bin', 'wb') as f:
    f.write(salt + iv + mac + encrypted_data)

with open('encrypted_file.bin', 'rb') as f:
    salt = f.read(16)
    iv = f.read(16)
    mac = f.read(32)
    encrypted_data = f.read()

key = generate_key(password, salt)

h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(encrypted_data)
h.verify(mac)

decryptor = cipher.decryptor()
decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

def unpad_data(padded_data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

data = unpad_data(decrypted_padded_data)
print(data)  # Вивід оригінальних даних

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = pad_data(data)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + mac + encrypted_data)

    messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        mac = f.read(32)
        encrypted_data = f.read()

    key = generate_key(password, salt)   
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(mac)
    except InvalidSignature:
        messagebox.showerror("Error", "MAC verification failed!")
        return

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    data = unpad_data(decrypted_padded_data)

    with open(file_path.replace('.enc', ''), 'wb') as f:
        f.write(data)

    messagebox.showinfo("Success", "File decrypted successfully!")

root = tk.Tk()
root.title("AES Encryption/Decryption")

encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_button.pack(pady=20)

decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_button.pack(pady=20)

root.mainloop()
