import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("900x700")
        root.title("CryptoExplorer")

        # Welcome Message Window
        self.welcome_frame = ttk.Frame(root)
        self.welcome_frame.pack(pady=50)

        ttk.Label(self.welcome_frame, text="Welcome to CryptoExplorer!", font=("Helvetica", 16)).pack(pady=10)
        ttk.Label(self.welcome_frame, text="Explore encrypting and decrypting messages.", font=("Helvetica", 12)).pack()
        ttk.Button(self.welcome_frame, text="Let's Go!", command=self.show_crypto_interface).pack(pady=20)

        # Crypto Interface (Initially Hidden)
        self.crypto_frame = ttk.Frame(root)
        self.crypto_frame.pack_forget()  # Hide initially

        # Algorithm Selection (Dropdown)
        ttk.Label(self.crypto_frame, text="Select Algorithm:").pack()
        self.algorithm_var = tk.StringVar()
        self.algorithm_combobox = ttk.Combobox(self.crypto_frame, textvariable=self.algorithm_var, state="readonly")
        self.algorithm_combobox["values"] = [
            "AES",
            "RSA",
            "XOR Cipher",
            "Caesar Cipher",
            "Block Cipher (XOR)",
            "SHA-256 Hash",
            "SHA-512 Hash",
            "MD5 Hash",
        ]
        self.algorithm_combobox.pack(pady=10)
        self.algorithm_combobox.bind("<<ComboboxSelected>>", self.update_input_area)

        # Input Type Selection (Radio Buttons)
        self.input_type_var = tk.StringVar(value="Text")  # Default value
        ttk.Radiobutton(self.crypto_frame, text="Text", variable=self.input_type_var, value="Text", command=self.update_input_area).pack()
        ttk.Radiobutton(self.crypto_frame, text="File", variable=self.input_type_var, value="File", command=self.open_file_dialog).pack()

        # Input Area (Dynamic)
        self.input_frame = ttk.Frame(self.crypto_frame)
        self.input_frame.pack()

        # Input Label
        ttk.Label(self.input_frame, text="Input:").pack()

        # Input Text Widget
        self.input_text = tk.Text(self.input_frame, height=10, width=50, state="normal")
        self.input_text.pack(pady=10)

        # Output Area
        ttk.Label(self.crypto_frame, text="Output:").pack()
        self.output_text = tk.Text(self.crypto_frame, height=10, width=50)
        self.output_text.pack(pady=10)

        # Buttons
        ttk.Button(self.crypto_frame, text="Encrypt/Hash", command=self.process_input).pack(pady=5)
        ttk.Button(self.crypto_frame, text="Decrypt", command=self.decrypt_input).pack(pady=5)

        # Define key entry
        self.key_entry = ttk.Entry(self.crypto_frame)
        self.key_entry.pack(pady=5)

        # Define private_key and public_key
        self.private_key = None
        self.public_key = None
    def open_file_dialog(self):
        if self.input_type_var.get() == "File":
            self.file_path = filedialog.askopenfilename(
                initialdir = "/",
                title = "Select a File",
                filetypes = (("Text files",
                              "*.txt*"),
                             ("all files",
                              "*.*"))
            )
            self.input_text.insert(tk.END, self.file_path)

    def pad(self, data, block_size):
        padding_length = block_size - len(data) % block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def unpad(self, data):
        padding_length = data[-1]
        assert padding_length > 0
        message, padding = data[:-padding_length], data[-padding_length:]
        assert all(p == padding_length for p in padding)
        return message
    
    def xor_encrypt_block(self, plaintext_block, key):
        encrypted_block = b""
        for i in range(len(plaintext_block)):
            encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
        return encrypted_block

    def xor_decrypt_block(self, ciphertext_block, key):
        return self.xor_encrypt_block(ciphertext_block, key) # XOR decryption is same as encryption
    

    def xor_encrypt(self, plaintext, key, block_size=16): 
        padded_plaintext = self.pad(plaintext, block_size)
        encrypted_data = b""
        for i in range(0, len(padded_plaintext), block_size):
            plaintext_block = padded_plaintext[i:i+block_size]
            encrypted_block = self.xor_encrypt_block(plaintext_block, key)
            encrypted_data += encrypted_block
        return encrypted_data

    def xor_decrypt(self, ciphertext, key, block_size=16):
        decrypted_data = b""
        for i in range(0, len(ciphertext), block_size):
            ciphertext_block = ciphertext[i:i+block_size]
            decrypted_block = self.xor_decrypt_block(ciphertext_block, key)
            decrypted_data += decrypted_block
        unpadded_decrypted_data = self.unpad(decrypted_data)
        return unpadded_decrypted_data

    def caesar_encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result

    def caesar_decrypt(self, text, shift):
        return self.caesar_encrypt(text, -shift)


    def xor_cipher(self, text, key):
        return bytes([ord(c) ^ ord(k) for c, k in zip(text, key)])
    
    def aes_encrypt(self, plaintext, key):
        f = Fernet(key)
        return f.encrypt(plaintext.encode())

    def aes_decrypt(self, ciphertext, key):
        f = Fernet(key)
        return f.decrypt(ciphertext).decode()

    def rsa_generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    # ----- Main processing functions -----    
    # ----- Main processing functions -----    
    def process_input(self):
        algorithm = self.algorithm_var.get()
        input_type = self.input_type_var.get()

        if input_type == "Text":
            input_data = self.input_text.get("1.0", tk.END).encode()
        elif input_type == "File":
            if self.file_path:
                with open(self.file_path, "rb") as f:
                    input_data = f.read()
            else:
                messagebox.showerror("Error", "Please select a file.")
                return  # Indent this return statement properly.
        key = self.key_entry.get().encode() if algorithm in ["AES", "XOR Cipher", "Block Cipher (XOR)"] else None
        shift = int(key) if algorithm == "Caesar Cipher" else 0  # Assuming key is the shift for Caesar

        self.output_text.delete("1.0", tk.END)

        if algorithm == "AES":
            try:
                key = base64.urlsafe_b64encode(key.ljust(32, b'\0'))
                encrypted_data = self.aes_encrypt(input_data, key)
                self.output_text.insert(tk.END, f"Ciphertext (AES): {encrypted_data.decode()}")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid key: {e}")
        elif algorithm == "RSA":
            if not hasattr(self, "private_key"):
                messagebox.showerror("Error", "Generate keys first!")
                return
            try:
                encrypted_data = self.rsa_encrypt(input_data.decode(), self.public_key)
                self.output_text.insert(tk.END, f"Ciphertext (RSA): {encrypted_data.hex()}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        elif algorithm == "XOR Cipher":
            encrypted_data = self.xor_cipher(input_data.decode(), key.decode())
            self.output_text.insert(tk.END, f"Ciphertext (XOR): {encrypted_data.decode()}")
        elif algorithm == "Caesar Cipher":
            encrypted_text = self.caesar_encrypt(input_data.decode(), shift)
            self.output_text.insert(tk.END, f"Ciphertext (Caesar): {encrypted_text}")
        elif algorithm == "Block Cipher (XOR)":
            block_size = 16  # You can make this customizable
            encrypted_data = self.xor_encrypt(input_data, key, block_size)
            self.output_text.insert(tk.END, f"Ciphertext (Block XOR): {encrypted_data.hex()}")
        elif algorithm == "SHA-256 Hash":
            hash_result = hashlib.sha256(input_data).hexdigest()
            self.output_text.insert(tk.END, f"SHA-256 Hash: {hash_result}")
        elif algorithm == "SHA-512 Hash":
            hash_result = hashlib.sha512(input_data).hexdigest()
            self.output_text.insert(tk.END, f"SHA-512 Hash: {hash_result}")
        elif algorithm == "MD5 Hash":
            hash_result = hashlib.md5(input_data).hexdigest()
            self.output_text.insert(tk.END, f"MD5 Hash: {hash_result}")

    def decrypt_input(self):
        algorithm = self.algorithm_var.get()
        input_type = self.input_type_var.get()
        input_data = self.input_text.get("1.0", tk.END).encode() if input_type == "Text" else self.input_text.get("1.0", tk.END)

        if algorithm in ["AES", "XOR Cipher", "Block Cipher (XOR)"]:
            key = self.key_entry.get().encode()

        shift = int(key) if algorithm == "Caesar Cipher" else 0
        block_size = 16
        
        self.output_text.delete("1.0", tk.END)
        
        if algorithm == "AES":
            try:
                key = base64.urlsafe_b64encode(key.ljust(32, b'\0'))
                decrypted_data = self.aes_decrypt(input_data, key)
                self.output_text.insert(tk.END, f"Plaintext (AES): {decrypted_data}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        elif algorithm == "RSA":
            if not hasattr(self, "private_key"):
                messagebox.showerror("Error", "Generate keys first!")
                return
            try:
                decrypted_data = self.rsa_decrypt(bytes.fromhex(input_data.decode()), self.private_key)
                self.output_text.insert(tk.END, f"Plaintext (RSA): {decrypted_data}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

        elif algorithm == "XOR Cipher":
            decrypted_data = self.xor_cipher(input_data.decode(), key.decode())
            self.output_text.insert(tk.END, f"Plaintext (XOR): {decrypted_data.decode()}")
        elif algorithm == "Caesar Cipher":
            decrypted_text = self.caesar_decrypt(input_data.decode(), shift)
            self.output_text.insert(tk.END, f"Plaintext (Caesar): {decrypted_text}")
        elif algorithm == "Block Cipher (XOR)":
            key = self.pad(bytes(key.encode()), block_size)
            decrypted_data = self.xor_decrypt(input_data, key, block_size)
            self.output_text.insert(tk.END, f"Plaintext (Block XOR): {decrypted_data.decode()}")
        else:
            messagebox.showerror("Error", "Decryption not applicable for hash algorithms.")


    def show_crypto_interface(self):
        self.welcome_frame.pack_forget()
        self.crypto_frame.pack(pady=20)

    def update_input_area(self, event=None):
        algorithm = self.algorithm_var.get()
        if algorithm == "Text":
            self.input_text.config(state="normal")
            self.input_text.delete("1.0", tk.END)
        else:  # File
            self.input_text.config(state="disabled")
            self.file_path = ""

 

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
