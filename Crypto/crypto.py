import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64

class CryptoApp:
    def __init__(self, root):
        # Initialize Tkinter window
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
        self.algorithm_combobox["values"] = ["XOR Cipher", "Caesar Cipher", "Block Cipher"]  # Add Caesar and Block Cipher
        self.algorithm_combobox.pack(pady=10)
        self.algorithm_combobox.bind("<<ComboboxSelected>>", self.update_input_area)

        # Input Frame
        self.input_frame = ttk.Frame(self.crypto_frame)
        self.input_frame.pack()

        # Input Label
        ttk.Label(self.input_frame, text="Input:").pack()

        # Input Text Widget
        self.input_text = tk.Text(self.input_frame, height=10, width=50, state="normal")
        self.input_text.pack(pady=10)

        # Key Label
        ttk.Label(self.input_frame, text="Key:").pack()

        # Key Entry
        self.key_entry = ttk.Entry(self.input_frame)
        self.key_entry.pack(pady=5)

        # Output Text Widget
        ttk.Label(self.crypto_frame, text="Output:").pack()
        self.output_text = tk.Text(self.crypto_frame, height=10, width=50)
        self.output_text.pack(pady=10)

        # Buttons
        ttk.Button(self.crypto_frame, text="Encrypt", command=self.encrypt).pack(pady=5)
        ttk.Button(self.crypto_frame, text="Decrypt", command=self.decrypt).pack(pady=5)

    def encrypt(self):
        algorithm = self.algorithm_var.get()
        if algorithm == "XOR Cipher":
            plaintext = self.input_text.get("1.0", tk.END).encode()
            key = self.key_entry.get().encode()
            encrypted_text = xor_encrypt(plaintext, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Ciphertext (XOR): {encrypted_text.decode()}")

        elif algorithm == "Caesar Cipher":
            plaintext = self.input_text.get("1.0", tk.END)
            shift_key = int(self.key_entry.get())
            encrypted_text = caesar_cipher(plaintext, shift_key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Ciphertext (Caesar): {encrypted_text}")

        elif algorithm == "Block Cipher":
            plaintext = self.input_text.get("1.0", tk.END).encode()
            key = self.key_entry.get().encode()
            block_size = 16  # Adjust as needed
            encrypted_text = block_cipher(plaintext, key, block_size)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Ciphertext (Block): {encrypted_text.decode()}")

    def decrypt(self):
        algorithm = self.algorithm_var.get()
        if algorithm == "XOR Cipher":
            ciphertext = self.input_text.get("1.0", tk.END).encode()
            key = self.key_entry.get().encode()
            decrypted_text = xor_decrypt(ciphertext, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Decrypted (XOR): {decrypted_text.decode()}")

        elif algorithm == "Caesar Cipher":
            ciphertext = self.input_text.get("1.0", tk.END)
            shift_key = int(self.key_entry.get())
            decrypted_text = caesar_cipher(ciphertext, -shift_key)  # Decrypt using negative shift
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Decrypted (Caesar): {decrypted_text}")

        elif algorithm == "Block Cipher":
            ciphertext = self.input_text.get("1.0", tk.END).encode()
            key = self.key_entry.get().encode()
            block_size = 16  # Adjust as needed
            decrypted_text = block_cipher_decrypt(ciphertext, key, block_size)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"Decrypted (Block): {decrypted_text.decode()}")

    def show_crypto_interface(self):
        self.welcome_frame.pack_forget()
        self.crypto_frame.pack(pady=20)

    def update_input_area(self, event=None):
        algorithm = self.algorithm_var.get()
        if algorithm == "XOR Cipher":
            self.input_text.config(state="normal")
            self.key_entry.config(state="normal")
        elif algorithm == "Caesar Cipher":
            self.input_text.config(state="normal")
            self.key_entry.config(state="normal")
        elif algorithm == "Block Cipher":
            self.input_text.config(state="normal")
            self.key_entry.config(state="normal")

# XOR Cipher Functions
def xor_encrypt(plaintext, key):
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        input_text_byte = plaintext[i]
        key_byte = key[i % len(key)]
        encrypted_byte = input_text_byte ^ key_byte
        ciphertext.append(encrypted_byte)
    return base64.b64encode(ciphertext)

def xor_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    decrypted_text = bytearray()
    for i in range(len(ciphertext)):
        encrypted_byte = ciphertext[i]
        key_byte = key[i % len(key)]
        decrypted_byte = encrypted_byte ^ key_byte
        decrypted_text.append(decrypted_byte)
    return decrypted_text.decode()

# Caesar Cipher Functions
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
            result += chr(shifted)
        else:
            result += char
    return result

# Block Cipher Functions
def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    assert padding_length > 0
    message, padding = data[:-padding_length], data[-padding_length:]
    assert all(p == padding_length for p in padding)
    return message

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)

def block_cipher(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)
    for i in range(0, len(padded_plaintext), block_size):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
    return encrypted_data

def block_cipher_decrypt(ciphertext, key, block_size):
    decrypted_data = b''
    for i in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
