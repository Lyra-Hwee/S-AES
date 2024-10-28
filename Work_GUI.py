import tkinter as tk
from tkinter import messagebox
from S_AES import encrypt, decrypt, key_expansion

class WorkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES CBC")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        self.create_widgets()

    def create_widgets(self):
        input_frame = tk.Frame(self.root, padx=20, pady=20)
        input_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(input_frame, text="请输入密钥（十六进制）:", font=("Arial", 12)).grid(row=0, column=0, sticky=tk.W)
        self.entry_key = tk.Entry(input_frame, font=("Arial", 12))
        self.entry_key.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(input_frame, text="请输入初始向量（IV，十六进制）:", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W)
        self.entry_iv = tk.Entry(input_frame, font=("Arial", 12))
        self.entry_iv.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(input_frame, text="请输入要加密的明文:", font=("Arial", 12)).grid(row=2, column=0, sticky=tk.W)
        self.entry_message = tk.Entry(input_frame, font=("Arial", 12))
        self.entry_message.grid(row=2, column=1, padx=10, pady=10)

        self.result_text = tk.StringVar()
        result_label = tk.Label(self.root, textvariable=self.result_text, font=("Arial", 12), wraplength=500, justify=tk.LEFT)
        result_label.pack(padx=20, pady=20)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        btn_encrypt = tk.Button(btn_frame, text="执行加密和解密", command=self.perform_encryption, bg="lightblue", fg="white", font=("Arial", 12), padx=10, pady=5)
        btn_encrypt.pack()

    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def hex_to_bytes(self, hex_string):
        return bytes.fromhex(hex_string)

    def pad_message(self, message):
        block_size = 2
        padding_length = (block_size - (len(message) % block_size)) % block_size
        return message + bytes([padding_length] * padding_length) if padding_length else message

    def unpad_message(self, padded_message):
        if not padded_message:
            return padded_message
        padding_length = padded_message[-1]
        return padded_message[:-padding_length] if padding_length < 3 else padded_message

    def encrypt_cbc(self, plaintext, key1, key2, key3, iv):
        plaintext = self.pad_message(plaintext)
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 2):
            block = plaintext[i:i + 2]
            xor_block = iv if i == 0 else ciphertext[-2:]
            xor_result = self.xor_bytes(xor_block, block)
            encrypted_block = encrypt(int.from_bytes(xor_result, 'big'), key1, key2, key3)
            ciphertext.extend(encrypted_block.to_bytes(2, 'big'))

        return bytes(ciphertext)

    def decrypt_cbc(self, ciphertext, key1, key2, key3, iv):
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 2):
            block = ciphertext[i:i + 2]
            decrypted_block = decrypt(int.from_bytes(block, 'big'), key1, key2, key3)
            xor_result = self.xor_bytes(iv if i == 0 else ciphertext[i - 2:i], decrypted_block.to_bytes(2, 'big'))
            plaintext.extend(xor_result)

        return self.unpad_message(bytes(plaintext))

    def perform_encryption(self):
        try:
            key = int(self.entry_key.get(), 16)
            iv = self.hex_to_bytes(self.entry_iv.get())

            if len(iv) != 2:
                messagebox.showerror("错误", "初始向量必须为2个字节（4个十六进制字符）")
                return

            message = self.entry_message.get().encode('utf-8')
            key1, key2, key3 = key_expansion(key)

            # 加密
            encrypted_message = self.encrypt_cbc(message, key1, key2, key3, iv)
            encrypted_hex = encrypted_message.hex()

            # 篡改密文
            altered_ciphertext = bytearray(encrypted_message)
            altered_ciphertext[0] ^= 0x01  # 将第一个字节异或1进行篡改
            altered_hex = altered_ciphertext.hex()

            # 解密篡改后的密文
            decrypted_after_alteration = self.decrypt_cbc(bytes(altered_ciphertext), key1, key2, key3, iv)
            decrypted_message = decrypted_after_alteration.decode('utf-8', errors='ignore')

            self.result_text.set(
                f"密文: {encrypted_hex}\n修改后的密文: {altered_hex}\n对修改后密文解密所得明文: {decrypted_message}"
            )
        except ValueError:
            messagebox.showerror("错误", "请确保密钥是有效的十六进制数")


if __name__ == "__main__":
    root = tk.Tk()
    app = WorkApp(root)
    root.mainloop()