import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
from S_AES import encrypt, decrypt
from Key import key_expansion

class SAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES")
        self.root.geometry("450x470")
        self.root.configure(bg="#f2f2f2")

        # 添加并调整背景图像
        self.bg_image = ImageTk.PhotoImage(Image.open("bg_image.jpg").resize((450, 470), Image.LANCZOS))
        background_label = tk.Label(root, image=self.bg_image)
        background_label.place(relwidth=1, relheight=1)

        # 添加标题标签
        title_label = tk.Label(root, text="S-AES", font=("Helvetica Neue", 28, "bold"), bg="#f2f2f2", fg="#303F9F")
        title_label.pack(pady=(10, 5))

        # 创建选项卡Notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=1, fill="both", padx=20, pady=20)

        # 加密选项卡
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="加密")
        self.setup_encrypt_tab()

        # 解密选项卡
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="解密")
        self.setup_decrypt_tab()

    # 加密
    def setup_encrypt_tab(self):
        ttk.Label(self.encrypt_frame, text="输入16位密钥:", font=("Helvetica Neue", 14, "bold")).pack(pady=(15, 5))
        self.key_entry = ttk.Entry(self.encrypt_frame, width=40, font=("Helvetica Neue", 14), justify='center')
        self.key_entry.pack(pady=10)

        ttk.Label(self.encrypt_frame, text="输入16位明文:", font=("Helvetica Neue", 14, "bold")).pack(pady=(10, 5))
        self.plaintext_entry = ttk.Entry(self.encrypt_frame, width=40, font=("Helvetica Neue", 14), justify='center')
        self.plaintext_entry.pack(pady=10)

        button_frame = tk.Frame(self.encrypt_frame, bg="#f2f2f2")
        button_frame.pack(pady=20)

        encrypt_button = tk.Button(button_frame, text="🔒 加密", command=self.encrypt_action,
                                   font=("Helvetica Neue", 14, "bold"), bg="#4CAF50", fg="white",
                                   relief="raised", width=10, bd=0, highlightthickness=0)
        encrypt_button.pack(side=tk.LEFT, padx=(20, 5), pady=10)

        clear_button = tk.Button(button_frame, text="🔄", command=self.clear_encrypt_fields,
                                 font=("Helvetica Neue", 14, "bold"), bg="#e0e0e0", fg="black",
                                 relief="raised", width=3, bd=0, highlightthickness=0)
        clear_button.pack(side=tk.LEFT)

        self.result_label_encrypt = ttk.Label(self.encrypt_frame, text="", foreground="red",
                                              font=("Helvetica Neue", 14))
        self.result_label_encrypt.pack(pady=(10, 20))

    # 解密
    def setup_decrypt_tab(self):
        ttk.Label(self.decrypt_frame, text="输入16位密钥:", font=("Helvetica Neue", 14, "bold")).pack(pady=(15, 5))
        self.key_decrypt_entry = ttk.Entry(self.decrypt_frame, width=40, font=("Helvetica Neue", 14), justify='center')
        self.key_decrypt_entry.pack(pady=10)

        ttk.Label(self.decrypt_frame, text="输入16位密文:", font=("Helvetica Neue", 14, "bold")).pack(pady=(10, 5))
        self.ciphertext_entry = ttk.Entry(self.decrypt_frame, width=40, font=("Helvetica Neue", 14), justify='center')
        self.ciphertext_entry.pack(pady=10)

        button_frame = tk.Frame(self.decrypt_frame, bg="#f2f2f2")
        button_frame.pack(pady=20)

        decrypt_button = tk.Button(button_frame, text="🔓 解密", command=self.decrypt_action,
                                   font=("Helvetica Neue", 14, "bold"), bg="#f44336", fg="white",
                                   relief="raised", width=10, bd=0, highlightthickness=0)
        decrypt_button.pack(side=tk.LEFT, padx=(20, 5), pady=10)

        clear_button = tk.Button(button_frame, text="🔄", command=self.clear_decrypt_fields,
                                 font=("Helvetica Neue", 14, "bold"), bg="#e0e0e0", fg="black",
                                 relief="raised", width=3, bd=0, highlightthickness=0)
        clear_button.pack(side=tk.LEFT)

        self.result_label_decrypt = ttk.Label(self.decrypt_frame, text="", foreground="red",
                                              font=("Helvetica Neue", 14))
        self.result_label_decrypt.pack(pady=(10, 20))

    # 加密结果
    def encrypt_action(self):
        key_input = self.key_entry.get()
        plaintext_input = self.plaintext_entry.get()

        if self.is_valid_input(key_input, 16) and self.is_valid_input(plaintext_input, 16):
            key_value = int(key_input, 2)
            plaintext_value = int(plaintext_input, 2)
            key1, key2, key3 = key_expansion(key_value)
            encrypted_text = encrypt(plaintext_value, key1, key2, key3)
            self.result_label_encrypt.config(text=f"加密结果: {bin(encrypted_text)[2:].zfill(16)}")
        else:
            self.key_entry.delete(0, tk.END)
            self.plaintext_entry.delete(0, tk.END)
            messagebox.showerror("错误", "无效输入，请确保密钥和明文均为16位二进制数。")

    # 解密结果
    def decrypt_action(self):
        key_input = self.key_decrypt_entry.get()
        ciphertext_input = self.ciphertext_entry.get()

        if self.is_valid_input(key_input, 16) and self.is_valid_input(ciphertext_input, 16):
            key_value = int(key_input, 2)
            ciphertext_value = int(ciphertext_input, 2)
            key1, key2, key3 = key_expansion(key_value)
            decrypted_text = decrypt(ciphertext_value, key1, key2, key3)
            self.result_label_decrypt.config(text=f"解密结果: {bin(decrypted_text)[2:].zfill(16)}")
        else:
            self.key_decrypt_entry.delete(0, tk.END)
            self.ciphertext_entry.delete(0, tk.END)
            messagebox.showerror("错误", "无效输入，请确保密钥和密文均为16位二进制数。")

    def is_valid_input(self, input_text, length):
        return len(input_text) == length and all(bit in '01' for bit in input_text)

    # 加密清空键
    def clear_encrypt_fields(self):
        self.key_entry.delete(0, tk.END)
        self.plaintext_entry.delete(0, tk.END)
        self.result_label_encrypt.config(text="")

    # 解密清空键
    def clear_decrypt_fields(self):
        self.key_decrypt_entry.delete(0, tk.END)
        self.ciphertext_entry.delete(0, tk.END)
        self.result_label_decrypt.config(text="")


if __name__ == "__main__":
    root = tk.Tk()
    app = SAESApp(root)
    root.mainloop()