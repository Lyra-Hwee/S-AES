import tkinter as tk
from tkinter import messagebox, scrolledtext
from Key import key_expansion
from S_AES import encrypt, decrypt


class AttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("中间相遇攻击")
        self.root.geometry("600x400")
        self.root.config(bg="#f0f0f0")

        self.create_widgets()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(main_frame, text="请输入明文-密文对（格式为: 明文, 密文; 明文, 密文）:",
                 font=("Arial", 12), bg="#f0f0f0").pack(pady=10)

        self.user_input = tk.StringVar()
        user_input_entry = tk.Entry(main_frame, textvariable=self.user_input,
                                    width=70, font=("Arial", 12))
        user_input_entry.pack(pady=5)
        user_input_entry.config(borderwidth=2, relief="groove")

        execute_button = tk.Button(main_frame, text="执行攻击",
                                   command=self.perform_attack,
                                   font=("Arial", 12),
                                   bg="#4285f4", fg="white")
        execute_button.pack(pady=20)

        self.result_text = scrolledtext.ScrolledText(main_frame,
                                                     wrap=tk.WORD,
                                                     width=70,
                                                     height=15,
                                                     font=("Arial", 12),
                                                     bg="#ffffff",
                                                     relief="flat")
        self.result_text.pack(pady=10)

        tooltip = tk.Label(main_frame, text="示例: 0x0123, 0x4567; 0x89AB, 0xCDEF",
                           bg="#f0f0f0",
                           fg="#FF5733",
                           font=("Arial", 10))
        tooltip.pack(pady=5)

    def meet_in_middle_attack(self, plain_text, cipher_text):
        key_length = 0xFFFF
        intermediate_results = {}

        # 1. 第一轮加密并存储结果
        for k1 in range(key_length + 1):
            # 密钥扩展
            key_A1, key_A2, key_A3 = key_expansion(k1)
            C1 = encrypt(plain_text, key_A1, key_A2, key_A3)
            intermediate_results[C1] = k1

            # 2. 反向查找第二轮加密
        found_keys = set()
        for k2 in range(key_length + 1):
            key_B1, key_B2, key_B3 = key_expansion(k2)
            C1 = decrypt(cipher_text, key_B1, key_B2, key_B3)
            if C1 in intermediate_results:
                k1 = intermediate_results[C1]
                found_keys.add((k1, k2))

        return found_keys

    def perform_attack(self):
        input_pairs = self.user_input.get().strip().split(';')

        if not input_pairs:
            messagebox.showerror("输入错误", "没有输入任何明文-密文对。")
            return

        common_keys = None
        results = []

        for pair in input_pairs:
            try:
                plaintext_hex, ciphertext_hex = map(str.strip, pair.split(','))
                known_plaintext = int(plaintext_hex, 16)
                known_ciphertext = int(ciphertext_hex, 16)

                found_keys = self.meet_in_middle_attack(known_plaintext, known_ciphertext)

                if common_keys is None:
                    common_keys = found_keys
                else:
                    common_keys = common_keys.intersection(found_keys)

                result_str = f"已知明密文对: {plaintext_hex}\n已知密文: {ciphertext_hex}\n找到的密钥数量: {len(found_keys)}\n"
                results.append(result_str)

            except ValueError:
                messagebox.showerror("输入错误", f"输入格式错误: {pair}，请使用 '明文, 密文' 格式。")
                return

                # 输出共同密钥
        if common_keys:
            total_keys = len(common_keys)
            result_str = f"\n找到的共同密钥总数量: {total_keys}\n"

            first_ten_keys = list(common_keys)[:10]
            for k1, k2 in first_ten_keys:
                result_str += f"K1 = {k1:04x}, K2 = {k2:04x}\n"
            results.append(result_str)
        else:
            results.append("未找到共同的密钥。")

            # 显示结果
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "\n".join(results))


if __name__ == "__main__":
    root = tk.Tk()
    app = AttackGUI(root)
    root.mainloop()