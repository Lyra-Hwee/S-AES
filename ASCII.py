from Key import key_expansion
from S_AES import encrypt, decrypt

def encrypt_text(plaintext, key1, key2, key3):
    """使用提供的密钥和区块密码加密文本字符串，并以ASCII字符输出。"""
    encrypted_text = ""
    for char in plaintext:
        # 将ASCII字符转换为16位整数
        char_value = ord(char)
        # 对字符进行加密
        encrypted_value = encrypt(char_value, key1, key2, key3)
        # 将16位加密值拆分为两个8位部分
        high_byte = (encrypted_value & 0xFF00) >> 8
        low_byte = encrypted_value & 0x00FF
        # 以字符形式附加
        encrypted_text += chr(high_byte) + chr(low_byte)
    return encrypted_text

def decrypt_text(encrypted_text, key1, key2, key3):
    """使用提供的密钥和区块密码将加密字符串解密回原始明文。"""
    decrypted_text = ''
    # 每两个字符处理为一个块（表示一个加密的16位块）
    for i in range(0, len(encrypted_text), 2):
        # 将两个8位部分组合为一个16位加密值
        high_byte = ord(encrypted_text[i])
        low_byte = ord(encrypted_text[i + 1])
        encrypted_value = (high_byte << 8) | low_byte
        # 解密字符
        decrypted_value = decrypt(encrypted_value, key1, key2, key3)
        # 将解密后的16位整数转换回ASCII字符
        decrypted_text += chr(decrypted_value)
    return decrypted_text

def main():
    key1, key2, key3 = key_expansion(0x3A94)  # 示例密钥扩展
    while True:
        choice = input("请选择操作 (encrypt/decrypt/exit): ").strip().lower()

        if choice == 'encrypt':
            plaintext = input("请输入要加密的明文: ")
            encrypted = encrypt_text(plaintext, key1, key2, key3)
            print("加密后的ASCII字符: ", end='')
            print(encrypted)

        elif choice == 'decrypt':
            encrypted_text = input("请输入要解密的密文: ")
            if len(encrypted_text) % 2 != 0:
                print("输入的密文长度必须为偶数（每个字符由两个字符表示）!", end='')
                continue
            decrypted = decrypt_text(encrypted_text, key1, key2, key3)
            print("解密后的文本: ", end='')
            print(decrypted)

        elif choice == 'exit':
            print("退出程序。", end='')
            break

        else:
            print("无效选择，请输入 'encrypt', 'decrypt' 或 'exit'。", end='')

if __name__ == '__main__':
    main()