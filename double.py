from Key import key_expansion
from S_AES import encrypt, decrypt


def double_encrypt(plaintext, key_32bit):
    # 将32位密钥分成两个16位密钥
    key_A = (key_32bit & 0xFFFF0000) >> 16
    key_B = key_32bit & 0x0000FFFF

    # 对第一个16位密钥进行密钥扩展
    key_A1, key_A2, key_A3 = key_expansion(key_A)
    # 使用key_A进行第一次加密
    intermediate_ciphertext = encrypt(plaintext, key_A1, key_A2, key_A3)

    # 对第二个16位密钥进行密钥扩展
    key_B1, key_B2, key_B3 = key_expansion(key_B)
    # 使用key_B进行第二次加密
    final_ciphertext = encrypt(intermediate_ciphertext, key_B1, key_B2, key_B3)

    return final_ciphertext


def double_decrypt(final_ciphertext, key_32bit):
    # 将32位密钥分成两个16位密钥
    key_A = (key_32bit & 0xFFFF0000) >> 16
    key_B = key_32bit & 0x0000FFFF

    # 对第二个16位密钥进行密钥扩展
    key_B1, key_B2, key_B3 = key_expansion(key_B)
    # 使用key_B进行解密
    intermediate_ciphertext = decrypt(final_ciphertext, key_B1, key_B2, key_B3)

    # 对第一个16位密钥进行密钥扩展
    key_A1, key_A2, key_A3 = key_expansion(key_A)
    # 使用key_A进行解密
    original_plaintext = decrypt(intermediate_ciphertext, key_A1, key_A2, key_A3)

    return original_plaintext


# 用户接口，选择加密或解密
if __name__ == "__main__":
    operation = input("双重加密————请选择操作（1：加密，2：解密）：").strip().lower()

    if operation not in ['1', '2']:
        print("无效的操作，请输入 '1' 或 '2'。")
    else:
        hex_input = input("请输入16位十六进制明文 (例如:1233')")
        plaintext = int(hex_input, 16)

        key_input = input("请输入32位十六进制密钥 (例如:12345678')")
        key_32bit = int(key_input, 16)

        if operation == '1':
            # 执行加密操作
            ciphertext = double_encrypt(plaintext, key_32bit)
            print("密文:", hex(ciphertext))
        elif operation == '2':
            # 执行解密操作
            decrypted_plaintext = double_decrypt(plaintext, key_32bit)
            print("解密后的明文:", hex(decrypted_plaintext))