import os
from S_AES import encrypt, decrypt, key_expansion

def xor_bytes(a, b):
    """对两个字节进行异或运算"""
    return bytes(x ^ y for x, y in zip(a, b))


def pad_message(message):
    """为消息填充至16位的倍数"""
    padding_length = 2 - (len(message) % 2) if len(message) % 2 != 0 else 0
    return message + bytes([padding_length] * padding_length)


def unpad_message(padded_message):
    """去除填充"""
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]


def encrypt_cbc(plaintext, key1, key2, key3, iv):
    """CBC模式加密"""
    plaintext = pad_message(plaintext)
    ciphertext = bytearray()

    # 将明文按2字节切割
    for i in range(0, len(plaintext), 2):
        block = plaintext[i:i + 2]

        # IV或前一个密文块与当前块异或
        if i == 0:
            xor_block = iv
        else:
            xor_block = ciphertext[-2:]

        # 执行异或操作
        xor_result = xor_bytes(xor_block, block)

        # 执行S-AES加密
        encrypted_block = encrypt(int.from_bytes(xor_result, 'big'), key1, key2, key3)

        # 将加密的块添加到密文中
        ciphertext.extend(encrypted_block.to_bytes(2, 'big'))

    return bytes(ciphertext)


def decrypt_cbc(ciphertext, key1, key2, key3, iv):
    """CBC模式解密"""
    plaintext = bytearray()

    # 将密文按2字节切割
    for i in range(0, len(ciphertext), 2):
        block = ciphertext[i:i + 2]

        # 执行S-AES解密
        decrypted_block = decrypt(int.from_bytes(block, 'big'), key1, key2, key3)

        # 如果是第一个块，直接使用IV
        if i == 0:
            xor_result = xor_bytes(iv, decrypted_block.to_bytes(2, 'big'))
        else:
            xor_result = xor_bytes(ciphertext[i - 2:i], decrypted_block.to_bytes(2, 'big'))

        # 将解密后的结果添加到明文
        plaintext.extend(xor_result)

    return unpad_message(bytes(plaintext))


def hex_to_bytes(hex_string):
    """将十六进制字符串转换为字节"""
    return bytes.fromhex(hex_string)


if __name__ == "__main__":
    key = 0x1B2A  # 16位密钥示例
    key1, key2, key3 = key_expansion(key)

    # 用户输入IV（应为2个十六进制字符）
    iv_input = input("请输入16进制格式的初始向量（IV），例如 '1A2B': ")
    iv = hex_to_bytes(iv_input)  # 将输入转换为字节

    if len(iv) != 2:
        print("初始向量必须为2个字节（4个十六进制字符）")
        exit(1)

    print(f"IV: {iv.hex()}")

    message = b"Hello,S-AES"  # 明文消息
    encrypted_message = encrypt_cbc(message, key1, key2, key3, iv)
    print(f"Encrypted: {encrypted_message.hex()}")

    # 篡改密文 (例如，改变第一个密文块的一个字节)
    altered_ciphertext = bytearray(encrypted_message)
    altered_ciphertext[0] ^= 0x01  # 将第一个字节异或1进行篡改
    print(f"Altered Ciphertext: {altered_ciphertext.hex()}")

    # 解密篡改后的密文
    decrypted_after_alteration = decrypt_cbc(bytes(altered_ciphertext), key1, key2, key3, iv)
    print(f"Decrypted (after alteration): {decrypted_after_alteration.decode('utf-8', errors='ignore')}")
