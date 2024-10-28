from Key import key_expansion
from S_AES import encrypt, decrypt

def meet_in_middle_attack(plain_text, cipher_text):
    key_length = 0xFFFF  # 16位密钥的取值范围

    # 存储中间结果
    intermediate_results = {}

    # 1. 第一轮加密并存储结果
    for k1 in range(key_length + 1):
        # 密钥扩展
        key_A1, key_A2, key_A3 = key_expansion(k1)
        C1 = encrypt(plain_text, key_A1, key_A2, key_A3)  # 使用扩展后的密钥加密
        intermediate_results[C1] = k1  # 以 C1 为键，k1 为值

    # 2. 反向查找第二轮加密
    found_keys = set()
    for k2 in range(key_length + 1):
        # 密钥扩展
        key_B1, key_B2, key_B3 = key_expansion(k2)
        C1 = decrypt(cipher_text, key_B1, key_B2, key_B3)  # 解密得到的中间密文
        if C1 in intermediate_results:
            k1 = intermediate_results[C1]
            found_keys.add((k1, k2))  # 存储找到的密钥对

    return found_keys

def main():
    input_pairs = []  # 存储明文-密文对的列表

    while True:
        user_input = input("请输入明文-密文对（格式为: 明文, 密文）或输入 'end' 结束输入: ")
        if user_input.lower() == "end":
            break
        else:
            try:
                plaintext_hex, ciphertext_hex = user_input.split(',')  # 以逗号分隔输入
                known_plaintext = int(plaintext_hex.strip(), 16)  # 明文转为十六进制整数
                known_ciphertext = int(ciphertext_hex.strip(), 16)  # 密文转为十六进制整数
                input_pairs.append((known_plaintext, known_ciphertext))  # 存储有效的明文-密文对
            except ValueError:
                print("输入格式错误，请使用格式 '明文, 密文'。")

    if not input_pairs:
        print("没有输入任何明文-密文对。")
        return

    # 初始化共同密钥集合
    common_keys = None

    # 处理每个输入的明文-密文对
    for index, (known_plaintext, known_ciphertext) in enumerate(input_pairs):
        print(f"\n已知明文: {hex(known_plaintext)}")
        print(f"已知密文: {hex(known_ciphertext)}")

        # 进行中间相遇攻击
        found_keys = meet_in_middle_attack(known_plaintext, known_ciphertext)

        if index == 0:
            # 第一个明文-密文对的结果
            common_keys = found_keys
        else:
            # 对于后续的明文-密文对，与之前记录的共同密钥集合进行交集
            common_keys = common_keys.intersection(found_keys)

    # 输出共同密钥
    if common_keys:
        print(f"\n找到的共同密钥数量: {len(common_keys)}")
        for k1, k2 in common_keys:
            print(f"K1 = {k1:04x}, K2 = {k2:04x}")  # 使用四位十六进制格式输出
    else:
        print("未找到共同的密钥。")

if __name__ == "__main__":
    main()