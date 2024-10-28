from Key import key_expansion  
from S_AES import encrypt, decrypt  

def triple_encrypt(plaintext, key_32bit):  
    key_K1 = (key_32bit & 0xFFFF0000) >> 16  
    key_K2 = (key_32bit & 0x0000FFFF)  
    key_K3 = key_K1  

    key_K1_expanded = key_expansion(key_K1)  
    key_K2_expanded = key_expansion(key_K2)  
    key_K3_expanded = key_expansion(key_K3)  

    intermediate_ciphertext = encrypt(plaintext, *key_K1_expanded)  
    intermediate_ciphertext = encrypt(intermediate_ciphertext, *key_K2_expanded)  
    final_ciphertext = encrypt(intermediate_ciphertext, *key_K3_expanded)  

    return final_ciphertext  

def triple_decrypt(final_ciphertext, key_32bit):  
    key_K1 = (key_32bit & 0xFFFF0000) >> 16  
    key_K2 = (key_32bit & 0x0000FFFF)  
    key_K3 = key_K1  

    key_K3_expanded = key_expansion(key_K3)  
    key_K2_expanded = key_expansion(key_K2)  
    key_K1_expanded = key_expansion(key_K1)  

    intermediate_ciphertext = decrypt(final_ciphertext, *key_K3_expanded)  
    intermediate_ciphertext = decrypt(intermediate_ciphertext, *key_K2_expanded)  
    original_plaintext = decrypt(intermediate_ciphertext, *key_K1_expanded)  

    return original_plaintext  

if __name__ == "__main__":  
    choice = input("三重加密————请选择操作（1：加密，2：解密）：")

    if choice == '1':  
        plaintext = int(input("请输入16位明文（十六进制，例如:1234）："), 16)
        key_32bit = int(input("请输入32位密钥（十六进制，例如:12345678）："), 16)

        ciphertext = triple_encrypt(plaintext, key_32bit)  
        print("加密后的密文:", hex(ciphertext))  

    elif choice == '2':  
        ciphertext = int(input("请输入密文（十六进制，例如:1234）："), 16)
        key_32bit = int(input("请输入32位密钥（十六进制，例如:12345678）："), 16)

        decrypted_plaintext = triple_decrypt(ciphertext, key_32bit)  
        print("解密后的明文:", hex(decrypted_plaintext))  

    else:  
        print("无效的选择，请输入 1 或 2。")