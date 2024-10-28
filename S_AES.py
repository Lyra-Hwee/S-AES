from Key import key_expansion, s_box_substitution, inverse_s_box_substitution
def to_byte_matrix(value):
    # 将16位整数转换为2x2半字节矩阵
    return [
        [(value >> 12) & 0x0F, (value >> 4) & 0x0F],
        [(value >> 8) & 0x0F, (value >> 0) & 0x0F]
    ]

def apply_s_box(matrix):
    # 半字节代替
    return [[s_box_substitution(nibble) for nibble in row] for row in matrix]

def inverse_apply_s_box(matrix):
    # 逆半字节代替
    return [[inverse_s_box_substitution(nibble) for nibble in row] for row in matrix]

def shift_row(matrix):
    #行位移
    matrix[1] = matrix[1][1:] + matrix[1][:1]
    return matrix

def inverse_shift_row(matrix):
    # 逆行移位
    matrix[1] = matrix[1][-1:] + matrix[1][:-1]
    return matrix

def gf_multiply(x, y):
    # GF(2^4)加法和乘法 模x^4 + x + 1
    result = 0
    for _ in range(4):
        if y & 1:
            result ^= x
        y >>= 1
        x <<= 1
        if x & 0x10:
            x ^= 0b10011
    return result & 0x0F

def mix_columns(matrix):
    # 列混淆
    result = [
        [
            gf_multiply(1, matrix[0][0]) ^ gf_multiply(4, matrix[1][0]),
            gf_multiply(1, matrix[0][1]) ^ gf_multiply(4, matrix[1][1])
        ],
        [
            gf_multiply(4, matrix[0][0]) ^ gf_multiply(1, matrix[1][0]),
            gf_multiply(4, matrix[0][1]) ^ gf_multiply(1, matrix[1][1])
        ]
    ]
    return result

def inverse_mix_columns(matrix):
    # 逆列混淆
    result = [
        [
            gf_multiply(9, matrix[0][0]) ^ gf_multiply(2, matrix[1][0]),
            gf_multiply(9, matrix[0][1]) ^ gf_multiply(2, matrix[1][1])
        ],
        [
            gf_multiply(2, matrix[0][0]) ^ gf_multiply(9, matrix[1][0]),
            gf_multiply(2, matrix[0][1]) ^ gf_multiply(9, matrix[1][1])
        ]
    ]
    return result

def matrix_to_binary(matrix):
    # 将2x2半字节矩阵转换为16位整数
    return (matrix[0][0] << 12) | (matrix[0][1] << 4) | (matrix[1][0] << 8) | matrix[1][1]

def binary_to_matrix(value):
    # 将16位整数转换为2x2字节矩阵
    return to_byte_matrix(value)

def encrypt(plaintext, key1, key2, key3):
    """加密"""
    # 第0轮
    result = plaintext ^ key1

    # 第1轮
    matrix = to_byte_matrix(result)
    s_box_applied_matrix = apply_s_box(matrix)
    shifted_matrix = shift_row(s_box_applied_matrix)
    mixed_matrix = mix_columns(shifted_matrix)
    binary_value = matrix_to_binary(mixed_matrix)
    xor_result = binary_value ^ key2
    after_key2_matrix = binary_to_matrix(xor_result)

    # 第2轮
    s_box_after_key2 = apply_s_box(after_key2_matrix)
    shifted_after_key2 = shift_row(s_box_after_key2)
    binary_final = matrix_to_binary(shifted_after_key2)
    final_result = binary_final ^ key3

    return final_result

def decrypt(ciphertext, key1, key2, key3):
    """解密"""

    # 第0轮
    result = ciphertext ^ key3

    # 第1轮
    matrix = binary_to_matrix(result)
    shifted_matrix = inverse_shift_row(matrix)
    s_box_applied_matrix = inverse_apply_s_box(shifted_matrix)

    # 第2轮
    binary_value = matrix_to_binary(s_box_applied_matrix)
    xor_result = binary_value ^ key2
    after_key2_matrix = binary_to_matrix(xor_result)
    mixed_matrix = inverse_mix_columns(after_key2_matrix)
    shifted_matrix = inverse_shift_row(mixed_matrix)
    s_box_applied_matrix = inverse_apply_s_box(shifted_matrix)
    binary_value = matrix_to_binary(s_box_applied_matrix)
    final_result = binary_value ^ key1

    return final_result
