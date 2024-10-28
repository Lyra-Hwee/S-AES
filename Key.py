def s_box_substitution(nibble):
    # S-盒定义
    s_box = [
        [0x9, 0x4, 0xA, 0xB],
        [0xD, 0x1, 0x8, 0x5],
        [0x6, 0x2, 0x0, 0x3],
        [0xC, 0xE, 0xF, 0x7]
    ]

    # 从nibble中提取行和列
    row = (nibble & 0b1100) >> 2
    col = nibble & 0b0011

    return s_box[row][col]


def inverse_s_box_substitution(nibble):
    # 逆S-盒定义
    s_box = [
        [0xA, 0x5, 0x9, 0xB],
        [0x1, 0x7, 0x8, 0xF],
        [0x6, 0x0, 0x2, 0x3],
        [0xC, 0x4, 0xD, 0xE]
    ]

    # 从nibble中提取行和列
    row = (nibble & 0b1100) >> 2
    col = nibble & 0b0011

    return s_box[row][col]


def g_function(word, round_constant):
    """g函数"""
    # 分为两部分并进行交换
    right_nibble = (word & 0xF0) >> 4
    left_nibble = word & 0x0F

    # 使用 S-盒进行替换
    left_nibble = s_box_substitution(left_nibble)
    right_nibble = s_box_substitution(right_nibble)

    # 合并
    combined = ((left_nibble << 4) | right_nibble)

    # 与轮常量进行异或运算
    return combined ^ round_constant


def key_expansion(key):
    # 将16位密钥分成两个8位的字
    w0 = (key & 0xFF00) >> 8
    w1 = key & 0x00FF

    # 定义第一轮和第二轮的常量
    rcon1 = 0x80
    rcon2 = 0x30

    # 扩展密钥
    w2 = w0 ^ g_function(w1, rcon1)
    w3 = w2 ^ w1
    w4 = w2 ^ g_function(w3, rcon2)
    w5 = w4 ^ w3

    # w[0,1]、w[2,3]、w[4,5]
    key1 = (w0 << 8) | w1
    key2 = (w2 << 8) | w3
    key3 = (w4 << 8) | w5

    # 得到三个密钥
    return key1, key2, key3
def to_byte_matrix(value):
    # 将16位整数转换为2x2半字节矩阵
    return [
        [(value >> 12) & 0x0F, (value >> 8) & 0x0F],
        [(value >> 4) & 0x0F, (value >> 0) & 0x0F]
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
    return (matrix[0][0] << 12) | (matrix[0][1] << 8) | (matrix[1][0] << 4) | matrix[1][1]

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



