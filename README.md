# S-AES
## 测试结果（共五关）
### 第一关：基本测试
基本测试格式如下：

明文：16位二进制数

密文：16位二进制数

密钥：16位二进制数

*** 
**标准加密**

按照实验基本要求的输入格式，输入明文和密钥。

<img width="334" alt="图片1" src="https://github.com/user-attachments/assets/b9ca7f7a-2f1e-43bc-ba20-f95a67d925a0">


测试结果

<img width="331" alt="图片2" src="https://github.com/user-attachments/assets/e1fdc3e4-877a-415d-9bb3-745a52c87777">

***
**标准解密**

按照实验基本要求的输入格式，将加密得到的密文和加密使用的密钥作为输入，看能否解密得到被加密的明文。

<img width="333" alt="图片3" src="https://github.com/user-attachments/assets/4737edfc-4e85-4e18-80dd-a79e81fefd42">

**在基本加解密测试中，加密所用的密钥和明文能够与解密所用密钥与密文对应，说明基本加解密通过测试。**
 |   | 明文 | 密钥 |	密文 |
 | :--- | :---: | ---: | ---: |
 | 16位二进制加密 |	1010101010101010 | 	0101010101010101 |	0110010001101011 | 
 |   | 密文 | 密钥 | 明文 |
 | 16位二进制解密 |  0110010001101011 |	0101010101010101 |	1010101010101010 |

### 第二关：交叉测试
考虑到是"算法标准"，所有人在编写程序的时候需要使用相同算法流程和转换单元(替换盒、列混淆矩阵等)，以保证算法和程序在异构的系统或平台上都可以正常运行。 本项目已经与黎雷组的同学进行了二进制的加密交叉测试，得出结果如下：

黎雷组

<img width="740" alt="图片4" src="https://github.com/user-attachments/assets/28ad89cc-e825-4ed8-903e-976828254671">

我们组

<img width="331" alt="图片5" src="https://github.com/user-attachments/assets/eccea4d8-c290-46e4-9ce9-e90c2b9db278">

**使用相同的密钥和明文能够得出相同的加密结果，加密通过测试。**
*** 
同时，我们小组也与其他组进行了解密测试。

以下为其他小组的测试结果

![图片6](https://github.com/user-attachments/assets/74609d81-1c45-4db2-accc-8085a029b89d)

我们组

<img width="333" alt="图片7" src="https://github.com/user-attachments/assets/8a0187c2-7854-4b93-ac07-4ee36ed9d979">

**使用相同的密钥和密文能够得出相同的解密结果，解密通过测试。**

### 第三关：扩展功能
考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串(很可能是乱码)。

扩展功能测试输入格式如下：

明文：任意ASCII编码字符串

密钥：16bit二进制数

*注意:密钥应该为16bits 加密后极大可能出现乱码*
***
**以下是加密测试**

<img width="373" alt="图片8" src="https://github.com/user-attachments/assets/7579925d-67a4-4231-9512-902cc0965228">

 ***
 
**以下是解密测试**

<img width="369" alt="图片9" src="https://github.com/user-attachments/assets/cdb4902c-a0b5-4459-ba25-677223536a52">

### 第四关：多重加密

#### 1.双重加解密的实现
##### 双重加密
在完成基础的加解密功能之外，还完成了双重加密功能，使用32位的密钥，将密钥分为key1和key2，分别对两个密钥进行密钥扩展，先使用key1加密明文，再使用key2加密密文，得到最终的加密结果 对此我们使用了下面的测试。

测试格式如下：

明文：16位十六进制数

密钥：32位十六进制数

测试结果如下：

<img width="356" alt="图片10" src="https://github.com/user-attachments/assets/bc9ab18c-9961-4770-84aa-6527e51b7f4d">

**这里我们按照双重加密的步骤使用AES分别进行两次加密，如果得到相同结果，则测试成功。**

分别进行两次加密结果如下

<img width="333" alt="图片11" src="https://github.com/user-attachments/assets/32ae378d-76b9-46cf-b3ec-438f6e3967d7">

<img width="331" alt="图片12" src="https://github.com/user-attachments/assets/d4db4310-6d17-4ad1-aab4-10458c4a2640">

**由于进行双重加密和分别进行两次加密得到了相同的密文，因此测试成功。**

<img width="560" alt="图片13" src="https://github.com/user-attachments/assets/6d8072eb-b56c-4b68-b60f-4a356b4c5ea9">


##### 双重解密
按照实验基本要求的输入格式，将加密得到的密文和加密使用的密钥作为输入，看能否解密得到被加密的明文。

测试格式如下：

密文：16位十六进制数

密钥：32位十六进制数

测试结果如下：

<img width="348" alt="图片14" src="https://github.com/user-attachments/assets/0c43c7ca-f9f3-4ef6-a80e-39d5b5b56fa2">

**在双重解密测试中，加密所用的密钥和明文能够与解密所用密钥与密文对应，说明双重解密通过测试。**
 |   | 明文 | 密钥 |	密文 |
 | :--- | :---: | ---: | ---: |
 | 16位十六进制加密 |	0x1243 | 	0x98765432 |	0x20c4 | 
 |   | 密文 | 密钥 | 明文 |
 | 16位十六进制解密 |  0x20c4 |	0x98765432 |	0x1243 |
 
#### 2.中间相遇攻击
我们组使用了同一组密钥对应的三组明密文对来进行中间相遇攻击，每次计算出一组明密文对满足的所有密钥对， 然后将三组得到的所有密钥对进行比较来得到唯一的密钥。

测试方法如下：

将密钥设置为key1=0xacaf，key2=0x3c11，使用该密钥进行双重加密得到2组，3组..明密文对，直到中间相遇攻击能够找到唯一一对共同密钥。

使用设置的密钥进行双重加密的结果：

| 密钥 | 明文 |	密文 |
| :--- | :---: | ---: |
|K1=0xacaf K2=0x3c11 | 0x1234 | 0x4321 |
|K1=0xacaf K2=0x3c11 | 0x1235 | 0xc324 |
|K1=0xacaf K2=0x3c11 | 0x1233 | 0xb32f |

使用中间相遇攻击的测试结果：

<img width="507" alt="图片15" src="https://github.com/user-attachments/assets/db4886a4-7450-4c09-82ee-b8d714622934">

<img width="509" alt="图片16" src="https://github.com/user-attachments/assets/c7499b9d-f5b5-4a53-85e3-6c514d5a9984">



**使用中间相遇攻击能够找到正确的共同密钥，测试成功。**
#### 3.三重加解密的实现
与双重加解密类似：这里我们按照32bits密钥key（k1+k2）的模式进行三重加密，key=key1+key2+key3(key1)，依次使用key1、key2、key3对明文、中间态、第二次加密得到的中间态进行加密，得到密文，解密过程则相反。

对此我们使用了下面的测试来进行验证：
***
##### 三重加密：
测试结果如下

<img width="415" alt="图片17" src="https://github.com/user-attachments/assets/87804b57-73e0-49c2-ad45-f060010bd4ec">

*这里我们按照三重加密的步骤使用AES分别进行三次加密，如果得到相同结果，则测试成功。*

分别进行三次加密结果如下

<img width="329" alt="图片18" src="https://github.com/user-attachments/assets/78ddf781-573c-41b5-99ea-65e4921d5824">

<img width="335" alt="图片19" src="https://github.com/user-attachments/assets/41b5b4b9-5f1f-4d54-9a66-0de64d577cc7">

<img width="332" alt="图片20" src="https://github.com/user-attachments/assets/29f60841-5158-4346-81b6-b8f2f352cb05">


**由于进行三重加密和分别进行三次加密得到了相同的密文，因此测试成功。**

<img width="701" alt="图片21" src="https://github.com/user-attachments/assets/fde17d47-4e9d-44d1-b025-6b06ef00e83c">

*** 

##### 三重解密：
按照实验基本要求的输入格式，将加密得到的密文和加密使用的密钥作为输入，看能否解密得到被加密的明文。

测试结果如下

<img width="389" alt="图片22" src="https://github.com/user-attachments/assets/8b9c4365-dbc2-4fdc-a2c4-b14968176726">

**在三重解密测试中，加密所用的密钥和明文能够与解密所用密钥与密文对应，说明三重解密通过测试。**

### 第五关：工作模式
基于S-AES算法，还可使用密码分组链(CBC)模式对较长的明文消息进行加密。
***
1.选择一个16位的初始向量（IV）。

2.将较长的明文消息分成固定大小的块（16位），然后使用S-AES算法来依次加密每个块。

3.对于第一个块，将它与初始向量进行XOR操作，然后使用S-AES进行加密。加密后的结果成为下一个块的初始向量。

4.对于后续的块，将明文块与前一个加密块进行XOR操作，然后使用S-AES进行加密。这个过程会一直持续，直到整个消息被加密。

5.发送加密后的消息以及最后一个加密块给接收方。

6.接收方知道初始向量，它可以根据相同的步骤解密消息，将每个块解密并将结果与前一个块的密文进行XOR操作。
***
下面是测试案例

<img width="443" alt="图片23" src="https://github.com/user-attachments/assets/0f9241ec-7716-4160-9156-41ac72962219">

<img width="444" alt="图片24" src="https://github.com/user-attachments/assets/84993313-276c-4754-8ed2-d881ebbcea5e">

***
在本次测试中，我们通过将密文的第一个字节异或1完成对密文的篡改，然后进行解密，对比篡改密文前后的解密结果。通过测试案例发现，对密文第一个字节进行篡改后，解密所得16进制明文的前三位受到影响，后五位不变。
因此，我们组推测得以二进制16bits为一个明文块和密文块，如果某一个密文块被篡改，则与其对应的明文块会受到影响，其他明文块则不受影响，不存在连锁反应。

## 开发手册
### 1.AES加解密算法
#### （一）算法简介
AES（Advanced Encryption Standard）是一种广泛使用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年发布，用以取代旧的数据加密标准（DES）。AES加密算法以其高安全性和快速的加解密速度而闻名，在软件和硬件上都能高效运行，且实现相对简单，需要的存储空间较少。
#### （二）加密步骤
AES加密步骤
***
##### 1.初始轮密钥加

将输入的明文与轮密钥进行逐字节异或操作。

##### 2.轮次处理（每轮包含以下步骤，通常进行10轮、12轮或14轮，具体取决于密钥长度）

**半字节替换（apply_s_box）**

使用S-Box对每个半字节进行非线性替换。

**行移位（shift_row）**

将状态矩阵的行进行循环左移，第一行不变，第二行左移1位，第三行左移2位，第四行左移3位。

**列混淆（mix_columns）**

对每一列进行线性变换，增强数据的扩散性。

**轮密钥加**

将当前状态与当前轮密钥进行逐字节异或操作。

##### 3.最后轮（不进行列混合）

进行一次半字节替换（apply_s_box）。

行移位（shift_row）。

进行最后的轮密钥加。
***
为便于理解，我们绘制实现的流程图如下

<img width="241" alt="图片25" src="https://github.com/user-attachments/assets/4256ff67-d73c-49ed-9cb3-3541019ffdf5">


*PS：解密过程与加密过程类似，但使用的是逆操作，包括逆半字节替换、逆行移位、逆列混淆和逆轮密钥加操作。*
#### （三）算法实现（S_AES.py)
***
**将16位整数转换为2x2半字节矩阵**
```python 
def to_byte_matrix(value):
    # 将16位整数转换为2x2半字节矩阵
    return [
        [(value >> 12) & 0x0F, (value >> 4) & 0x0F],
        [(value >> 8) & 0x0F, (value >> 0) & 0x0F]
    ]
```
***
**实现加密算法**
```python 
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
```
***
**实现解密算法**
```python 
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
```
### 2.扩展功能实现
***
#### 2.1ASCII加密(ASCII.py)
**简介：** 考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串(很可能是乱码)。

**主要功能：** 对ASCII字符串进行加解密。

**实现代码（加密算法）：**
```python 
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
```
***
#### 2.2双重加密算法(double.py)
**简介：** 将S-AES算法通过双重加密进行扩展，分组长度仍然是16 bits，但密钥长度为32 bits。

**主要功能：** 使用长度为32bits的密钥对明文进行加密。

**实现代码（加密算法）：**
```python 
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
```
***
#### 2.3三重加密算法(triple.py)
**简介：** 将S-AES算法通过三重加密进行扩展，按照32 bits密钥Key(K1+K2)的模式进行三重加密解密。

**主要功能：** 将32bits的密钥分为k1，k2，按照k1,k2,k1的顺序对明文进行加密。

**实现代码（加密算法）：**
```python 
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

```
***
#### 2.4中间相遇攻击(meet-in-the-middle attack.py)
**简介：** 通过明密文对能找到所有可能的密钥，而通过中间相遇算法，如果给出多对明密文对，能够找到他们的共同密钥。

**主要功能：** 根据明密文对找到所有可能的密钥并能够找到多对明密文对的共同密钥。

**实现代码（加密算法）：**
```python 
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
```
***
#### 2.5 CBC工作模式(CBC.py)
**简介：** 基于S-AES算法，生成初始向量，使用密码分组链(CBC)模式对较长的明文消息进行加密。

AES算法的ECB工作模式与CBC工作模式有以下不同之处
| 特性 |	ECB（电子密码本模式） | 	CBC（密码块链接模式） |
| :--- | :---: | ---: |
| 加密方式 | 	每个明文块独立加密，使用相同的密钥。 |	每个明文块在加密前与前一个密文块进行异或操作。 |
| 初始化向量 |	不需要初始化向量（IV）。 |	需要一个随机的初始化向量（IV）。|
| 并行处理 |	可以并行处理多个明文块。 |	不能并行处理，因为每个块依赖于前一个块的结果。 |
| 相同明文块的处理 |	相同的明文块会产生相同的密文块。 |	相同的明文块会产生不同的密文块（取决于IV和前一个密文块）。 |
| 安全性 |	安全性较低，容易受到模式分析攻击。 |	安全性较高，能有效抵抗模式分析攻击。 | 
| 错误传播 |	仅影响当前块，其他块不受影响。 |	如果一个密文块被篡改，后续的所有块都会受到影响。 |
| 适用场景 |	不推荐用于敏感数据的加密，适合对安全性要求不高的场景。 |	适用于大多数需要加密敏感数据的场景。 |

**功能：** 对较长的明文消息进行加密。

**重要的类和方法：** 

def xor_bytes(a, b):对两个字节进行异或运算

def pad_message(message):为消息填充至16位的倍数

def unpad_message(padded_message):去除填充

def hex_to_bytes(hex_string):将十六进制字符串转换为字节

**实现代码（加密）：**
```python 
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
```
### 3.注意事项
密钥和明文长度：AES 加解密要求密钥和明文为 16 字节（128 位）。

数据格式：确保前端输入数据格式与后端解析格式一致，避免解析错误。

## 用户指南
欢迎使用 S-AES 加密算法工具！本指南将帮助您理解如何使用该工具进行加解密、多重加密、中间相遇攻击、CBC模式等功能。
***
### 1.项目介绍
本项目基于S-AES（简化的数据加密标准）算法，提供简单易用的界面，让用户能够轻松进行消息的加密和解密。用户只需输入待加密的明文和自定义密钥，即可生成安全的密文。通过解密功能，用户可以使用相同的密钥恢复原始消息。

此外，用户能输入明密文对找到所有可能的密钥，以及使用CBC模式对长明文进行加解密，满足了不同的加解密需求。该软件旨在帮助用户理解对称加密的基本原理，同时提高信息安全意识。

<img width="293" alt="图片26" src="https://github.com/user-attachments/assets/660f6989-42e9-4ebb-b9da-764cd3d10133">

### 2.功能介绍
本项目提供了四种加解密方式和中间相遇攻击，四种加密方式分别是单次加密（ASCII和16bits二进制）、双重加密、三重加密以及CBC加密，分别需要16bit、32bit、32bit和16bit密钥，同时CBC加密需要输入初始向量。
#### 2.1单次加密
选择普通二进制加密或ASCII加密。

在明文输入区域输入需要加密的明文（以二进制或 ASCII 格式）。

输入对应位数的密钥，注意每行密钥输入框只能输入16bit密钥，从上到下按序输入。

点击相应的“加密”按钮。

系统将返回加密后的密文，显示在反馈区域。


#### 2.2单次解密
选择普通二进制解密或ASCII解密。

在密文输入区域输入需要加密的明文（以二进制或 ASCII 格式）。

输入对应位数的密钥，注意每行密钥输入框只能输入16bit密钥，从上到下按序输入。

点击相应的“解密”按钮。

系统将返回加密后的密文，显示在反馈区域。

#### 2.3中间相遇攻击
输入明密文对，格式为明文，密文；明文，密文。

点击执行攻击。

系统将返回攻击后的结果，包括各自找到的密钥数量，找到共同密钥的数量以及找到的共同密钥，显示在反馈区域。

#### 2.4 工作模式输入16进制密钥
自定义16进制初始向量。

输入需要加密的明文。

点击执行加密和解密按钮。

系统将返回加密所得密文，对密文进行修改后的结果，以及对修改后密文进行解密所得明文。

### 3.注意事项

标准输入下：明文和密钥必须分别为16位和16位二进制数，不得包含除0和1以外的字符。

中间相遇攻击和工作模式下，输入的明密文以及密钥必须为16进制数。

在拓展输入情况下，输入的密文或明文会被视为字符，转化为ASCII码进行处理。但密钥必须仍然是严格的16位二进制数。

### 4.反馈与支持
如果您遇到任何问题或需要帮助，请随时联系我们。感谢您使用SDES算法加解密工具！

祝您使用愉快！
















