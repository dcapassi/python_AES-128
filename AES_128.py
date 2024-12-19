from aes_lookup import InvSbox, Sbox, Rcon

def string_to_hex_utf_8_list(input):
    output = []
    for char in input:
        encoded_char = char.encode('utf-8').hex()
        for i in range(0, len(encoded_char), 2):
            output.append(f"0x{encoded_char[i:i+2].lower()}")
    return output
    
def vector_to_matrix(vector,cols):
    output = []
    row_lenght = int(len(vector)/cols)
    init = 0
    finish = init + row_lenght
    for _ in range(cols):
        output.append(vector[init:finish])
        init += int(row_lenght)
        finish += row_lenght
    return output

def transpose_matrix(matrix):
    matrix_T = []
    new_line = []
    for row in range(len(matrix)):
        for col in range(len(matrix)):
            new_line.append(matrix[col][row])
        matrix_T.append(new_line)
        new_line = []
    return matrix_T


def get_matrix_column(matrix,col):
    vector = []
    for row in matrix:
        vector.append(row[col])
    return vector


def subword(word,type='encrypt'):
    if type == 'encrypt':
        return hex(Sbox[word])
    if type == 'decrypt':
        return hex(InvSbox[word])

def vector_subword(vector, type='encrypt'):
    return [subword(int(word,16),type) for word in vector]

def matrix_subword(matrix, type='encrypt'):
    return [vector_subword(vector, type) for vector in matrix]

def vector_xor_round(vector,round):
    first = True
    output = []
    for byte in vector:
        if (first == True):
            byteB = hex(Rcon[round])
        else:
            byteB = '0x00'
        output.append(xor(byte,byteB))
        first = False
    return output

def vectors_xor(vectorA, vectorB):
    output = []
    for i in range(len(vectorA)):
        output.append(xor(vectorA[i],vectorB[i]))
    return output

def shift_word(word, shift_count, direction = 'left'): 
    if (direction == 'left'):
        return (word[shift_count:]+word[:shift_count])
    if (direction == 'right'):
        return (word[-shift_count:]+word[:-shift_count])


def xor(byteA,byteB):
    byteA_as_int = int(byteA,16)
    byteB_as_int = int(byteB,16)
    xor_int = byteA_as_int ^ byteB_as_int
    xor_hex = hex(xor_int)
    return xor_hex


def generate_subkey(key_matrix_array,round):
    key_matrix = key_matrix_array[len(key_matrix_array)-1]
    output = key_matrix_array

    vector_last_row = get_matrix_column(key_matrix, 3)
    vector_last_row_shifted = shift_word(vector_last_row,1,'left')
    vector_subword_done = vector_subword(vector_last_row_shifted)

    g_vector = vector_xor_round(vector_subword_done,round)

    vector_first_row= get_matrix_column(key_matrix, 0)
    vector_second_row= get_matrix_column(key_matrix, 1)
    vector_third_row= get_matrix_column(key_matrix, 2)
    vector_fourth_row= get_matrix_column(key_matrix, 3)


    new_key_w4 = vectors_xor(vector_first_row,g_vector)
    new_key_w5 = vectors_xor(new_key_w4,vector_second_row)
    new_key_w6 = vectors_xor(new_key_w5,vector_third_row)
    new_key_w7 = vectors_xor(new_key_w6,vector_fourth_row)
    matrix_transposed = transpose_matrix([new_key_w4, new_key_w5, new_key_w6, new_key_w7])
    output.append(matrix_transposed)

    return output


def generate_key_array(key_matrix):
    key_matrix_array = []
    key_matrix_array.append(key_matrix)
    for round in range(1,11):
        key_matrix_array = generate_subkey(key_matrix_array,round)
    return key_matrix_array

def str_to_matrix_hexa(key):
    key_vector = string_to_hex_utf_8_list(key)
    key_matrix = transpose_matrix(vector_to_matrix(key_vector,4))
    return key_matrix


def xor_matrix(matrixA,matrixB):
    new_matrix = []
    for idx,row in enumerate(matrixA):
        row = []
        for idy,column in enumerate(matrixA):
            row.append(xor(matrixA[idx][idy],matrixB[idx][idy]))
        new_matrix.append(row)
    return new_matrix


def shift_row_transformation(matrix):
    return [
        matrix[0],
        shift_word(matrix[1],1,'left'),
        shift_word(matrix[2],2,'left'),
        shift_word(matrix[3],3,'left'),
    ]

def inv_shift_row_transformation(matrix):
    return [
        matrix[0],
        shift_word(matrix[1],1,'right'),
        shift_word(matrix[2],2,'right'),
        shift_word(matrix[3],3,'right'),
    ]

def matrix_to_string(matrix):
    matrix_t = transpose_matrix(matrix)
    output = ''
    for row in matrix_t:
        for byte in row:
            byte_value = byte[2:]
            if len(byte_value)==1:
                byte_value = '0'+byte_value
            output += byte_value
    return output

def matrix_to_string_utf_8(matrix):
    matrix_t = transpose_matrix(matrix)
    output = ''
    for row in matrix_t:
        for byte in row:
            byte_value = int(byte[2:],16)
            output += chr(byte_value)
    return output

def mix_columns(state):
    mul2  = [gf_mul(x, 0x02) for x in range(256)]
    mul3  = [gf_mul(x, 0x03) for x in range(256)]

    for i in range(4):  
        row_a = int(state[0][i], 16)
        row_b = int(state[1][i], 16)
        row_c = int(state[2][i], 16)
        row_d = int(state[3][i], 16)
        
        new_a = (mul2[row_a] ^ mul3[row_b] ^ row_c ^ row_d) & 0xFF
        new_b = (row_a ^ mul2[row_b] ^ mul3[row_c] ^ row_d) & 0xFF
        new_c = (row_a ^ row_b ^ mul2[row_c] ^ mul3[row_d]) & 0xFF
        new_d = (mul3[row_a] ^ row_b ^ row_c ^ mul2[row_d]) & 0xFF
        
        state[0][i] = hex(new_a)
        state[1][i] = hex(new_b)
        state[2][i] = hex(new_c)
        state[3][i] = hex(new_d)
    
    return state

def gf_mul(a, b):
    """Multiply two bytes (a and b) in GF(2^8) using the AES polynomial."""
    p = 0
    for i in range(8):
        if (b & 1) == 1:
            p ^= a
        # Check if a's high bit is set
        hi_bit_set = (a & 0x80)
        a <<= 1
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def inv_mix_columns(state):
    # Create multiplication tables using gf_mul
    mul9  = [gf_mul(x, 0x09) for x in range(256)]
    mul11 = [gf_mul(x, 0x0B) for x in range(256)]
    mul13 = [gf_mul(x, 0x0D) for x in range(256)]
    mul14 = [gf_mul(x, 0x0E) for x in range(256)]
    
    for i in range(4):  # Iterate over each column
        # Convert hex strings to integers
        row_a = int(state[0][i], 16)
        row_b = int(state[1][i], 16)
        row_c = int(state[2][i], 16)
        row_d = int(state[3][i], 16)
        
        # Perform Inverse MixColumns transformation for the column
        new_a = (mul14[row_a] ^ mul11[row_b] ^ mul13[row_c] ^ mul9[row_d]) & 0xFF
        new_b = (mul9[row_a] ^ mul14[row_b] ^ mul11[row_c] ^ mul13[row_d]) & 0xFF
        new_c = (mul13[row_a] ^ mul9[row_b] ^ mul14[row_c] ^ mul11[row_d]) & 0xFF
        new_d = (mul11[row_a] ^ mul13[row_b] ^ mul9[row_c] ^ mul14[row_d]) & 0xFF
        
        # Update state matrix with transformed values (hexadecimal, lowercase format)
        state[0][i] = f"{new_a:02x}"
        state[1][i] = f"{new_b:02x}"
        state[2][i] = f"{new_c:02x}"
        state[3][i] = f"{new_d:02x}"
    
    return state

def string_to_4x4_list(input_string):
    # Validate input length
    if len(input_string) != 32:
        raise ValueError("Input string must be exactly 32 characters long.")
    
    # Create a 4x4 list
    matrix = [
        [input_string[i:i+2] for i in range(row * 8, (row + 1) * 8, 2)]
        for row in range(4)
    ]
    return matrix

def encrypt(key, text):

    if len(key) != 16:
        raise ValueError("Input key must be exactly 32 characters long.")
    
    key_matrix = str_to_matrix_hexa(key)
    text_matrix = str_to_matrix_hexa(text)
    key_array = generate_key_array(key_matrix)

    state_matrix = xor_matrix(key_matrix,text_matrix)

    r = 1
    for round in range(1, 10):
        sub_bytes_matrix = matrix_subword(state_matrix)

        shift_row_matrix = shift_row_transformation(sub_bytes_matrix)

        mix_columns_matrix = mix_columns(shift_row_matrix)

        state_matrix = xor_matrix(mix_columns_matrix, key_array[round])
        r += 1

    sub_bytes_matrix = matrix_subword(state_matrix)
    shift_row_matrix = shift_row_transformation(sub_bytes_matrix)
    state_matrix = xor_matrix(shift_row_matrix, key_array[10])


    encripted_text = matrix_to_string(state_matrix)

    return encripted_text


def decrypt(cipher_text, key):

    if len(cipher_text) != 32:
        raise ValueError("Input cipher must be exactly 32 characters long.")
    
    key_matrix = str_to_matrix_hexa(key)
    cipher_text_matrix = transpose_matrix(string_to_4x4_list(cipher_text))

    key_array = generate_key_array(key_matrix)

    state_matrix = xor_matrix(cipher_text_matrix, key_array[10])

    for round in list(reversed(range(1, 10))):
        inv_shift_row_matrix = inv_shift_row_transformation(state_matrix)
        inv_sub_bytes_matrix = matrix_subword(inv_shift_row_matrix, 'decrypt')
        state_matrix = xor_matrix(inv_sub_bytes_matrix, key_array[round])
        state_matrix = inv_mix_columns(state_matrix)

    inv_shift_row_matrix = inv_shift_row_transformation(state_matrix)
    inv_sub_bytes_matrix = matrix_subword(inv_shift_row_matrix, 'decrypt')
    decrypted_text = xor_matrix(inv_sub_bytes_matrix, key_array[0])
    decrypted_text = matrix_to_string_utf_8(decrypted_text)

    return decrypted_text
