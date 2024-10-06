import random

# Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Inverse Initial Permutation (IP)
INV_IP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Permutasi dan fungsi XOR
def permute(input_block, table):
    return ''.join([input_block[i-1] for i in table])

def xor(block1, block2):
    return ''.join(['1' if block1[i] != block2[i] else '0' for i in range(len(block1))])

# Fungsi Feistel
def feistel_function(right_half, subkey):
    return xor(right_half, subkey)

# DES round
def des_rounds(left, right, subkey):
    new_left = right
    new_right = xor(left, feistel_function(right, subkey))
    return new_left, new_right

# Enkripsi level blok
def block_encrypt(block, keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for key in keys:
        left, right = des_rounds(left, right, key)
    combined = right + left
    return permute(combined, INV_IP)

# Dekripsi level blok
def block_decrypt(block, keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for key in reversed(keys):
        left, right = des_rounds(left, right, key)
    combined = right + left
    return permute(combined, INV_IP)

# Key generation
def key_generator():
    main_key = format(random.getrandbits(64), '064b')
    print(f"Generated Key: {main_key}")
    subkeys = [format(random.getrandbits(48), '048b') for _ in range(16)]
    return subkeys

# Fungsi padding dan unpadding
def pad(plaintext_bin):
    while len(plaintext_bin) % 64 != 0:
        plaintext_bin += '0'
    return plaintext_bin

def unpad(plaintext_bin):
    return plaintext_bin.rstrip('0')

# Enkripsi dan Dekripsi mode CBC
def encrypt_cbc(plaintext, keys, iv):
    plaintext_bin = pad(plaintext)
    blocks = [plaintext_bin[i:i+64] for i in range(0, len(plaintext_bin), 64)]
    previous_block = iv
    ciphertext = ""

    for block in blocks:
        block = xor(block, previous_block)
        encrypted_block = block_encrypt(block, keys)
        previous_block = encrypted_block
        ciphertext += encrypted_block

    return ciphertext

def decrypt_cbc(ciphertext, keys, iv):
    blocks = [ciphertext[i:i+64] for i in range(0, len(ciphertext), 64)]
    previous_block = iv
    decrypted_text = ""

    for block in blocks:
        decrypted_block = block_decrypt(block, keys)
        plaintext_block = xor(decrypted_block, previous_block)
        previous_block = block
        decrypted_text += plaintext_block

    return unpad(decrypted_text)

# Fungsi helper konversi biner
def str_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_str(binary_text):
    chars = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    return ''.join([chr(int(char, 2)) for char in chars])


if __name__ == "__main__":
    keys = key_generator()
    iv = format(random.getrandbits(64), '064b')

    plaintext = input("Enter plaintext: ")
    plaintext_bin = str_to_bin(plaintext)
    plaintext_bin = pad(plaintext_bin)

    # Enkripsi
    encrypted_bin = encrypt_cbc(plaintext_bin, keys, iv)
    print(f"Encrypted: {encrypted_bin}")

    # Dekripsi
    decrypted_bin = decrypt_cbc(encrypted_bin, keys, iv)
    decrypted_text = bin_to_str(decrypted_bin)
    print(f"Decrypted: {decrypted_text}")