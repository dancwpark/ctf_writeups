from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher

def decrypt(ciphertext, key):
    plain = []
    for i in ciphertext:
        plain.append(chr(i//key))
    return plain


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text

def rev_xor(ciphertext, text_key):
    plain_text = ""
    key_length = len(text_key)
    for i, char in enumerate(ciphertext):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plain_text += decrypted_char
    
    return plain_text[::-1]


def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')


if __name__ == "__main__":
    message = sys.argv[1]
    test(message, "trudeau")
    cipher =  [61578, 109472, 437888, 6842, 0, 20526, 129998, 526834, 478940, 287364, 0, 567886, 143682, 34210, 465256, 0, 150524, 588412, 6842, 424204, 164208, 184734, 41052, 41052, 116314, 41052, 177892, 348942, 218944, 335258, 177892, 47894, 82104, 116314]
    new_cipher = []
    for i in cipher:
        new_cipher.append(i//311)

    a = 90
    b = 26
    p = 97
    g1 = 29
    g2 = 31

    u1 = generator(g1, a, p)
    u2 = generator(g2, a, p)
    v1 = generator(g1, b, p)
    v2 = generator(g2, b, p)

    key1 = generator(v1, a, p)
    key2 = generator(v2, a, p)
    bkey1 = generator(u1, b, p)
    bkey2 = generator(u2, b, p)

    print(key1, bkey1)
    print(key2, bkey2)

    sharedkey1 = 47
    sharedkey2 = 22

    plain1 = decrypt(new_cipher, sharedkey1)
    plain2 = decrypt(new_cipher, sharedkey2)

    plain1 = rev_xor(plain1, 'trudeau')
    plain2 = rev_xor(plain2, 'trudeau')

    print(plain1)
    print(plain2)




