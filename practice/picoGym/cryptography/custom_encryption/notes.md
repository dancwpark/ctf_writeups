# Custom Encryption

1. 2 primes: p, g
2. a is between p-10, p -- b is between g-10 and g
3. generator function -- `g**x mod p`
4. u = `g**a mod p`
5. v = `g**b mod p`
6. key = `v**a mod p`
7. bkey = `u**a mod p`

so key = `(g**b)**a mod p`
so bkey = `(g**a)**a mod p`

ensure key == bkey

use key to encrypt plaintext with the text key -- dynamic xor key
and then encrypt again using the bkey

for each character in the plaintext going backwards:
charkey = text+key[index mod key_len)
encrypted char = chr(ord(char) xor ord(charkey))
  * changes char and char key to decimal - xor them - then return the char
take the returned ciphertext and encrypt with the bkey
for char in ciphertext1:
    1. decimal of char multiplied by key * 311

# decrypt
* a = 90, b = 26
    * p, q?
    * p = 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100
    * g = 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36

