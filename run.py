from AES_128 import encrypt, decrypt

key = '1HundredwireKey.'
text = '1HundredwireWiFi'

cipher_text = encrypt(key,text)
output = decrypt(cipher_text,key)

print(cipher_text)
print(output)