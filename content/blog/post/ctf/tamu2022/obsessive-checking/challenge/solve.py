from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from pwn import *


#6370752e6366735f71756f74615f7573
#2f7379732f66732f6367726f75702f6370752f6370752e6366735f71756f74615f7573

def dec(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pt


#ct = p64(0xb7ec822fe7709550)+p64(0x575fe7ab801a233d)+p64(0xb07865a5f602f6d8)+p64(0xc7cd911b396da3ea)

key = p64(0xb10377e39a316bef)+p64(0x9e6b76de949612ec)+p64(0x5696f29e48ec594f)+p64(0xc6b3ed3f8c157327)


f = open("flag_book.txt.bin", "rb")
ct = f.read()
f.close()

with open("decryted.txt", "wb") as w:
    w.write(dec(key, ct[:16], ct))




#for key in map(lambda x: bytes.fromhex(x), keys):
#    for iv in map(lambda x: bytes.fromhex(x), ivs):
#        dec(key, iv)

