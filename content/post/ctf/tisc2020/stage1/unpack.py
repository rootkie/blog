import subprocess
import os
import zlib, gzip, bz2, lzma, base64

filename = "out"
counter = 0
data = ""
with open("temp.mess", "rb") as f:
    data = f.read()

with open(filename, "wb") as f:
    f.write(zlib.decompress(data))


while True:
    file_output = str(subprocess.check_output(['file',filename]))
    if "zlib" in file_output: 
        with open(filename, "rb") as f:
            data = f.read()
        with open(filename, "wb") as f:
            f.write(zlib.decompress(data))
    if "gzip" in file_output:
        with open(filename, "rb") as f:
            data = f.read()
        with open(filename, "wb") as f:
            f.write(gzip.decompress(data))
    if "bzip2" in file_output:
        with open(filename, "rb") as f:
            data = f.read()
        with open(filename, "wb") as f:
            f.write(bz2.decompress(data))
    if "XZ" in file_output:
        os.system("mv out out.xz; xz -d out.xz")
    if "ASCII" in file_output:
        with open(filename, "r") as f:
            data = f.read()
        
        try:
            d = bytearray.fromhex(data)
            with open(filename, "wb") as f:
                f.write(d)
        except:
            d = base64.b64decode(data)
            with open(filename, "wb") as f:
                f.write(d)
        if "TISC" in str(d):
            break


    counter += 1
    if counter > 500:
        break
print (counter)
