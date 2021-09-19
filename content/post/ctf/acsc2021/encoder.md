---
title: "ACSC 2021 Encoder write up"
date: 2021-09-19T15:37:12+08:00
draft: false
---

# Encoder [REV/270]

Encoder is a 64-bit Linux ELF binary that encodes a file. We need to find a way to decode the file and retrieve flag.jpg

# Initial Analysis

Playing around with the file a bit, we can gather some conclusions

```bash
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
encoded:
00000000: 140f e281 3c50 078a 40f1 281e c503 78a0  ....<P..@.(...x.
00000010: 0f14 81e2 503c 8a07 f140 1e28 03c5 a078  ....P<...@.(...x
00000020: 140f e281 3c50 078a 40f1 281e c503 78a0  ....<P..@.(...x.
00000030: 0f14 81e2 503c 8a07 f140 1e28 03c5 a078  ....P<...@.(...x
=======file2=======
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
encoded:
00000000: 1805 a300 1460 028c 8051 300a 4601 28c0  .....`...Q0.F.(.
00000010: 0518 00a3 6014 8c02 5180 0a30 0146 c028  ....`...Q..0.F.(
00000020: 1805 a300 1460 028c 8051 300a 4601 28c0  .....`...Q0.F.(.
00000030: 0518 00a3 6014 8c02 5180 0a30 0146 c028  ....`...Q..0.F.(
```

1. The encoding is 1:2 ratio. Meaning each byte is encoded to 2 bytes
2. The same byte will encode to different byte depending on the byte position in  the file. However, there is a repeating pattern every 16 bytes. In fact there is some correlation between 4x4byte blocks within the 16 bytes. Like 1805 at position 0 will become 8051 at position 8, 0518 at position 16. It's just some shifting of bits here and there.
3. The encoding table is randomly generated since each run has a different result.

# Eliminating the variance

Tracing the program from main to target function does not work in IDA since it seems to introduce some sort of bad instruction to screw with the disassembler.

```assembly
.text:000000000000191B ; int __fastcall main(int, char **, char **)
.text:000000000000191B main            proc near               ; DATA XREF: start+1D↑o
.text:000000000000191B                                         ; main+F↓o
.text:000000000000191B
.text:000000000000191B var_70          = qword ptr -70h
.text:000000000000191B var_64          = dword ptr -64h
.text:000000000000191B var_4           = dword ptr -4
.text:000000000000191B
.text:000000000000191B ; __unwind {
.text:000000000000191B                 push    rbp
.text:000000000000191C                 mov     rbp, rsp
.text:000000000000191F                 sub     rsp, 70h
.text:0000000000001923                 mov     [rbp+var_64], edi
.text:0000000000001926                 mov     [rbp+var_70], rsi
.text:000000000000192A                 lea     rax, main
.text:0000000000001931                 and     rax, 0FFFFFFFFFFFFF000h
.text:0000000000001937                 mov     edx, 7          ; prot
.text:000000000000193C                 mov     esi, 4000h      ; len
.text:0000000000001941                 mov     rdi, rax        ; addr
.text:0000000000001944                 call    _mprotect
.text:0000000000001949                 mov     [rbp+var_4], eax
.text:000000000000194C                 ud2
.text:000000000000194C main            endp
.text:000000000000194C
.text:000000000000194C ; ---------------------------------------------------------------------------
.text:000000000000194E                 dw 5206h
.text:0000000000001950                 dq 250B0F79B700CDB6h, 3D99232B4F22453Ch, 0A1794DE5C872052Bh
.text:0000000000001950                 dq 9E67749C3158D825h, 0B6F1F2AB87F61265h, 1E0B0F72B1E9F962h
.text:0000000000001950                 dq 1DF9972B4F22453Ch, 391CAB1526C66F03h, 32B6E0007D7CFC25h
.text:0000000000001950                 dq 0B0F72C67F2A12E3h, 2690FF7FB6413C07h, 809C96463C160B0Fh
```



However, since we know the encoding table is randomly generated, we can start working from there by finding the xrefs to rand calls

```assembly
.text:0000000000001873                 push    rbp
.text:0000000000001874                 mov     rbp, rsp
.text:0000000000001877                 sub     rsp, 140h
.text:000000000000187E                 jnb     short loc_1885
.text:000000000000187E ; ---------------------------------------------------------------------------
.text:0000000000001880                 db 0FFh, 0FEh, 0F0h, 0ABh, 2Ah
.text:0000000000001885 ; ---------------------------------------------------------------------------
.text:0000000000001885
.text:0000000000001885 loc_1885:                               ; CODE XREF: .text:000000000000187E↑j
.text:0000000000001885                 mov     esi, 0
.text:000000000000188A                 lea     rdi, aDevUrandom ; "/dev/urandom"
.text:0000000000001891                 mov     eax, 0
.text:0000000000001896                 call    _open
.text:000000000000189B                 mov     cs:fd, eax
.text:00000000000018A1                 mov     edi, 0
.text:00000000000018A6                 call    _time ; "here is where the randomness come from"
.text:00000000000018AB                 mov     edi, eax
.text:00000000000018AD                 call    _srand
.text:00000000000018B2                 call    _rand
.text:00000000000018B7                 mov     ecx, eax
.text:00000000000018B9                 movsxd  rax, ecx
.text:00000000000018BC                 imul    rax, -7F7F7F7Fh
```



At this stage, it is initializing the encoding table with srand(time(0)) and rand() as seed. There are some bitwise magic going afterwards but my solution does require the full understanding of what's going on.

First thing first we can eliminate the variance in each invocation by changing the assembly of `call time -> mov eax, <num>`. We will always use a static number as seed to srand and this will make encoder basically a static encoder without the changing encoding table. This editing can be done using radare2 or any hex editor. We will call this modified version of encoder `encoder.mod`. With this `encoder.mod` we can further experiment the behavior of the binary.

```asm
[0x00001896]> pd 10
            0x00001896      e805f5ffff     call sym.imp.open
            0x0000189b      8905bf282000   mov dword [0x00204160], eax ; [0x204160:4]=0
            0x000018a1      bf00000000     mov edi, 0
            0x000018a6      b8efbeadde     mov eax, 0xdeadbeef
            0x000018ab      89c7           mov edi, eax
            0x000018ad      e83ef5ffff     call sym.imp.srand
            0x000018b2      e899f4ffff     call sym.imp.rand
            0x000018b7      89c1           mov ecx, eax
            0x000018b9      4863c1         movsxd rax, ecx
            0x000018bc      4869c0818080.  imul rax, rax, -0x7f7f7f7f
```

# Further analysis

Now we have a static encoder, we can test if each byte's encoding is independent.

```
00000000: 4141 4141                                AAAA
encoded:
00000000: 081c 8103 7020 0e04                      ....p ..
==============
00000000: 4241 4141                                BAAA
encoded:
00000000: 041c 8103 7020 0e04                      ....p ..
```

From here, we can see that the As are encoded to the same WORD if they are at  the same position. With that in mind, we can now recreate the encoding table for any given seed. However, what should the seed be?

## Finding the seed

To find the seed, we need something to verify our seed. Luckily, they provided the flag file as a jpg file. We can always use the magic header as the predicate.

We know that the first 3 bytes of any jpg is `FF D8 FF` and the first 6 bytes of encoded flag file is `00 0A C3 81 28 00`. So we need to find a seed that will give us that particular encoding.

I wrote a script that will modify the binary at specific location to change the value of `num` in `mov eax, <num>`, saving the binary and running the binary on given test file containing the jpg magic number. Then it will check if the encoded data matches.

```python
from pwn import *
import os


op = b'\xb8' # mov eax, 

start = 1609462861
end = 1631942935

for i in range(end, start, -1):
    print (i)
    val = p32(i)

    f = open("encoder.mod", "rb").read()
    f = bytearray(f)
    f[0x18a6:0x18a6+5] = op+val
    open("encoder.target", "wb").write(f)
    os.chmod("encoder.target", 755)


    # run the program on test
    os.system("./encoder.target test2")

    # verify it hit target
    f = open("test2.enc", "rb").read()
    if f[0] == 0 and f[1] == 0xa and f[2] == 0xc3 and f[3] == 0x81 and f[4] == 0x28 and f[5] == 0:
        break
```

Running the script will give us an `encoder.target` which matches the encoder that is used to encode the flag file.

# Recreating the table and solve

Now we have everything we need to decode this flag. Since the bytes are 1 to 1 match to the encoding table which seems to be a 16 WORD array, we can recreate the table by using the following python script

```python
import os
import sys

def create_pads():
    for i in range(0,256):
        towrite = i.to_bytes(1, byteorder="big") * 0x20
        open(str(i)+".pad", "wb").write(towrite)

def create_encs():
    for i in range(0,256):
        os.system("../encoder.target " + str(i)+".pad")

def dec(infile, outfile):
    # recreate encoding table in b
    b = [[0 for i in range(0xffff)] for _ in range(16)]

    for i in range(256):
        f = open("./"+str(i)+".pad.enc", "rb").read()

        for j in range(0,32,2):
            t = int.from_bytes(f[j:j+2], "big")
            b[int(j/2)][t] = i

    # decoding given file
    flag = open(infile, "rb").read()
    output = bytearray(int(len(flag)/2))
    for i in range(0, len(flag), 2):
        t = int.from_bytes(flag[i:i+2], "big")
        cur = b[int(i/2) % 16][t]
        output[int(i/2)] = cur

    open(outfile, "wb").write(output)

if __name__ == "__main__":
    create_pads()
    create_encs()
    dec(sys.argv[1], sys.argv[2])
```

1. We create 32 bytes of each possible byte
2. Use encoder to encode all 256 pads
3. Recreate the encoding table and use it to decode a given file.

4. Open the resulting flag.jpg and submit the flag

# Conclusion

I took a more experimental and dynamic approach to this challenge since I didn't want to bother with the tedious RE aspect. I have a feeling this approach may not be intended as it seems too easy to be worth 270 points. But all in all, it is quite a fun challenge that is more traditional than the other RE challenge in ACSC.

