import binascii
from pwn import *

def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

keyenc = 0x4aca8af91f97ef198ba32c820e8868deb693f86f763d3a2879a84fa8e7af6f396107701b480e453ec69b7e3f72f02520f408a98c163db6c70f9902eab87c882b73c158e16be95dc4a9921fec3297586343b250f6cf58f3512e37de84e2f3d12639bec4f88ed5e68226fad6c2e5dbdfe9b44350aaedc61015e8f28cce50a69c67f919f0c5d2c2c9073bf4d25afb299e65acf703880949b32f5e442e77cf527f6a8a3881ba1f94e79103abb9c1a1f55a4735488e05d0a41fd7feb3b7c130c2139dcc4301a55d87806e04f45ce210ecbc971bfaf7a2ff090f39709f4025f658f7729eb1cfbef40cfce7d469d1095f60144e2f312b6493ce0cca3765189089425a04d035cdd6a80b131b231215141ae83f2a3410fc551ca30296be4ad3f7bf4cdb1e09583f97d445150c037f88d7ca765174f8b202b6a5f513dd9f20b430bbbbfc2309293271faac024b38cde3fc22555cd860ef79ae16697982e37650c933ced29879280f2301d7efcc4967dd77e668a65afbc770d46669e67678f347c5d85ffe05218d8ebeec470ca1d74ae8956589db43999a1643a95b0a72acf6ace052fdef8bcc63dc7ce67024866d4e7cb421965218614a41e0789c7239733e6f97c00f1db05bff3e1283e3790a4a9ac2e6f1cfa5084555f4412da28d7434bfa27d6b4cdf4da50889c9285c8ca0e606398bfb3b34894752667df01a28023b7297d3a16978f4a974cf2d04088

print (binascii.unhexlify(hex(nth_root(keyenc,3))[2:]))
