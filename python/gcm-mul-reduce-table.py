#!/usr/bin/python3

REDUCE_BYTE = 0xE1

reduce_table = [0] * 256
for i in range(8):
    i_bit = 1 << i
    for j in range(256):
        if j & i_bit:
            reduce_table[j] ^= (REDUCE_BYTE << (i + 1))

for j in range(256):
    if j and (j % 16) == 0:
        print()
    print('0x{:04X}u, '.format(reduce_table[j]), end='')
print()
