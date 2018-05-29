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
    reduce_value = reduce_table[j]
    if False:
        # Swap endianness.
        reduce_value = ((reduce_value & 0xFF) << 8) | ((reduce_value >> 8) & 0xFF)
    if True:
        print('0x{:04X}u, '.format(reduce_value), end='')
    else:
        print('{{ {{ 0x{:02X}u, 0x{:02X}u, }} }}, '.format(reduce_value >> 8, reduce_value & 0xFF), end='')
print()
