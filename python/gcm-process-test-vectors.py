#!/usr/bin/python3

import codecs
import re
import fileinput

bracket_re = re.compile(r'^\[\s*(\w+)\s*=\s*(\w+)\s*\]$')
params_re = re.compile(r'^\s*(\w+)\s*=\s*(\w*)\s*$')

group_params = {}
params = {}
num_out = 0

def to_c_init(hex_str):
    if hex_str:
        bytes_init = ', '.join([ '0x{:02X}u'.format(x) for x in codecs.decode(hex_str, 'hex') ])
        return '(const uint8_t []){ ' + bytes_init + ', }'
    else:
        return 'NULL'

def c_len(key, hex_str):
    data_len = len(hex_str) // 2
    return data_len

TEMPLATE = '''    {{
        // {}
        .p_key =    {},
        .p_iv =     {},
        .aad_len =  {},
        .p_aad =    {},
        .pt_len =   {},
        .p_pt =     {},
        .ct_len =   {},
        .p_ct =     {},
        .tag_len =  {},
        .p_tag =    {},
    }},'''

for line_num, line in enumerate(fileinput.input()):
    line = line.rstrip()
    #print(line)

    if not line:
        if params and group_params['Keylen'] == 128 and group_params['IVlen'] == 96:
            #print(group_params)
            #print(params)
            #print()
            num_out += 1
            try:
                print(TEMPLATE.format(
                    num_out - 1,
                    to_c_init(params['Key']),
                    to_c_init(params['IV']),
                    c_len('AAD', params['AAD']),
                    to_c_init(params['AAD']),
                    c_len('PT', params['PT']),
                    to_c_init(params['PT']),
                    c_len('CT', params['CT']),
                    to_c_init(params['CT']),
                    c_len('Tag', params['Tag']),
                    to_c_init(params['Tag']),
                ))
            except Exception:
                print(line_num, num_out, params)
                raise
        params = {}
        continue

    if line[0] == '#':
        continue

    m = bracket_re.match(line)
    if m:
        key = m.group(1)
        value = m.group(2)
        try:
            value = int(value)
        except Exception:
            pass
        group_params[key] = value
        #print(key, value)
    else:
        m = params_re.match(line)
        if m:
            key = m.group(1)
            value = m.group(2)
            params[key] = value
            #print(key, value)
print('\n\n#define GCM_NUM_VECTORS {}'.format(num_out))
