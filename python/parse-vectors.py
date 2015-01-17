#!/usr/bin/env python3

import codecs
#from pprint import pprint

key_map = {
    'COUNT': 'count',
    'KEY': 'key',
    'PLAINTEXT': 'plain',
    'CIPHERTEXT': 'cipher',
}

def byte_string_to_c_array_init(byte_string):
    return ", ".join("0x{:02X}".format(c) for c in byte_string)

def vectors_iter(fileobj):
    for line in fileobj:
        line = line.strip()
        if line.startswith("COUNT"):
            parts = line.split("=")
            count = int(parts[1].strip())
            #yield count
            test_data = { 'count': count }
            for line in fileobj:
                line = line.strip()
                if not line:
                    yield test_data
                    break
                key, valuestr = [ a.strip() for a in line.split("=") ]
                key = key_map.get(key, key)
                value = codecs.decode(valuestr, "hex")
                test_data[key] = value

def main():
    import sys

    filename = sys.argv[1]
    with open(filename, "r") as f:
        vectors_list = []
        for test_data in vectors_iter(f):
            #pprint(test_data)
            vector_prefix = "count{}".format(test_data['count'])
            for key in ('key', 'plain', 'cipher'):
                if key in test_data:
                    array_data = byte_string_to_c_array_init(test_data[key])
                    print("const uint8_t {}{}[] = {{ {} }};".format(vector_prefix, key, array_data))

            print("const vector_data_t {} = {{".format(vector_prefix))
            print("    .count = {},".format(test_data['count']))
            for key in ('key', 'plain', 'cipher'):
                if key in test_data:
                    print("    .{} = {}{},".format(key, vector_prefix, key))
                else:
                    print("    .{} = NULL,".format(key))
            print("};")
            print()
            vectors_list.append(vector_prefix)

        print("const vector_data_t * const test_vectors[] = {")
        for vector_name in vectors_list:
            print("    &{},".format(vector_name))
        print("};")

if __name__ == "__main__":
    main()

