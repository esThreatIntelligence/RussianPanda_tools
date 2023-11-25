# Author: RussianPanda

# Tested on samples:
# 7b0cfa445110ff4fd35b1add25a3d00d
# b706b0852bbd821cecafc722b675315f
# 7cfde8947e0b0995468f77b960ff96ea

import yara
import re
from Crypto.Cipher import ARC4
import sys

def decrypt_rc4(key, ciphertext):
    cipher = ARC4.new(key)
    return cipher.decrypt(ciphertext)

def find_first_non_null_sequence(data_slice):
    match = re.search(rb'[\x01-\xff]+', data_slice)
    return match.group() if match else None

rule = yara.compile(source='rule data_scan { strings: $s = {50 72 6F 64 75 63 74 4E 61 6D 65 00} condition: $s }')

def scan_bytes(file_path, decrypted_rc4_config_key):
    desired_length = 0
    with open(file_path, 'rb') as f:
        f.seek(0, 2)  
        file_size = f.tell()

        # Start with the maximum number of bytes we want to read
        read_size = min(8000, file_size)
        while desired_length < 50 or desired_length > 400:
            start = max(0, file_size - read_size)
            f.seek(start)
            last_bytes = f.read(read_size)
            
            last_bytes = last_bytes.strip(b'\x00')
            desired_length = len(last_bytes)

            # Reduce the read_size until we find the appropriate number of bytes
            if desired_length > 50 and desired_length < 400:
                break  
            else:
                read_size -= 50  #
                if read_size < 50:
                    print("Can't find a suitable number of bytes that satisfy the condition")
                    return

        if not last_bytes:
            return
        
        decrypted_data = decrypt_rc4(decrypted_rc4_config_key, last_bytes)

        if b'3333' in decrypted_data:
            ascii_string = decrypted_data.decode('ascii', 'ignore')

            pattern = r'(?<=[\x00\x11])((?:[^\x00\x11]+\x00?)+)(?=[\x00\x11])'

            matches = re.findall(pattern, ascii_string)

            for match in matches:
                match = re.sub(r'3333', '', match)  
                match = re.sub(r'\b09\b', '', match)  

                clean_match = ''.join(filter(str.isprintable, match)).strip()
                if len(clean_match) > 1:
                    print(clean_match)

def scan_binary(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    matches = rule.match(data=data)
    for match in matches:
        for string in match.strings:
            offset = string[0]
            start = max(0, offset - 750)
            data_slice = data[start:offset]
            non_null_data = find_first_non_null_sequence(data_slice)
            
            if non_null_data and len(non_null_data) >= 32:  
                for i in range(min(6, len(non_null_data) // 4)):

                    rc4_key_pos = len(non_null_data) - (4 * (i + 1))
                    rc4_key = non_null_data[rc4_key_pos:rc4_key_pos+4]
                
                    encrypted_rc4 = non_null_data[:rc4_key_pos]  
                    decrypted_rc4_config_key = decrypt_rc4(rc4_key, encrypted_rc4)[:32]

                    if decrypted_rc4_config_key:
                        scan_bytes(file_path, decrypted_rc4_config_key)
                    else:
                        print(f"Decryption failed for RC4 key at position {rc4_key_pos}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: parallax_rat_config_extractor.py <file.bin>")
        sys.exit(1)

    file_path = sys.argv[1]
    scan_binary(file_path)