# Author: RussianPanda

# Reference: https://research.openanalysis.net/pikabot/debugging/string%20decryption/2023/11/12/new-pikabot.html

# Tested on samples:
# eac50a1484c8340309f09da104776d95
# 53e19ad0acf644ef2ddf55e22846de7c
# a12001230dd6f5ca67f7935bcfdcd650
# 989daccd224508438f6f6db6ce7b5125

import sys
import yara
import pefile
from capstone import *
from Crypto.Cipher import AES
import base64
import re


def unpad(data):
    return data[:-data[-1]]

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted)

def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

def aes_dec(enc_str):
    enc_str_bytes = bytes.fromhex(enc_str)

    # Extract the IV
    iv_start = 3 + 16
    iv = enc_str_bytes[iv_start:iv_start + 16]

    # Extract Encrypted C2 (44 bytes after the IV)
    encrypted_c2_start = iv_start + 16
    encrypted_c2 = enc_str_bytes[encrypted_c2_start:encrypted_c2_start + 44]

    # Extract the first 100 bytes of enc_str_bytes
    aes_key = enc_str_bytes[3:95]

    if iv in aes_key:
        aes_key = aes_key.replace(iv, b'')
    if encrypted_c2 in aes_key:
        aes_key = aes_key.replace(encrypted_c2, b'')

    try:
        # Decrypt Encrypted C2 using AES
        encrypted_c2_b64_dec = base64.b64decode(encrypted_c2)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_c2 = cipher.decrypt(encrypted_c2_b64_dec)

        # Extract readable characters
        decrypted_c2 = decrypted_c2.decode('utf-8', errors='ignore')
        filtered_c2 = ''.join(re.findall(r'[a-zA-Z0-9.:]+', decrypted_c2))
        return filtered_c2
    except Exception :
        pass
    
def offset_to_virtual(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < section.PointerToRawData + section.SizeOfRawData:
            virtual_offset = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + (offset - section.PointerToRawData)
            return virtual_offset
    return None

# Read bytes until null termination
def read_until_null(pe, file_offset):
    extracted_data = bytearray()
    while True:
        byte = pe.get_data(file_offset, 1)
        if byte == b'\x00':
            break
        extracted_data += byte
        file_offset += 1
    return extracted_data

# YARA rules
rule_data_one = 'rule data_one { strings: $s = {be ?? ?? ?? ?? 33 d2 f3 a5} condition: $s }'
rule_data_two = 'rule data_two { strings: $a = {be ?? ?? ?? 00 8d bd ?? ?? ff ff f3 a5 be} condition: $a }'

rules = yara.compile(sources={
    'data_one': rule_data_one,
    'data_two': rule_data_two
})

if len(sys.argv) < 2:
    print("Usage: python pikabot_c2_extractor.py <file_path>")
    sys.exit(1)

file_path = sys.argv[1]

try:
    pe = pefile.PE(file_path)
except FileNotFoundError:
    print(f"File not found: {file_path}")
    sys.exit(1)

pe = pefile.PE(file_path)

matches = rules.match(file_path)

def process_match(match, pe, max_instructions=50):
    for string in match.strings:
        offset, identifier, data = string

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        with open(file_path, 'rb') as file:
            file.seek(offset)
            file_data = file.read(1024)

        mov_esi_counter = 0
        instruction_count = 0
        for insn in md.disasm(file_data, offset):
            instruction_count += 1
            if instruction_count > max_instructions:
                return None, None

            if insn.mnemonic == 'mov' and 'esi' in insn.op_str:
                mov_esi_counter += 1
                second_operand = insn.op_str.split(',')[1].strip()
                if second_operand.startswith('0x'):
                    memory_address = int(second_operand, 16)
                    file_offset = memory_address - pe.OPTIONAL_HEADER.ImageBase

                    if mov_esi_counter == 1:
                        encrypted_data = pe.get_data(file_offset, 672)
                    elif mov_esi_counter == 2:
                        rc4_key = read_until_null(pe, file_offset)
                        return encrypted_data, rc4_key

    return None, None

for match in matches:
    encrypted_data, rc4_key = process_match(match, pe)
    
    if rc4_key:
        break

if encrypted_data and rc4_key:
    decrypted_data = rc4(rc4_key, encrypted_data)
    decrypted_data = decrypted_data.replace(b'_', b'=')

    split_data = decrypted_data.split(b'\x26') 
    for i, data_part in enumerate(split_data, start=1):
        enc_str = data_part.hex()
        decrypted_value = aes_dec(enc_str)
        if decrypted_value: 
            print(f"C2: {decrypted_value}")


if not rc4_key:
    print("RC4 key not found in any matches")
