# author: RussianPanda
# reference: https://github.com/esThreatIntelligence/RussianPanda_tools/blob/main/darkgate_config_extractor.py
# tested on samples: 786486d57e52d2c59f99f841989bfc9d
# 853e53f0fd01e14e61498ffea94d70b0

import pefile
import re
import sys
import zlib

def has_symbols(s):
    return any(char for char in s if not char.isalnum() and char not in [' ', '\t', '\n', '\r'])

def decode_custom_base64(encoded_str, custom_base64_str):
    index_map = {char: i for i, char in enumerate(custom_base64_str)}

    def decode_block(block):
        index = [index_map.get(char, 64) for char in block]
        while len(index) < 4:
            index.append(64)

        byte1 = (index[0] << 2) | (index[1] >> 4)
        byte2 = ((index[1] & 0x0F) << 4) | (index[2] >> 2)
        byte3 = ((index[2] & 0x03) << 6) | index[3]

        bytes_decoded = bytearray()
        bytes_decoded.append(byte1)
        if index[2] != 64:
            bytes_decoded.append(byte2)
        if index[3] != 64:
            bytes_decoded.append(byte3)
        return bytes_decoded

    try:
        decoded_bytes = bytearray()
        for i in range(0, len(encoded_str), 4):
            decoded_bytes += decode_block(encoded_str[i:i+4])
        return decoded_bytes
    except Exception as e:
        print(e)
        return None

def find_base64_pattern_in_pe(file_path):
    base64_pattern_64 = re.compile(b"[A-Za-z0-9+/=]{64,}")
    base64_pattern_any = re.compile(b"[A-Za-z0-9+/=]{20,}")

    pe = pefile.PE(file_path)
    data = pe.get_memory_mapped_image()
    all_encrypted_strings = []

    base64_64_matches = [match.group(0).decode(errors='replace') for match in base64_pattern_64.finditer(data)]

    if len(base64_64_matches) >= 3:
        custom_base64_str = base64_64_matches[1]
        custom_base64_str_two = base64_64_matches[2]

        decoded_str_two = decode_custom_base64(custom_base64_str_two, custom_base64_str)
        if decoded_str_two:
            try:
                decompressed_data = zlib.decompress(decoded_str_two)
                print(f"Configuration: {decompressed_data.decode('utf-8')}")
            except Exception as e:
                print(f"Failed to decompress the configuration: {e}")

    for match in base64_pattern_any.finditer(data):
        matched_bytes = match.group(0).decode(errors='replace')
        if len(matched_bytes) >= 20:
            all_encrypted_strings.append(matched_bytes)

    for matched_bytes in base64_64_matches:
        all_encrypted_strings.append(matched_bytes)

    decoded_results = {}

    for s in all_encrypted_strings:
        decoded_bytes = decode_custom_base64(s, custom_base64_str)
        if decoded_bytes:
            try:
                decoded_string = decoded_bytes.decode('utf-8', 'ignore')
                if has_symbols(decoded_string):
                    decoded_results[s] = decoded_string
            except Exception:
                pass

    http_results = {k: v for k, v in decoded_results.items() if 'http://' in v or 'https://' in v}
    for url in http_results.values():
        separated_urls = re.sub(r'(http:// | https://)', r' | \1', url)
        print(f"C2: {separated_urls.strip(' | ')}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python darkgate_config_extractor_2.py <path_to_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    find_base64_pattern_in_pe(file_path)
