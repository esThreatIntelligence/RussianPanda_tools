# Author: RussianPanda
# Tested on sample: 296c88dda6b9864da68f0918a6a7280d

import sys

def decode_custom_base64(encoded_data, custom_base64_str):
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
        for i in range(0, len(encoded_data), 4):
            decoded_bytes += decode_block(encoded_data[i:i+4])
        return decoded_bytes
    except Exception as e:
        print(e)
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python darkgate_payload_decode.py <path_to_data_file> <path_to_output_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            data_split = data.split(b'|')
            if len(data_split) < 3:
                print("Invalid data format")
                sys.exit(1)

            custom_base64_str = data_split[1].decode('utf-8')
            encoded_data = data_split[2].decode('utf-8')

            decoded_bytes = decode_custom_base64(encoded_data, custom_base64_str)
            if decoded_bytes:
                with open(output_file_path, 'wb') as output_file:
                    output_file.write(decoded_bytes)
                print("Payload successfully decoded!")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
