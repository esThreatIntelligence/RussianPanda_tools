# Author: RussianPanda
# b803e8d9da6efe7b0220f654c7afb784d21dc222afd4a4e41396e74f861cbf30

def hex_char_to_byte(char):
    ascii_val = ord(char)
    
    if '0' <= char <= '9':
        return ascii_val - ord('0')
    elif 'a' <= char <= 'f':
        return ascii_val - ord('a') + 10
    elif 'A' <= char <= 'F':
        return ascii_val - ord('A') + 10
    else:
        return 0

def deobfuscate_str(input_str):
    byte_array = []
    for i in range(0, len(input_str), 2):
        first_byte = hex_char_to_byte(input_str[i]) * 16
        second_byte = hex_char_to_byte(input_str[i+1])
        byte_array.append(first_byte | second_byte)
    
    # XOR decryption
    key = byte_array[:4]
    decrypted_bytes = [byte_array[i] ^ key[i % 4] for i in range(4, len(byte_array))]
    
    decrypted_str = ''.join([chr(b) for b in decrypted_bytes])
    
    return decrypted_str

enc_string = "aab58e5185f0f625cfdbfd38c5dbfd7e" # input the encrypted string
deobfuscated_str = deobfuscate_str(enc_string)
print(deobfuscated_str)
