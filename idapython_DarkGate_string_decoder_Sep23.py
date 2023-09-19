# Author: RussianPanda
# Tested on sample: 786486d57e52d2c59f99f841989bfc9d
import idautils
import idc
import ida_bytes

def decode_custom_base64(encoded_bytes, char_map):
    decoded_bytes = bytearray()
    index_map = {char: index for index, char in enumerate(char_map)}

    padding = len(encoded_bytes) % 4
    if padding:
        encoded_bytes += b'\x00' * (4 - padding)
    
    blocks = [encoded_bytes[i:i+4] for i in range(0, len(encoded_bytes), 4)]

    for block in blocks:
        indices = [index_map.get(char, 64) for char in block]

        decoded_bytes.append(((indices[1] & 0x30) >> 4) | ((indices[0] & 0x3F) << 2))
        if indices[2] != 64:
            decoded_bytes.append(((indices[2] & 0x3C) >> 2) | ((indices[1] & 0x0F) << 4))
            if indices[3] != 64:
                decoded_bytes.append((indices[3] & 0x3F) | ((indices[2] & 0x03) << 6))

    return decoded_bytes


ea = 0x004572B0 #change this to the relevant address you have

custom_base64_str_bytes = bytes.fromhex("2CBA7CD1972228A6253B8CAEA93E86ACB1E72EB223B687A3A880A7B5B79E5B8E99CFA18324212AD8265D9F20607E2F3C9CB3AAA429F1B440A25E3AA5895CAF9A")

for ref in idautils.XrefsTo(ea):
  cur_addr = ref.frm
  prev_addr1 = idc.prev_head(cur_addr)
  #print(hex(prev_addr1))
  
  second_operand_value = idc.get_operand_value(prev_addr1, 1)
  if second_operand_value != -1:  
      bytes_content = ida_bytes.get_bytes(second_operand_value, 165)  
      #print(f'Content at {hex(second_operand_value)}: {bytes_content.hex()}')

      encoded_hex_str_bytes = bytes.fromhex(bytes_content.hex())
      decoded_str_bytes = decode_custom_base64(encoded_hex_str_bytes, custom_base64_str_bytes)
      
      decoded_str = decoded_str_bytes.decode('ascii', errors='ignore')
      print(f'Decoded string at {hex(second_operand_value)} : {decoded_str}')
