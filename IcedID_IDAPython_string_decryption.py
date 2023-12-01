# Authors: RussianPanda and Jacob Gajek
# Tested on samples:
# 8da8913824dda580cd210f4326a69bca

import idautils
import idc
import idaapi
import ida_ua

def extract_hex_string_until_double_null(address):
    hex_string = ""
    prev_byte = None
    while True:
        byte_value = idc.get_wide_byte(address)
        if byte_value == 0x00 and prev_byte == 0x00:
            break
        hex_string += f"{byte_value:02X}"
        prev_byte = byte_value
        address += 1
    return hex_string

def find_xrefs_and_get_values(address):
    lea_addresses = []
    hex_data_list = []
    for xref in idautils.XrefsTo(address, 0):
        xref_address = xref.frm
        insn = ida_ua.insn_t()
        prev_insn_address = idaapi.decode_prev_insn(insn, xref_address)
        if prev_insn_address != idaapi.BADADDR:
            mnemonic = idc.print_insn_mnem(prev_insn_address)
            if mnemonic == "lea":
                operand_address = idc.get_operand_value(prev_insn_address, 1)
                lea_addresses.append((operand_address, xref_address))
    lea_addresses.sort()
    for i in range(len(lea_addresses)):
        addr, xref_addr = lea_addresses[i]
        end_addr = lea_addresses[i + 1][0] - 1 if i < len(lea_addresses) - 1 else address
        if i >= len(lea_addresses) - 2:
            hex_data = extract_hex_string_until_double_null(addr)
        else:
            size = end_addr - addr + 1
            hex_data = extract_hex_string(addr, size)
        hex_data_list.append((hex_data, xref_addr))
    return hex_data_list

def prng_seed(a1):
    v1 = (((a1 + 11865) << 31 | (a1 + 11865) >> 1) << 31 | (((a1 + 11865) << 31 | (a1 + 11865) >> 1) >> 1)) << 30
    v1 = v1 & ((1 << 64) - 1) # Truncating to 64 bits
    v3 = ((((v1 & 0xFFFFFFFF) | (v1 >> 32)) ^ 0x151D) >> 30) | (4 * (((v1 & 0xFFFFFFFF) | (v1 >> 32)) ^ 0x151D))
    v3 = v3 & ((1 << 32) - 1) # Truncating to 32 bits
    return (v3 >> 31) | (2 * v3) # Final computation and truncation to 32-bit


def nextval(a1):
    # Ensure a1 is treated as a 32-bit unsigned integer
    a1 = a1 & 0xFFFFFFFF
    return prng_seed(a1)  

def decrypt(hex_ciphertext):
    ciphertext = bytes.fromhex(hex_ciphertext)
    v6 = int.from_bytes(ciphertext[:4], 'little') & 0xFFFFFFFF
    v5 = (int.from_bytes(ciphertext[4:6], 'little') ^ int.from_bytes(ciphertext[:2], 'little')) & 0xFFFF
    v7 = ciphertext[6:]
    buffer = bytearray()
    for i in range(v5):
        if i >= len(v7):
            break
        v3 = v7[i]
        v6 = nextval(v6)
        buffer.append((v6 ^ v3) & 0xFF)
    return buffer


def main(target_address):
    hex_data_list = find_xrefs_and_get_values(target_address)
    for hex_data, xref_addr in hex_data_list:
        decrypted_bytes = decrypt(hex_data)
        comment = ""

        try:
            decoded_string = decrypted_bytes.decode("UTF-16LE")
            if decoded_string.isascii():
                # Print the decoded string if it contains only ASCII characters
                print(f"Decrypted string from {xref_addr:#x}: {decoded_string}")
                comment = f"{decoded_string}"
            else:
                # Print the raw bytes if the string contains non-ASCII characters
                print(f"Decrypted string from {xref_addr:#x}: {bytes(decrypted_bytes)}")
                comment = f"{bytes(decrypted_bytes)}"
        except UnicodeDecodeError:
            # Print the raw bytes if there is a UnicodeDecodeError
            print(f"Decrypted string from {xref_addr:#x}: {bytes(decrypted_bytes)}")
            comment = f"{bytes(decrypted_bytes)}"
            
        # Set the comment at the xref address in IDA
        idc.set_cmt(xref_addr, comment, False)
        print(f"Comment set at {xref_addr:#x}: {comment}")
        

if __name__ == "__main__":
    target_address = 0x000000018000A3B4 # decryption address here
    main(target_address)
