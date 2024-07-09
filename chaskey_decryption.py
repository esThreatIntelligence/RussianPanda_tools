# Reference: https://github.com/TheWover/donut

import struct

def rol(value, bits, size=32):
    return ((value << bits) & (2**size - 1)) | (value >> (size - bits))

def increment_counter(counter):
    if (counter[3] & 0xFF000000) == 0xFF000000:
        counter[3] = (counter[3] - 0xFEFF0000) & 0xFFFFFFFF
    else:
        counter[3] = (counter[3] + 0x01000000) & 0xFFFFFFFF
        #print(f"Counter new: {counter[3]:08X}")

def decrypt(encrypted_data, key, initial_counter):
    encrypted_bytes = bytes.fromhex(encrypted_data)
    block_size = 16
    counter = initial_counter[:] 
    decrypted_bytes = bytearray()

    while encrypted_bytes:
        block = encrypted_bytes[:block_size]
        encrypted_bytes = encrypted_bytes[block_size:]

        # Prepare the counter
        tmp = counter[:]
        #print("Initial Counter:", ' '.join(f"{x:08X}" for x in tmp))
        for i in range(4):
            tmp[i] ^= key[i]
            #print(f"Counter XOR Key[{i}]: {tmp[i]:08X} (Counter: {counter[i]:08X}, Key: {key[i]:08X})")
        rounds = 16
        for round in range(1, rounds + 1):
            step1 = (tmp[1] + tmp[0]) & 0xFFFFFFFF
            step2 = (tmp[3] + tmp[2]) & 0xFFFFFFFF
            step3 = step1 ^ rol(tmp[1], 5)
            step4 = step2 ^ rol(tmp[3], 8)
            step5 = (step3 + step2) & 0xFFFFFFFF
            tmp[0] = (step4 + rol(step1, 16)) & 0xFFFFFFFF
            tmp[1] = (step5 ^ rol(step3, 7)) & 0xFFFFFFFF
            tmp[3] = (tmp[0] ^ rol(step4, 13)) & 0xFFFFFFFF
            tmp[2] = rol(step5, 16) & 0xFFFFFFFF
            #print(f"Round {round:02}: {tmp[0]:08X} {tmp[1]:08X} {tmp[2]:08X} {tmp[3]:08X}")

            # Generate keystream and decrypt the block for the current round
            round_keystream = struct.pack('<4I', *tmp)
            round_decrypted_bytes = bytearray()
            for i, (keystream_byte, block_byte) in enumerate(zip(round_keystream, block)):
                decrypted_byte = keystream_byte ^ block_byte
                round_decrypted_bytes.append(decrypted_byte)

        for i in range(4):
            tmp[i] ^= key[i]
            #print(f"Final Counter XOR Key[{i}]: {tmp[i]:08X}")

        # Generate final keystream and decrypt the block
        keystream = struct.pack('<4I', *tmp)
        #print("Final Keystream:", keystream.hex())

        for i, (keystream_byte, block_byte) in enumerate(zip(keystream, block)):
            decrypted_byte = keystream_byte ^ block_byte
            decrypted_bytes.append(decrypted_byte)
            #print(f"Decrypting Byte {i}: Keystream {keystream_byte:02X} ^ {block_byte:02X} =  {decrypted_byte:02X}")

        # Increment the counter for the next block
        increment_counter(counter)

    return decrypted_bytes

# Constants (they can be different for each sample)
key = [0x754b8e92, 0xbf825b21, 0xaf9fa7ea, 0xcdc28452]
initial_counter = [0x4731b22d, 0xe2540c9a, 0x09618faa, 0x0891c15e]

encrypted_data = "" # data in hex
decrypted_data = decrypt(encrypted_data, key, initial_counter)
print("Decrypted Data:", decrypted_data.hex())
