# Author: RussianPanda

import os
import pefile
from murmurhash2 import murmurhash2

SYSTEM32_PATH = os.path.join(os.environ['WINDIR'], 'System32')
DLL_NAMES = ['crypt32.dll', 'kernel32.dll', 'ntdll.dll', 'winhttp.dll', 'advapi32.dll', 'user32.dll', 'wininet.dll', 'mscoree.dll']

DLL_PATHS = [os.path.join(SYSTEM32_PATH, dll_name) for dll_name in DLL_NAMES]

SEED = 0x20

def compute_hashes_for_dlls(dll_path):
    pe = pefile.PE(dll_path)
    computed_hashes = {}
    
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        try:
            expName = export.name.decode()
            hashValue = murmurhash2(expName.encode('utf-8'), SEED)
            computed_hashes[expName] = hex(hashValue)
        except AttributeError:
            continue
            
    return computed_hashes

output_file_path = input("Enter the full path where you want to save the output: ")
output_file = open(output_file_path, "w")

for dll_path in DLL_PATHS:
    if os.path.exists(dll_path):
        hashes = compute_hashes_for_dlls(dll_path)
        for api, hash_val in hashes.items():
            output_file.write(f'{api} - {hash_val}\n')  
        output_file.write('-' * 60 + '\n') 
    else:
        print(f"{dll_path} not found!")

output_file.close()

print(f"Success! Hashes values saved to {output_file_path}")
