# Author: RussianPanda
# Tested on samples:
# a0114420ff98f4f09df676527add4ccaaf4326b4bd0c87b153d1ea71adf50022
# 250fe7be536bb8674dd7e0e7c4de2ca1e3311ed657181d950dda6590a3bded51

import re
from dotnetfile import DotNetPE
from base64 import b64decode
from Crypto.Cipher import AES
import argparse
from Crypto.Util.Padding import unpad

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="path of the binary file", required=True)
args = parser.parse_args()

dotnet_file_path = args.file
dotnet_file = DotNetPE(dotnet_file_path)

data = dotnet_file.get_user_stream_strings()

base64_pattern = r"^(?=.{20,})(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
base64_regex = re.compile(base64_pattern)

matches = []
for string in data:
    matches.extend([match.group() for match in base64_regex.finditer(string) if match])

matches_string = ''.join(matches)

decoded_string = b64decode(matches_string).decode('utf-8')

key_pattern = r"\$A\.Key=\@\(\[byte\]([^\)]+)\);"
iv_pattern = r"\$A\.IV=\@\(\[byte\]([^\)]+)\);"
base64_match_after = r"FromBase64String\('([^']+)'\)"
decoy = r"DownloadFile\('([^']+)',.*\)"

key_match = re.search(key_pattern, decoded_string)
iv_match = re.search(iv_pattern, decoded_string)
base64_match = re.search(base64_match_after, decoded_string)
decoy_match = re.search(decoy, decoded_string)


key = key_match.group(1) if key_match else None
IV = iv_match.group(1) if iv_match else None
base64 = base64_match.group(1) if base64_match else None
decoy_url = decoy_match.group(1) if decoy_match else None

print("Key:", key)
print("IV:", IV)
print("Decoy:", decoy_url)

if key and IV:
    key_bytes = bytes([int(i) for i in key.split(',')])
    IV_bytes = bytes([int(i) for i in IV.split(',')])

    encrypted_data = b64decode(base64)

    cipher = AES.new(key_bytes, AES.MODE_CBC, IV_bytes)

    # Decrypt the data 
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    output_path = input("Enter the path where you want to save the decrypted payload: ")

    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
else:
    print("Failed to extract key or IV or encrypted data!")