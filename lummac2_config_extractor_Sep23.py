# Author: RussianPanda
# Tested on samples:
# 120118e90a4136d604c048644c8ad12a
# eda59d417b01a84cfcddd6c2f89eb925
# 9b7bfa21820626de24db08e807fec382
# 8e73534a56be1e315ace08ec9ee4588c

import re
import pefile
import requests
import base64
import json  
import sys

def seek_and_extract(patterns, data):
    primary_pattern = patterns[0]
    secondary_patterns = patterns[1:]
    results = []

    for match in re.finditer(primary_pattern, data):
        data_start = max(0, match.start() - 100)
        data_end = match.end() + 100
        window = data[data_start:data_end]

        for secondary_pattern in secondary_patterns:
            secondary_matches = re.findall(secondary_pattern, window)
            results.extend(secondary_matches)

    return results

def filter_results(results):
    filtered_results = []
    no_repeat = set()
    for result in results:
        if len(result) > 6 and b'xxxxx' not in result and result not in no_repeat:
            filtered_results.append(result)
            no_repeat.add(result)
    return filtered_results

if len(sys.argv) < 2:
    print("Usage: lummac2_config_extractor_Sep23.py <payload_path>")
    sys.exit(1)

file_path = sys.argv[1]
pe = pefile.PE(file_path)
memory_mapped_image = pe.get_memory_mapped_image()

patterns = [
    re.compile(b'\x78{4}'), 
    re.compile(b'[A-Za-z0-9-]+--[A-Za-z0-9-]+\x00'), 
    re.compile(b'[A-Za-z]{3,}\x00'), 
    re.compile(b'[a-z]+\.[a-z]{2,4}\x00') 
]

results = seek_and_extract(patterns, memory_mapped_image)
filtered_results = filter_results(results)

new_pattern = re.compile(b'[a-fA-F0-9]{32}')
new_results = new_pattern.findall(memory_mapped_image)
filtered_results.extend(filter_results(new_results))

data = {
    'act': 'recive_message',
    'lid': '',
    'j': '',
    'ver': '4.0' # the version can change
}

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cache-Control': 'no-cache',
    'Host': '',
}

for result in filtered_results:
    result_str = result.rstrip(b'\x00').decode('utf-8')
    if 'default' in result_str or re.fullmatch('[a-fA-F0-9]{32}', result_str):
        data['j'] = result_str
        print(f"j: {result_str}")
    elif '.' in result_str:
        if not headers['Host']:
            headers['Host'] = result_str
        data['url'] = result_str
        print(f"C2: {result_str}")
    else:
        data['lid'] = result_str
        print(f"lid: {result_str}")

url = data.pop('url', "")
if url:
    url = "http://" + url + "/api"

session = requests.Session()
session.proxies = {
    'http': '198.49.68.80:80',
    'https': '198.49.68.80:80',
}
try:
    response = session.post(url, headers=headers, data=data, timeout=10)
    
    #print(f"Response Content: {response.text}")

    def xor_decrypt(data, key):
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    
    decoded_data = base64.b64decode(response.text)
    key = decoded_data[:32]
    decrypted_data = xor_decrypt(decoded_data[32:], key)
    decoded_string = decrypted_data.decode('utf-8', errors='replace')  
    data_beautified = json.dumps(json.loads(decoded_string), indent=4)
    print(data_beautified)
except Exception as e:
    print(f"An error occurred: {e}")