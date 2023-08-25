# Author: RussianPanda

import requests
import base64
import json  

session = requests.Session()

# Proxies setup
session.proxies = {
    'http': '198.49.68.80:80',
    'https': '198.49.68.80:80',
}

url = input("Please enter the URL to fetch config from (for example: http://URL/c2conf): ")

try:
    response = session.get(url, timeout=10)  # Setting the timeout to 10 seconds

    def xor_decrypt(data, key):
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    decoded_data = base64.b64decode(response.text)
    key = decoded_data[:32]

    decrypted_data = xor_decrypt(decoded_data[32:], key)

    decoded_string = decrypted_data.decode('utf-8', errors='replace')  

    data_beautified = json.dumps(json.loads(decoded_string), indent=4)

    print(data_beautified)

except requests.exceptions.Timeout:
    print("Server is likely down")
