# Author: RussianPanda
# Tested on samples:
# 111364143d111f5cf817019e3f74d813705e0a6e7e31bd75adda525caf1280a7
# c576793ee59fee30fe80d7e66b1ba7608f64432a21954ff18f1c71d52417b0bf
# c0a7cbf26f34fbcf29cdafcf393ce4765e3cf6707b65c5023888a52c5bbc9b12
# 1dfca1ff87aa54c7612944ff333fc508d3cad0a21e6c981c0dee3a5d89b7fa1b 
# b803e8d9da6efe7b0220f654c7afb784d21dc222afd4a4e41396e74f861cbf30

import pefile
import re

pattern1 = b'\x00\x00\x00\x47\x00\x45\x00\x54\x00\x00\x00'
sequence1 = b'\x78\x79\x7a\x00\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78'
sequence2 = b'\x69\x6F\x00\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78'
pattern3 = b'\x6C\x69\x64\x3D\x25\x73\x26'
version_pattern = re.compile(b'ver=([\d\.]+)')
build_id_pattern = re.compile(b'\x00([a-zA-Z0-9\-_@]+?)\x00x+')
# New pattern for capturing .io and .xyz domains
domain_match_tld = re.compile(b'([a-zA-Z0-9\-_@]+\.(io|xyz))') # this can change

file_path = input("Please enter the path to the LummaC2 payload: ")

pe = pefile.PE(file_path)

memory_mapped_image = pe.get_memory_mapped_image()

if sequence1 in memory_mapped_image:
    pattern2 = sequence1
elif sequence2 in memory_mapped_image:
    pattern2 = sequence2
else:
    pattern2 = None

def seek_and_extract(pattern, section):
    match = re.search(pattern, section.get_data())
    if match:
        data_start = max(0, match.start() - 100)  # Make sure it doesn't go negative
        data_end = match.end() + 100
        matched_data = section.get_data()[data_start:data_end]
        return matched_data
    return None

domains = set()

def extract_domains(matched_data):
    global build_id_var
    domain_pattern = re.compile(b'\x00([a-zA-Z0-9.-]{5,})\x00.{1,30}\x00([a-zA-Z0-9.-]{5,})\x00')
    domain_match = domain_pattern.search(matched_data)
    if domain_match:
        domain1 = domain_match.group(1).decode('utf-8', errors='ignore')
        domain2 = domain_match.group(2).decode('utf-8', errors='ignore')
 
        # Filter out between C2 and build_id
        if '.' in domain1 and domain1 not in domains:
            print(f"C2: {domain1}")
            domains.add(domain1)
        elif '--' in domain1 or '.' not in domain1 and not build_id_var:
            print(f"Build ID: {domain1}")
            build_id_var = True

        # Only print domain2 if it's different from domain1 and not printed before
        if domain1 != domain2:
            if '.' in domain2 and domain2 not in domains:
                print(f"C2: {domain2}")
                domains.add(domain2)
        elif '--' in domain1 or '.' not in domain1 and not build_id_var:
            if not build_id_var:
                print(f"Build ID: {domain1}")
                build_id_var = True

    
    tld_match = domain_match_tld.search(matched_data)
    if tld_match:
        domain = tld_match.group(1).decode('utf-8', errors='ignore')
        if domain not in domains:
            print(f"C2: {domain}")
            domains.add(domain)

build_id_var = False
matched_one = None
matched_two = None
matched_three = None
build_id_1 = False  #  ensure Build ID is printed only once

for section in pe.sections:
    if not matched_one:
        matched_one = seek_and_extract(pattern1, section)
        if matched_one:
            build_match = build_id_pattern.search(matched_one)
            if build_match and not build_id_var:
                build = build_match.group(1).decode('utf-8', errors='ignore')
                print(f"Build ID: {build}")
                build_id_var = True

    if not matched_two:
        matched_two = seek_and_extract(pattern2, section)
        if matched_two:
            extract_domains(matched_two)

    if not matched_three:
        matched_three = seek_and_extract(pattern3, section)
        if matched_three:
            match_within_pattern_3 = version_pattern.search(matched_three)
            if match_within_pattern_3:
                extracted_string = match_within_pattern_3.group(1).decode('utf-8', errors='ignore')
                print(f"Version: {extracted_string}")

    if matched_one and matched_two:
        break


#if not matched_one:
#    print("pattern1 not found") # pattern1
#if not matched_two:
#   print("pattern2 not found") # pattern2
#if not matched_three:
#    print("pattern3 not found") # pattern3
