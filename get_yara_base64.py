#!/usr/bin/env python
# -*- coding: utf-8 -*-


from collections import defaultdict
from operator import itemgetter
from yara import compile
import base64
import re
import string
import argparse
import sys
import logging

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="[%(asctime)s][%(levelname)s]: %(message)s")

_R_BASE64 = """
rule contentis_base64 : Base64
{
    meta:
        author = "Jaume Martin"
        description = "This rule finds for base64 strings"
        version = "0.2"
        notes = "https://github.com/Yara-Rules/rules/issues/153"
    strings:
        $a = /([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
    condition:
        $a
}
"""
def run_yara(rule_code, buffer_to_sample) :
    try :
        yar_object = compile(source = rule_code)
        matches = yar_object.match(data = buffer_to_sample)

    except Exception as Exception_Error :
        print("%s", (Exception_Error))
        return(False)

    if(len(matches)) != 0 :
        return(matches)
    return(False)

def naive(s, X):
    freq = defaultdict(int)
    for i in range(len(s) - X + 1):
        freq[s[i:i+X]] += 1
    return max(freq.items(), key=itemgetter(1))

def rev_b64(base64):
    found = True
    base64 = re.sub(r"^b\'\\x.*\\x[0-9]{1,2}((?!\\x))", '', base64)
    base64_rev1 = "".join(re.findall(".*BAJ", base64))
    base64_rev2 = "".join(re.findall(".*AAP", base64))
    base64_rev3 = "".join(re.findall(".*AAI", base64))
    if(len(base64_rev2) > len(base64_rev1)):
        if(len(base64_rev3) > len(base64_rev2)):
            base64_rev = base64_rev3
        else:
            base64_rev = base64_rev2
    else:
        if(len(base64_rev3) > len(base64_rev1)):
            base64_rev = base64_rev3
        else:
            base64_rev = base64_rev1
    base64_1 = "".join(re.findall("JAB.*", base64))
    base64_2 = "".join(re.findall("PAA.*", base64))
    base64_3 = "".join(re.findall("IAA.*", base64))
    if(len(base64_2) != 0 or len(base64_1) != 0):
        if(len(base64_2) > len(base64_1)):
            if(len(base64_3)> len(base64_2)):
                base64 = base64_3
            else:
                base64 = base64_2
        else:
            if(len(base64_3)> len(base64_1)):
                base64 = base64_3
            else:
                base64 = base64_1
    else:
        found = False
    base64_clean = re.sub(r"\\x[0-9]{1,2}.*", '', base64)
    base64_clean = base64_clean.replace('\\r\\n', '')
    logging.debug(f"Base64 found: {base64_clean}")
    if found:
        logging.info("Base64 found!")
    return base64_clean, found

def find_pattern(obfuscated_pwsh_clean, found=True):
    resources_emotet = ''
    base64_string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/="
    signature = run_yara(_R_BASE64, obfuscated_pwsh_clean)
    logging.info("Checking base64 provided...")
    if signature != False and len(obfuscated_pwsh_clean) % 4 == 0:
        test = "".join(filter(lambda x: x in string.printable, base64.b64decode(obfuscated_pwsh_clean).decode('utf-8', 'ignore')))
        if(re.search("http", test, re.IGNORECASE) != None):
            logging.info("URLs found!")
            return "".join(filter(lambda x: x in string.printable, base64.b64decode(obfuscated_pwsh_clean).decode('utf-8', 'ignore')))
    logging.debug(f"Base64 provided: {obfuscated_pwsh_clean}")
    logging.info("Looking for pattern...")
    for noise_substr_len in range(2,30):
        noise_substr = naive(obfuscated_pwsh_clean, noise_substr_len)
        logging.debug(f"Pattern: {noise_substr}")
        try:
            logging.debug(f"Trying to replace pattern {noise_substr}")
            pwsh_b64 = obfuscated_pwsh_clean.replace(noise_substr[0],"")
            while noise_substr[0] in pwsh_b64:
                pwsh_b64 = pwsh_b64.replace(noise_substr[0],"")
            if found == False:
                b64, found = rev_b64(pwsh_b64)
                if found == False:
                    continue
                else:
                    pwsh_b64 = b64
            pwsh_b64 = "".join(filter(lambda x: x in base64_string, pwsh_b64))
            if "=" in pwsh_b64:
                pwsh_b64 = "".join(re.findall(".*\=", pwsh_b64))
            logging.info("Adjusting base64 padding...")
            while(len(pwsh_b64) % 4 != 0):
                pwsh_b64 = pwsh_b64[:-1]
            signature = run_yara(_R_BASE64, pwsh_b64)
            if signature != False and len(pwsh_b64) > 800:
                resources_emotet = "".join(filter(lambda x: x in string.printable, base64.b64decode(pwsh_b64).decode('utf-8', 'ignore')))
                urls = [""]
                urls[0] = resources_emotet
                logging.info("Cleaning base64...")
                if "'+'" in resources_emotet:
                    resources_emotet = resources_emotet.replace("(","")
                    resources_emotet = resources_emotet.replace(")","")
                    resources_emotet = resources_emotet.replace("'+'","")
                    resources_emotet = resources_emotet.replace("' + '","")
                    logging.debug(f"Emotet resources: {resources_emotet}")
                    urls = re.findall("http[s]*[^\']*", resources_emotet)
                    if len(urls) == 0:
                        continue
                    if len(urls[0]) < 150:
                        logging.debug("IF URLS")
                        urls = re.findall("[\@,\*,\!].*[^\'].*", resources_emotet)
                    logging.debug(f"Resources emotet: {urls[0]}")
                for noise_substr_len in range(2,30):
                    noise_substr = naive(urls[0], noise_substr_len)
                    extract_urls = urls[0]
                    count = 0
                    while noise_substr[0] in extract_urls:
                        if "://" not in extract_urls:
                            logging.debug("No / present in URLs")
                            extract_urls = extract_urls.replace(noise_substr[0],"/")
                            logging.debug(f"Extracted URLs: {extract_urls}")
                        elif ("ttps:" not in extract_urls or "ttp:" not in extract_urls) and "://" not in extract_urls:
                            logging.debug("No : present in URLs")
                            extract_urls = extract_urls.replace(noise_substr[0],":")
                            logging.debug(f"Extracted URLs: {extract_urls}")
                        else:
                            logging.debug("No http present in URLs")
                            extract_urls = extract_urls.replace(noise_substr[0],"http")
                        if "http://" in extract_urls or "https://" in extract_urls:
                            return extract_urls
                        count+=1
                        if count == 10:
                            break
                if re.search("\@http", resources_emotet, re.IGNORECASE) != None or re.search("\*http", resources_emotet, re.IGNORECASE) != None or re.search("\!http", resources_emotet, re.IGNORECASE) != None:
                    logging.debug(f"Final emotet resources: {resources_emotet}")
                    return resources_emotet
        except TypeError as e:
            print(e)
            continue

def main():
    parser = argparse.ArgumentParser(
        description = "Detect pattern ofuscation. ")
    parser.add_argument('base64', type=str,
        help = 'Base64 ofuscated')
    parser.add_argument('rev', type=int,
        help = 'Reverse string or not')
    args = parser.parse_args()
    obfuscated_pwsh_clean = args.base64
    if args.rev == 1:
        a = find_pattern(''.join(reversed(obfuscated_pwsh_clean)))
        print(a)
        return a
    else:
        b = find_pattern(obfuscated_pwsh_clean)
        print(b)
        return b

if __name__ == '__main__':
    main()
