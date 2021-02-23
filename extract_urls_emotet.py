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
import os
import get_yara_base64
from oledump import oledump
import json
import optparse
import logging

def generateOptions(s='', d=False):
    oParser = optparse.OptionParser(usage='usage: python3 full_emotet.py route_to_doc')
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-s', '--select', default=s, help='select item nr for dumping (a for all)')
    oParser.add_option('-d', '--dump', action='store_true', default=d, help='perform dump')
    oParser.add_option('-x', '--hexdump', action='store_true', default=False, help='perform hex dump')
    oParser.add_option('-a', '--asciidump', action='store_true', default=False, help='perform ascii dump')
    oParser.add_option('-A', '--asciidumprle', action='store_true', default=False, help='perform ascii dump with RLE')
    oParser.add_option('-S', '--strings', action='store_true', default=False, help='perform strings dump')
    oParser.add_option('-T', '--headtail', action='store_true', default=False, help='do head & tail')
    oParser.add_option('-v', '--vbadecompress', action='store_true', default=False, help='VBA decompression')
    oParser.add_option('--vbadecompressskipattributes', action='store_true', default=False, help='VBA decompression, skipping initial attributes')
    oParser.add_option('--vbadecompresscorrupt', action='store_true', default=False, help='VBA decompression, display beginning if corrupted')
    oParser.add_option('-r', '--raw', action='store_true', default=False, help='read raw file (use with options -v or -p')
    oParser.add_option('-t', '--translate', type=str, default='', help='string translation, like utf16 or .decode("utf8")')
    oParser.add_option('-e', '--extract', action='store_true', default=False, help='extract OLE embedded file')
    oParser.add_option('-i', '--info', action='store_true', default=False, help='print extra info for selected item')
    oParser.add_option('-p', '--plugins', type=str, default='', help='plugins to load (separate plugins with a comma , ; @file supported)')
    oParser.add_option('--pluginoptions', type=str, default='', help='options for the plugin')
    oParser.add_option('--plugindir', type=str, default='', help='directory for the plugin')
    oParser.add_option('-q', '--quiet', action='store_true', default=False, help='only print output from plugins')
    oParser.add_option('-y', '--yara', help="YARA rule-file, @file, directory or #rule to check streams (YARA search doesn't work with -s option)")
    oParser.add_option('-D', '--decoders', type=str, default='', help='decoders to load (separate decoders with a comma , ; @file supported)')
    oParser.add_option('--decoderoptions', type=str, default='', help='options for the decoder')
    oParser.add_option('--decoderdir', type=str, default='', help='directory for the decoder')
    oParser.add_option('--yarastrings', action='store_true', default=False, help='Print YARA strings')
    oParser.add_option('-M', '--metadata', action='store_true', default=False, help='Print metadata')
    oParser.add_option('-c', '--calc', action='store_true', default=False, help='Add extra calculated data to output, like hashes')
    oParser.add_option('--decompress', action='store_true', default=False, help='Search for compressed data in the stream and decompress it')
    oParser.add_option('-V', '--verbose', action='store_true', default=False, help='verbose output with decoder errors')
    oParser.add_option('-C', '--cut', type=str, default='', help='cut data')
    oParser.add_option('-E', '--extra', type=str, default='', help='add extra info (environment variable: OLEDUMP_EXTRA)')
    oParser.add_option('--storages', action='store_true', default=False, help='Include storages in report')
    oParser.add_option('-f', '--find', type=str, default='', help='Find D0CF11E0 MAGIC sequence (use l for listing, number for selecting)')
    oParser.add_option('-j', '--jsonoutput', action='store_true', default=False, help='produce json output')
    oParser.add_option('--password', default='infected', help='The ZIP password to be used (default %s)')
    return oParser

def detectURLs(base64):
    if(type(base64) == str):
        logging.debug("Getting largest string from the macro...")
        base64 = base64.split("\\")
        base64 = max(base64, key=len)
        base64_clean, found = get_yara_base64.rev_b64(base64)
        if(base64_clean != '' and len(base64_clean) > 1000):
            decoded = get_yara_base64.find_pattern(base64_clean, found)
            urls = re.findall("http[s]*://[^\']*", decoded)
            if 'httpss' in urls[0]:
                urls[0] = urls[0].replace('https','http')
            print ("URLs Emotet:\n" + re.sub('(\*|\@|\!)', '\n', urls[0]))
            return 0
    return -1

def recurisveLookForStr(base64):
    while(type(base64) != str):
        for s in base64:
            if(type(s) != str):
                if(len(s) != 0):
                    recurisveLookForStr(s)
            else:
                if(detectURLs(s) == 0):
                    exit()
                else:
                    return
        break
    if(detectURLs(base64) == 0):
        exit()
    else:
        return

def main():
    base64_clean = ''
    oParser = generateOptions('', False)
    logging.info("Generating options to oledump...")
    (options, args) = oParser.parse_args()
    if(len(args) != 1):
        print('usage: python3 full_emotet.py route_to_doc')
        exit()
    macros_dump = oledump.OLEDump(args[0], options)
    if(type(macros_dump) == int):
        info.error("Macros does not seem like EmotetDoc.")
        return -1
    logging.info("Looking for macro with obfuscated base64 string...")
    for macro in macros_dump:
        for m in macro:
            if(re.search("data",m, re.IGNORECASE)):
                continue
            oParser = generateOptions(m.split(":")[0], True)
            (options, args) = oParser.parse_args()
            base64 = oledump.OLEDump(args[0], options)
            if(type(base64) != str):
                recurisveLookForStr(base64)
            else:
                if(detectURLs(base64) == 0):
                    return 0
    logging.info("Base64 not found! Maybe this is not EmotetDoc")

if __name__ == '__main__':
    main()
