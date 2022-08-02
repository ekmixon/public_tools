# Author: Josh Grunzweig, Unit 42
# Description: Attempts to extract macros and decode embedded strings. These
# macros make use of a UAC bypass technique. Script relies on the accompanying
# olevba.py script included. 
# Reference: https://github.com/pan-unit42/public_tools/blob/master/macro_loader/macro_decode.py

import sys, re
from olevba import VBA_Parser, filter_vba


def get_macros(path):
	try:
		vba = VBA_Parser(path)
	except Exception as e:
		print("[-] Error parsing VBA")
		print(e.message)
		return
	if vba.detect_vba_macros():
		c = 1
		for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
			vba_code = filter_vba(vba_code)
			if vba_code.strip() != '':
				parse_macro(vba_code)
				with open(f"{str(c)}.vba", 'wb') as fh:
					fh.write(vba_code)
				c += 1


def decode(blacklist, string):
	return "".join(c for c in string if c not in blacklist)


def get_blacklist(macro_data):
	blacklist = None
	if r := re.search("\"(\w+)\"\s+Like\s+", macro_data, flags=re.IGNORECASE):
		print("[+] Found blacklist using Like method.")
		blacklist = r[1]
	else:
		print("[-] Blacklist not found via Like method. Checking for InStrRev().")
		if r := re.search(
			"\w+\s*\=\s*InStrRev\(\s*\"([^\"]+)\"", macro_data, flags=re.IGNORECASE
		):
			blacklist = r[1]
		else:
			print("[-] Variable not found via InStrRev method (1).")
			if r := re.search(
				"\w+\s*\=\s*InStrRev\(\s*(\S+)\s*,", macro_data, flags=re.IGNORECASE
			):
				print("[+] Variable found via InStrRev method (2).")
				var_search = f'{r[1]}\s*\=\s*\"([^\"]+)\"'
				if r2 := re.search(var_search, macro_data, flags=re.IGNORECASE):
					print("[+] Blacklist found via InStrRev method (2).")
					blacklist = r2[1]
				else:
					print("[-] Blacklist not found via InStrRev method (2).")
			else:
				print("[-] Variable not found via InStrRev method (2).")
	return blacklist

		
def parse_macro(macro_data):
	if not (blacklist := get_blacklist(macro_data)):
		return
	print(f"[+] Blacklist string: {blacklist}")
	all_strings = re.findall("\"([^\"\n]+)\"", macro_data)
	relevant_strings = []
	for string in all_strings:
		all_bl_chars = [c for c in string if c in blacklist]
		if (float(len(all_bl_chars)) / len(string)) > 0.50 and string != blacklist:
			relevant_strings.append(string)
	for c, string in enumerate(relevant_strings, start=1):
		print(f"[+] Segment #{c}")
		print(decode(blacklist, string))


get_macros(sys.argv[1])