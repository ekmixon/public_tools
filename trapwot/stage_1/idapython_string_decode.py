'''

This script finds all references to the string decode function (manually
specified). The string provided as an argument to this function is then decoded
and it's decoded value is then added as a comment. Additionally, the DWORD
storing the decoded function is renamed accordingly.

Example:

	Found XREF: 401d11
	[*] Found encrypted string: jvavarg [0x401d0c] | Decoded: wininet
	Found XREF: 401d29
	[*] Found encrypted string: xreary32 [0x401d22] | Decoded: kernel32
	Found XREF: 401d4b
	[*] Found encrypted string: VagreargBcraN [0x401d46] | Decoded: InternetOpenA
	Found XREF: 401d67
	[*] Found encrypted string: VagreargBcraHeyN [0x401d5d] | Decoded: InternetOpenUrlA
	Found XREF: 401d7d
	[*] Found encrypted string: VagreargErnqSvyr [0x401d73] | Decoded: InternetReadFile
	** Truncated **

Author = Josh Grunzweig [Unit42]
Copyright = 'Copyright 2014, Palo Alto Networks'

'''

def decode(str):
	out = ""
	for x in str:
		o = ord(x)
		if o <= 109 and x.isalpha() and x.islower():
			out += chr(o+13)
		elif o <= 77 and x.isalpha() and x.isupper():
			out += chr(o+13)
		elif o >= 110 and x.isalpha() and x.islower():
			out += chr(o-13)
		elif o >= 78 and x.isalpha() and x.isupper():
			out += chr(o-13)
		else:
			out += x
	return out

# Find all references to the string decode function. This maye need to be
# modified depending on the sample.
xref = XrefsTo(0x00401000,0)
for x in xref:
	print "Found XREF: %x" % x.frm

	heads = Heads(x.frm-12, x.frm)
	string_to_decode = None
	comment_pos = None
	for h in heads:
		if "push" in GetMnem(h):
			str = GetString(GetOperandValue(h,0), -1, ASCSTR_C)
			if str != None:
				string_to_decode = str
				comment_pos = h


	after_heads = Heads(x.frm, x.frm+35)
	dword_to_rename = None
	for h in after_heads:
		if "mov" in GetMnem(h):
			if "dword" in GetOpnd(h,0):
				dword_to_rename = GetOperandValue(h,0)
				print "[*] Found potential DWORD [0x%x]" % dword_to_rename
				break

	if comment_pos:
		decoded_string = decode(string_to_decode)
		print "[*] Found encrypted string: %s [0x%x] | Decoded: %s" % (string_to_decode, comment_pos, decoded_string)
		MakeComm(comment_pos, decoded_string)
		if dword_to_rename:
			print "[*] Renaming DWORD 0x%x to d_%s" % (dword_to_rename, decoded_string)
			MakeName(dword_to_rename, "d_" + decoded_string)
