import base64
from binascii import *
import hashlib
import sys
import os
import os.path
import glob
from optparse import OptionParser
from binascii import *
from struct import *
import wincrypto
from wincrypto import CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt


def md5_data(data):
  return hashlib.md5(data).hexdigest()

def xor_two_files(f1, f2):
  r = len(f1)
  if len(f2) < r:
    r = len(f2)
  return ''.join(chr(ord(f1[x]) ^ ord(f2[x])) for x in range(r))


parser = OptionParser()
parser.add_option("-d", "--dir", dest="directory",
                  help="folder to scan for cipher streams")
parser.add_option("-o", "--output", dest="output_directory",
                  help="output folder to store any discovered cipher streams")

(options, args) = parser.parse_args()

if not options.directory:   
  parser.error('Input directory not supplied')

if not options.output_directory:   
  parser.error('Output directory not supplied')

output_dir = options.output_directory

if not os.path.isdir(output_dir):
  os.makedirs(output_dir)
  print(f"[+] Directory {output_dir} does not exist. Creating it.")

streams_0_5 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.0_5")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_0_5.append(fd)

print(f"[+] Pulled {len(streams_0_5)} streams 0-5 from output folder.")

def is_stream_there_0_5(new_stream, size=2048):
  global streams_0_5
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.0_5"
    npath = os.path.join(output_dir, nfile)
    for s in streams_0_5:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (0-5). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_0_5[streams_0_5.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_0_5.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)

streams_5_30 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.5_30")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_0_5.append(fd)

print(f"[+] Pulled {len(streams_5_30)} streams 5-30 from output folder.")

def is_stream_there_5_30(new_stream, size=512):
  global streams_5_30
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.5_30"
    npath = os.path.join(output_dir, nfile)
    for s in streams_5_30:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (5-30). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_5_30[streams_5_30.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_5_30.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)


streams_30_100 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.30_100")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_30_100.append(fd)

print(f"[+] Pulled {len(streams_30_100)} streams 30-100 from output folder.")

def is_stream_there_30_100(new_stream, size=512):
  global streams_30_100
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.30_100"
    npath = os.path.join(output_dir, nfile)
    for s in streams_30_100:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (30-100). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_30_100[streams_30_100.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_30_100.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)


streams_100_300 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.100_300")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_100_300.append(fd)

print(f"[+] Pulled {len(streams_100_300)} streams 100-300 from output folder.")

def is_stream_there_100_300(new_stream, size=512):
  global streams_100_300
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.100_300"
    npath = os.path.join(output_dir, nfile)
    for s in streams_100_300:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (100-300). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_100_300[streams_100_300.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_100_300.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)


streams_300_700 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.300_700")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_300_700.append(fd)

print(f"[+] Pulled {len(streams_300_700)} streams 300-700 from output folder.")

def is_stream_there_300_700(new_stream, size=512):
  global streams_300_700
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.300_700"
    npath = os.path.join(output_dir, nfile)
    for s in streams_300_700:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (300-700). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_300_700[streams_300_700.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_300_700.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)




streams_700_2000 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.700_2000")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_700_2000.append(fd)

print(
    f"[+] Pulled {len(streams_700_2000)} streams 700-2000 from output folder.")

def is_stream_there_700_2000(new_stream, size=512):
  global streams_700_2000
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.700_1000"
    npath = os.path.join(output_dir, nfile)
    for s in streams_700_2000:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (700-2000). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_700_2000[streams_700_2000.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_700_2000.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)


streams_2000_3000 = []

for g in glob.glob(os.path.join(output_dir, "*.stream.2000_3000")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_2000_3000.append(fd)

print(
    f"[+] Pulled {len(streams_2000_3000)} streams 2000-3000 from output folder."
)

def is_stream_there_2000_3000(new_stream, size=512):
  global streams_2000_3000
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.2000_3000"
    npath = os.path.join(output_dir, nfile)
    for s in streams_2000_3000:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (2000-3000). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_2000_3000[streams_2000_3000.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_2000_3000.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)


streams_3000_ = []

for g in glob.glob(os.path.join(output_dir, "*.stream.3000_")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_3000_.append(fd)

print(f"[+] Pulled {len(streams_3000_)} streams 3000- from output folder.")

def is_stream_there_3000_(new_stream, size=512):
  global streams_3000_
  global output_dir
  stream_already_set = False
  if len(new_stream) > size:
    nfile = f"{md5_data(new_stream[:size])}.stream.3000_"
    npath = os.path.join(output_dir, nfile)
    for s in streams_3000_:
      if new_stream[:size] == s[:size]:
        if len(new_stream) > len(s):
          print("[+] Bigger stream found (3000-). Overwriting older one.")
          with open(npath,'wb') as fh:
            fh.write(new_stream)
          streams_3000_[streams_3000_.index(s)] = new_stream
        stream_already_set = True
    if stream_already_set == False:
      print("[+] New stream found.")
      streams_3000_.append(new_stream)
      with open(npath,'wb') as fh:
        print(f"Writing {npath}")
        fh.write(new_stream)



for root, dirs, files in os.walk(options.directory):
  for file in files:
    if file.endswith(".zXz"):
      zxz_file = os.path.join(root, file)
      og_file = zxz_file[:-4]
      if (os.path.isfile(og_file) and os.path.isfile(zxz_file)
          and os.path.getmtime(og_file) < os.path.getmtime(zxz_file)):
        try:
          with open(og_file, 'rb') as fh:
            og_data = fh.read()
          with open(zxz_file, 'rb') as fh:
            zxz_data = fh.read()
          if (len(zxz_data) > 0 and len(og_data) > 0
              and zxz_data[:4] != "\x00\x00\x00\x00"
              and og_data[:4] != "\x00\x00\x00\x00"):
            nstream = xor_two_files(zxz_data, og_data)
            if len(og_data) < (5*1024*1024):
              is_stream_there_0_5(nstream)
            elif len(og_data) < (30*1024*1024):
              is_stream_there_5_30(nstream)
            elif len(og_data) < (100*1024*1024):
              is_stream_there_30_100(nstream)     
            elif len(og_data) < (300*1024*1024):
              is_stream_there_100_300(nstream)   
            elif len(og_data) < (700*1024*1024):
              is_stream_there_300_700(nstream)   
            elif len(og_data) < (2000*1024*1024):
              is_stream_there_700_2000(nstream)   
            elif len(og_data) < (3000*1024*1024):
              is_stream_there_2000_3000(nstream)   
            else:
              is_stream_there_3000_(nstream)
        except Exception as e:
          pass