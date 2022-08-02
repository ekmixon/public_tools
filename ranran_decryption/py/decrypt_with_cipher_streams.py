import base64
from binascii import *
import hashlib
import sys
import os
import os.path
from optparse import OptionParser
from binascii import *
from struct import *
import glob


def xor_two_files(f1, f2):
  r = len(f1)
  if len(f2) < r:
    r = len(f2)
  return ''.join(chr(ord(f1[x]) ^ ord(f2[x])) for x in range(r))


parser = OptionParser()
parser.add_option("-d", "--dir", dest="directory",
                  help="decrypt specified directory")
parser.add_option("-i", "--stream-dir", dest="stream_directory",
                  help="input for collected cipher streams")

(options, args) = parser.parse_args()

if not options.directory:   
  parser.error('Decrypt directory not supplied')

if not options.stream_directory:   
  parser.error('Cipher stream directory not supplied')

decrypt_directory = options.directory
stream_directory = options.stream_directory

if not os.path.isdir(stream_directory):
  print("[*] Cipher stream directory doesn't exist. Exiting now.")
  sys.exit(1)

streams_0_5 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.0_5")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_0_5.append(fd)

print(f"[+] Pulled {len(streams_0_5)} streams 0-5 from output folder.")

streams_5_30 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.5_30")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_5_30.append(fd)

print(f"[+] Pulled {len(streams_5_30)} streams 5-30 from output folder.")

streams_30_100 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.30_100")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_30_100.append(fd)

print(f"[+] Pulled {len(streams_30_100)} streams 30-100 from output folder.")

streams_100_300 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.100_300")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_100_300.append(fd)

print(f"[+] Pulled {len(streams_100_300)} streams 100-300 from output folder.")


streams_300_700 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.300_700")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_300_700.append(fd)

print(f"[+] Pulled {len(streams_300_700)} streams 300-700 from output folder.")


streams_700_2000 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.700_2000")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_700_2000.append(fd)

print(
    f"[+] Pulled {len(streams_700_2000)} streams 700-2000 from output folder.")


streams_2000_3000 = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.2000_3000")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_2000_3000.append(fd)

print(
    f"[+] Pulled {len(streams_2000_3000)} streams 2000-3000 from output folder."
)


streams_3000_ = []

for g in glob.glob(os.path.join(stream_directory, "*.stream.3000_")):
  with open(g, 'rb') as f:
    fd = f.read()
  streams_3000_.append(fd)

print(f"[+] Pulled {len(streams_3000_)} streams 3000- from output folder.")


def decrypt_file_with_stream(zxz_file, streams):
  og_prefix = zxz_file.split(".")[-2]
  for c, stream in enumerate(streams):
    nfile = f"{zxz_file}.{str(c)}.{og_prefix}"
    with open(nfile, 'wb') as nfh:
      with open(zxz_file, 'rb') as ofh:
        zxz_data = ofh.read()
      nfh.write(xor_two_files(zxz_data, stream))
    print(f"[+] Wrote {nfile}")


for root, dirs, files in os.walk(options.directory):
  for file in files:
    if file.endswith(".zXz"):
      zxz_file = os.path.join(root, file)
      try:
        with open(zxz_file, 'rb') as fh:
          zxz_data = fh.read()
        if len(zxz_data) > 0 and zxz_data[:4] != "\x00\x00\x00\x00":
          if len(zxz_data) < (5*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_0_5)
          elif len(zxz_data) < (30*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_5_30)
          elif len(zxz_data) < (100*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_30_100)    
          elif len(zxz_data) < (300*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_100_300)
          elif len(zxz_data) < (700*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_300_700) 
          elif len(zxz_data) < (2000*1024*1024):
            decrypt_file_with_stream(zxz_file, streams_700_2000) 
          elif len(zxz_data) < (3000*1024*1024):
            idecrypt_file_with_stream(zxz_file, streams_2000_3000)  
          else:
            decrypt_file_with_stream(zxz_file, streams_3000_)
      except Exception as e:
        pass