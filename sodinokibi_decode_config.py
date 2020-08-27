import os
import sys
import pefile
import hashlib
import scandir
import struct
import json
from Crypto.Cipher import ARC4

excluded_sections = ['.text', '.rdata', '.data', '.reloc', '.rsrc', '.cfg']

def arc4(key, enc_data):
    var = ARC4.new(key)
    dec = var.decrypt(enc_data)
    return dec

def decode_sodinokibi_configuration(filename):
    try:
        with open(filename, "rb") as f:
            bytes = f.read()
            str_hash = hashlib.sha256(bytes).hexdigest()
        pe = pefile.PE(filename)
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            if section_name not in excluded_sections:
                #print(filename)
                #print(section_name)
                data = section.get_data()
                enc_len = struct.unpack('I', data[0x24:0x28])[0]
                dec_data = arc4(data[0:32], data[0x28:enc_len + 0x28])
                parsed = json.loads(dec_data[:-1])
                print("Sample SHA256 Hash: ", str_hash)
                print("Actor ID: ", parsed['pid'])
                print("Campaign ID: ", parsed['sub'])
                # print("Attacker's Public Encryption Key: ", parsed['pk']) 
    except Exception as e:
        print("Skipping file:" + filename + " because of the error: {}".format(e))
        #pass
        
def main():
    if os.path.isdir(sys.argv[1]):
            for root, dirs, files in scandir.walk(sys.argv[1]):
                for file in files:
                    decode_sodinokibi_configuration(os.path.join(root, file))
    else:
        decode_sodinokibi_configuration(sys.argv[1])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass