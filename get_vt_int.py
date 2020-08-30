import requests
import json
import argparse
import os
import ntpath
import shutil as sh
import datetime
import hashlib
import pefile
import struct
import pandas as pd
from Crypto.Cipher import ARC4
from opencage.geocoder import OpenCageGeocode
from pathlib import Path

excluded_sections = ['.text', '.rdata', '.data', '.reloc', '.rsrc', '.cfg']

def arc4(key, enc_data):
    var = ARC4.new(key)
    dec = var.decrypt(enc_data)
    return dec

def decode_sodinokibi_configuration(f):
    filename = os.path.join('./samples', f)
    filename += '.exe'
    with open(filename, "rb") as file:
        bytes = file.read()
        str_hash = hashlib.sha256(bytes).hexdigest()
    pe = pefile.PE(filename)
    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        if section_name not in excluded_sections:
            data = section.get_data()
            enc_len = struct.unpack('I', data[0x24:0x28])[0]
            dec_data = arc4(data[0:32], data[0x28:enc_len + 0x28])
            parsed = json.loads(dec_data[:-1])
            return str_hash, parsed['pid'], parsed['sub']
            #print("Sample SHA256 Hash: ", str_hash)
            #print("Actor ID: ", parsed['pid'])
            #print("Campaign ID: ", parsed['sub'])
            #print("Attacker's Public Encryption Key: ", parsed['pk']) 

def get_filename(path):
    items = []
    for file in os.listdir(path):
        # Generate file list without extensions inside the supplied path
        items.append(ntpath.basename(os.path.splitext(file)[0]))
    return items

def query_vt(sample_list, rp, vt_api_key):
    headers = { 'x-apikey' : vt_api_key }
    # Retrieve the list of saved reports in ./data path
    data_path = get_filename(rp)
    for element in sample_list:
        # Do not query VT for a saved report
        if element not in data_path:
            url = 'https://www.virustotal.com/api/v3/files/'+element+'/submissions'
            # This input is for debugging purposes and to not waste VT API usage limit
            input('Press any key to query VirusTotal Enterprise API backend...')
            response = requests.get(url, timeout=10, headers=headers, allow_redirects = True)
            file_path = os.path.join(rp, element)
            with open(file_path, 'wb') as f:
                f.write(response.content)
                print('Report of %s sample saved' % file_path)

def parse_vt_report(vt_reports, rp, sp, gc):
    attacks = []
    for rpt in vt_reports:
        report_path = os.path.join(rp, rpt)
        with open(report_path) as json_file:
            report = json.load(json_file)
            for i in range(len(report["data"])):
                for j in report["data"][i].keys():
                    if j == 'attributes':
                        city = report["data"][i][j].get('city')
                        country = report["data"][i][j].get('country')
                        timestamp = report["data"][i][j].get('date')
                        print("[+] Decoding ransomware configuration from sample {}".format(rpt))
                        sample_hash, aID, cID = decode_sodinokibi_configuration(rpt)
                        print("[+] Getting coordinates for city: {} in country {}".format(city, country))
                        result = gc.geocode(city, limit=1, countrycode=country, no_annotation=1)
                        if not result:
                            print('[-] Coordinates for city:{}, country:{} not found'.format(city, country))
                        else:
                            lat = result[0]['geometry']['lat']
                            lng = result[0]['geometry']['lng']
                            attack = { 'country': country, 'city': city, 'latitude': lat, 'longitude': lng, 'aid': aID, 'cid': cID, 'hash': sample_hash, 'timestamp': timestamp }
                            attacks.append(attack)
    return attacks

def dump_data(attacks, pd):
    df = pd.DataFrame(attacks)
    print(df)
    dumped_df = './data.csv'
    backup_df = './data.bak'
    if Path(dumped_df).is_file():
        sh.copy2(dumped_df, backup_df)
        df.to_csv(dumped_df, index=False)
    else:
        df.to_csv(dumped_df, index=False)

# local_datetime_converted = datetime.datetime.fromtimestamp(UTC_datetime_timestamp)

class Main(object):
    """
    Main class for sodinokibiTA project
    """
    def __init__(self, parser):
        args = parser.parse_args()
        self.vt_api_key = args.vt_api_key
        self.oc_api_key = args.oc_api_key
        self.samples_path = args.spath
        self.reports_path = args.rpath
        
        if not self.vt_api_key:
            self.vt_api_key = os.environ.get("VT_API_KEY")
            if not self.vt_api_key:
                parser.print_help()
                self.logger.error('[-] No VirusTotal Enterprise API key supplied')
        
        if not self.oc_api_key:
            self.oc_api_key = os.environ.get("OC_API_KEY")
            if not self.oc_api_key:
                parser.print_help()
                self.logger.error('[-] No OpenCage API key supplied')

        gc = OpenCageGeocode(self.oc_api_key)

        sl = get_filename(self.samples_path)
        # Comment this line if you do want to query VirusTotal
        query_vt(sl, self.reports_path, self.vt_api_key)
        rl = get_filename(self.reports_path)
        attacks = parse_vt_report(rl, self.reports_path, self.samples_path, gc)
        dump_data(attacks,pd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Project Sodinokibi')
    parser.add_argument('spath', action='store', help='Path to ransomware samples', default='./samples')
    parser.add_argument('rpath', action='store', help='Path to ransomware reports', default='./data')
    parser.add_argument('-vt', action='store', dest='vt_api_key', required=False, help='VirusTotal Enterprise API Key')
    parser.add_argument('-oc', action='store', dest='oc_api_key', required=False, help='OpenCage API Key')
    Main(parser)