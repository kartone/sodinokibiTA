# Testing Malware Bazaar API

import requests
import json
import os, glob
import pyzipper
import ntpath
from argparse import ArgumentParser

ZIP_PASSWORD = b"infected"
EXT_TO_CLEAN = "zip"
KEY = ""
SAMPLES_PATH = ""

def housekeeping(ext):
    try:
        for f in glob.glob(SAMPLES_PATH+'*.'+ext):
            os.remove(f)
    except OSError as e:
        print("Error: %s - %s " % (e.filename, e.strerror))

def get_sample(hash):
    headers = { 'API-KEY': KEY } 
    data = { 'query': 'get_file', 'sha256_hash': hash }
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers, allow_redirects=True)
    with open(SAMPLES_PATH+hash+'.zip', 'wb') as f:
        f.write(response.content)
        print("[+] Sample downloaded successfully")
    with pyzipper.AESZipFile(SAMPLES_PATH+hash+'.zip') as zf:
        zf.extractall(path=SAMPLES_PATH, pwd=ZIP_PASSWORD)
        print("[+] Sample unpacked successfully")

def main():
    parser = ArgumentParser(description="A simple script that will download samples from Malware Bazaar API matching the user defined TAG")
    parser.add_argument("path", help="Path where to save retrieved samples")
    parser.add_argument("-d", "--download", dest="get_sample", help="Download samples from Malware Bazaar", default=False)
    parser.add_argument("-c", "--housecleaning", dest="clean_sample", help="Delete temporary zip files", default =False)
    parser.add_argument("-t", "--tag", dest="tag_sample", help="Tag to search for on Malware Bazaar", default="Sodinokibi")
    parser.add_argument("-k", "--apikey", dest="api_key", help="Malware Bazaar API key")
    args = parser.parse_args()
    # print("arguments:", args)
    
    SAMPLES_PATH = args.path
    
    if args.api_key is not None:
        KEY = args.api_key
    else:
        KEY = os.environ.get("API_KEY")

    downloaded_samples = []
    data = { 'query': 'get_taginfo', 'tag': args.tag_sample }
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data = data, timeout=10)
    maldata = response.json()
    #print(json.dumps(maldata, indent=2, sort_keys=False))
    print("[+] Retrieving the list of downloaded samples...")
    for file in glob.glob(SAMPLES_PATH+'*'):
        filename = ntpath.basename(os.path.splitext(file)[0])
        downloaded_samples.append(filename)
    #print(downloaded_sample)
    print("[+] We have a total of %s samples" % len(downloaded_samples))
    for i in range(len(maldata["data"])):
        if "Decryptor" not in maldata["data"][i]["tags"]:
            for key in maldata["data"][i].keys():
                if key == "sha256_hash":
                    value = maldata["data"][i][key]
                    if value not in downloaded_samples:
                        print("[+] Downloading sample with ", key, "->", value)
                        if args.get_sample:
                            get_sample(value)
                        if args.clean_sample:
                            housekeeping(EXT_TO_CLEAN)
        else:
            print("[+] Skipping the sample because of Tag: Decryptor")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass