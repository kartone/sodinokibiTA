import requests
import json
import argparse
import logging
import os
import ntpath

def get_logger():
    """
    Configuring the default logger for the project sodinokibiTA
    """
    logger = logging.getLogger('sodinokibiTA')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

"""
def test_logging():
    logger = get_logger()
    logger.debug('debug message')
    logger.info('info message')
    logger.warning('warn message')
    logger.error('error message')
    logger.critical('critical message')
"""

def get_filename(sp):
    ld = []
    for file in os.listdir(sp):
        # Generate file list without extensions inside the supplied path
        ld.append(ntpath.basename(os.path.splitext(file)[0]))
    return ld

def query_vt(sample_list, rp, vt_api_key):
    headers = { 'x-apikey' : vt_api_key }
    # Retrieve the list of saved reports
    data_path = get_filename(rp)
    print(data_path)
    for element in sample_list:
        if element not in data_path:
            url = 'https://www.virustotal.com/api/v3/files/'+element+'/submissions'
            # This input is for debugging purposes and to not waste VT API usage limit
            input('Press any key to query VirusTotal...')
            response = requests.get(url, timeout=10, headers=headers, allow_redirects = True)
            file_path = os.path.join(rp, element)
            with open(file_path, 'wb') as f:
                f.write(response.content)
                print('Report of %s sample saved' % file_path)
        
class Main(object):
    """
    Main class for sodinokibiTA project
    """
    def __init__(self, parser):
        args = parser.parse_args()
        self.vt_api_key = args.vt_api_key
        self.samples_path = args.path
        self.reports_path = args.rpath
        self.logger = get_logger()
        
        if not self.vt_api_key:
            self.vt_api_key = os.environ.get("VT_API_KEY")
            if not self.vt_api_key:
                parser.print_help()
                self.logger.error('[-] No VirusTotal Enterprise API key supplied')

        sl = get_filename(self.samples_path)
        query_vt(sl, self.reports_path, self.vt_api_key)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is the project description')
    parser.add_argument('path', action='store', help='Path to ransomware samples')
    parser.add_argument('rpath', action='store', help='Path to ransomware reports')
    parser.add_argument('-vt', action='store', dest='vt_api_key', required=False, help='VirusTotal Enterprise API Key')
    Main(parser)