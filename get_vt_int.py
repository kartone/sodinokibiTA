import requests
import json
import argparse
import logging
import os

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

class Main(object):
    """
    Main class
    """
    def __init__(self, parser):
        args = parser.parse_args()
        self.vt_api_key=args.vt_api_key
        self.logger = get_logger()
        
        if not self.vt_api_key:
            self.vt_api_key = os.environ.get("VT_API_KEY")
            if not self.vt_api_key:
                parser.print_help()
                self.logger.error('[-] No VirusTotal Enterprise API key supplied')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is the project description')
    parser.add_argument('-vt', action='store', dest='vt_api_key', required=False, help='VirusTotal Enterprise API Key')
    Main(parser)