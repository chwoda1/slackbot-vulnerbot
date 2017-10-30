import sys
import unittest
sys.path.append('../')
from src import parser

import urllib.request
import gzip
import json


class Data_Grabber_Test(unittest.TestCase):

    snagger = parser.Data_Grabber()
    nvd_url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz"
    autoshun_url = 'https://www.autoshun.org/download/?api_key=7c8cf783819aec76915ac9d1673&format=csv'
    junkmail_url = 'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/whitelist.conf'

    def test_snag_json(self):
        data1 = self.snagger.snag_json(nvd_url , ['microsoft' , None , None])
        data2 = self.snagger.snag_json(nvd_url , [None , 'HIGH' , None])


    def test_snag_ip(self):

        test1 = [
            '2.32.152.144',     # actually in list
            '221.229.166.104',  # actually in list
            '23.234.52.20'      # actually in list
        ]

        test2 = [
            '2.33.153.144',     # random ip
            '100.6.59.135',     # random ip
            '1.1.1.1',          # invalid ip
            '100.168.174.183'   # random ip
        ]

        for ip in test1:
                value = self.snagger.snag_ip(self.autoshun_url , ip)
                assert value , 'This IP Address is Suspicious of Performing Illicit Activity'

        for ip in test2:
                value = self.snagger.snag_ip(self.autoshun_url , ip)
                assert value , 'According to my sources this IP is fine. Still use caution!'

    def test_snag_file(self):

        response = urllib.request.urlopen(self.junkmail_url)

        data = response.read().decode('ascii')
        good_emails = [
                'chris@aol.com',
                'jeff@gmail.com',
                'owen@comcast.net'
                ]

        bad_emails = [
                'chris@8chan.co',
                'jeff@speedpost.net',
                'owen@yeah.net'
                ]

        for emails in bad_emails:
                values = self.snagger.snag_file(self.junkmail_url , emails)
                assert values , 'That address is likely malicious'

        for emails in good_emails:
                values = self.snagger.snag_file(self.junkmail_url , emails)
                assert values ,'That email address looks safe!'


    def test_grab_data(self):
        print('hey')


data = Data_Grabber_Test()

data.test_snag_ip()
print("Snag IP Test Passed")

data.test_snag_file()
print("Snag File Test Passed")
