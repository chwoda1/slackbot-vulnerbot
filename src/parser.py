import urllib.request
import gzip
import json
import datetime
import re
import sys
import os
import os.path
import time

ip_file = '../ip_addresses'


class Data_Grabber:

    """
        @PARAM self
        @PARAM url is the url to the data path
        @PARAM keywords comes in the format of [MANUFACTURER, THREAT_LEVEL, DATE]

    """

    def snag_json(self, url, keywords):

        holder = []
        container = {}

        try:
            response = urllib.request.urlopen(url)
            values = gzip.decompress(response.read()).decode('utf-8')
            stuff = json.loads(values)
        except BaseException:
            return 'Sorry, there seems to be a problem with the url or your internet connection!'

        for keys in stuff['CVE_Items']:

            if keywords[0] is not None:

                if len(keys['cve']['affects']['vendor']['vendor_data']) != 0:

                    if keys['cve']['affects']['vendor']['vendor_data'][0]['vendor_name'] == keywords[0]:
                        holder = self.grab_data(holder, keys)

            if keywords[1] is not None:

                if keys['impact'] != {}:

                    if keywords[1].upper(
                    ) in keys['impact']['baseMetricV2']['severity']:
                        holder = self.grab_data(holder, keys)

            if keywords[2] is not None:
                print(keywords[2])

        return holder

    """
	@PARAM self
	@PARAM url
	@PARAM text

	@RETURN string to be printed to the end user

    """

    def snag_ip(self, url, text):

        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', text)
        if os.path.exists(ip_file):

            file_age = os.path.getatime(ip_file)
            now = time.time()

            if (file_age - now) > 1300:
                print(requesting)
                response = urllib.request.urlretrieve(url, ip_file)

        else:
            response = urllib.request.urlretrieve(url, ip_file)

        if open(ip_file, 'r').read().find(ip[0]) > 0:

            return 'This IP Address is Suspicious of Performing Illicit Activity'

        else:
            return 'According to my sources this IP is fine. Still use caution!'

    def snag_file(self, url, email):

        response = urllib.request.urlopen(url)
        data = response.read().decode('ascii')

        if email in data:
            return 'That address is likely malicious'

        return 'That email address looks safe!'

    def grab_data(self, holder, keys):

        description = keys['cve']['description']['description_data'][0]['value']
        manufac = keys['cve']['affects']['vendor']['vendor_data'][0]['vendor_name']
        product = keys['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name']
        container = {
            'description': description,
            'manufacturer': manufac,
            'product': product}
        holder.append(container)

        return holder
