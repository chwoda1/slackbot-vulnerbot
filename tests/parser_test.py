import sys
sys.path.append('../')
from src import parser

values = parser.Data_Grabber()
array = [10] 
array[0] = 'publishedDate'

keys = [10]
keys[0] = '2017-10'

values.snag_json('https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz', array)
