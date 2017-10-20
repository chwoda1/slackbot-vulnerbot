import sys
sys.path.append('../')
from slackclient import SlackClient
from src import parser
import time
import json
import urllib.request
import re
import gzip
import datetime

slack_token = SlackClient("xoxb-258025611333-yfUqCEH1AQXbe4dydpanhWi6")

nvd_url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz"
autoshun_url = 'https://www.autoshun.org/download/?api_key=7c8cf783819aec76915ac9d1673&format=csv'
junkmail_url = 'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/whitelist.conf'

grabber = parser.Data_Grabber()

user = '<@U7L0RHZ9T>'

def get_channel():
    
    channel_data = slack_token.api_call("channels.list")
    
    return channel_data["channels"][0]["id"] 
 

def init_bot(): 

    if slack_token.rtm_connect():
            
        while True:
         
            get_convo(slack_token.rtm_read())
            time.sleep(1)

    else: 
        print("Connection Failed")
     
def get_convo(data):

    for item in data: 
        
        if item['type'] == 'message' and user in item['text']:           
            reply_user =  '<@'+ item['user'] + '>'
            text = re.sub('<@.{9}>','', item['text'])
            
            get_question(text,reply_user)
            
        
def get_question(text , user): 

    # @TODO question 1) obtain all {low|medium|high} exploitability issues -> Default is High 
    # question 2) obtain all exploits targeting {manufacturer}
    # question 3) is this ip malicious? ~ip~
    # question 4) is this email spam? ~email~
    # question 5) what is your name?

    print(text)

    if re.match(' obtain all (high|medium|low) exploitability issues' , text):
        flag = 1
        date = time.strftime('%Y-%m-%d')
        value = re.compile('(high|medium|low)')    
        
        if value.search(text) == None:
            exploitability = 'high'
        else:
            exploitability = text.split()
            data = exploitability[2]
        
        response = grabber.snag_json(nvd_url,[None,data,None])
   
    elif re.match(' obtain all exploits targeting ([^\s]+)' , text):
        flag = 2
        array = text.split()
        manufacturer = array[4]
        response = grabber.snag_json(nvd_url,[manufacturer,None,None])


    elif re.match(r'( is |)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b (a bad|a malicious|a dangerous) ip\?*', text):
        flag = 3
        print(text)
        response = grabber.snag_ip(autoshun_url,text)
    
    elif re.match('( is |)<mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{1,30})\|' + \
            '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{1,30})>( a)?( spam| malicious| dangerous| junk)( address| email)\?' , text):
        
        flag=4
        domain_name = re.search(r'@([\w.]+)',text)
        response = grabber.snag_file(junkmail_url , domain_name.group(1)) 
        
    elif re.match(' what is your name?' , text):
        flag = 5
        response = 'My name is Vulnerbot!'

    else: 
        response = "I don't know the answer to that Question"
        flag = 6
    
    send_response(response,user,flag)

    
def send_response(text , user,flag): 

    to_send = 'Hi ' + str(user) + '!\n'
    
    if flag == 1:
        
        to_send += json_iterator(text,to_send)

        if len(text) == 0:
            to_send += ' There seems to be no new vulnerabilities posted for the day you queried'

       
    elif flag == 2:
                   
        to_send += json_iterator(text,to_send)

        if len(text) == 0:
            to_send += ' There seems to be no new vulnerabilities posted for the search you queried'


    elif flag == 3:

        to_send += text

    elif flag == 4 :
        
        to_send += text

    elif flag == 5:
        to_send += text
    
    else:
        to_send += text

    slack_message(to_send)


def slack_message(send):
    
    slack_token.api_call(
           'chat.postMessage',
            channel=get_channel(),
            text = send,
            as_user = 'false',
            icon_url = 'http://www.clipartlord.com/wp-content/uploads/2014/09/robot29-201x240.png',
            username = 'vulnerbot'
            )

def json_iterator(text , to_send):
    
    counter = 0
    
    if len(text) < 50:

        for keys in text:
            to_send += "*Description: *" + ' ' + keys['description'] + '\n'
            to_send += "*Manufacturer: *" + ' ' + keys['manufacturer'] + '\n'
            to_send += "*Product: *" + ' ' + keys['product'] + '\n\n'

    else:

        for keys in text:
            to_send += "*Description: *" + ' ' + keys['description'] + '\n'
            to_send += "*Manufacturer: *" + ' ' + keys['manufacturer'] + '\n'
            to_send += "*Product: *" + ' ' + keys['product'] + '\n\n'
            counter += 1

            if counter + 1 == 20: break

    return to_send

def fmt_date(text): 
    print('hi')


init_bot()


