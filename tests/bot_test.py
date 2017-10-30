import unittest
import sys
sys.path.append('../')

from src import bot


class Bot_Tests(unittest.TestCase):

    def test_get_question(self):

        test_q1 = [

            ' obtain all high exploitability issues',
            ' obtain all HIGH exploitability issues',

            ' obtain all medium exploitability issues',
            ' obtain all MEDIUM exploitability issues',

            ' obtain all low exploitability issues',
            ' obtain all LOW exploitability issues'
        ]

        for item in test_q1:
            flag = bot.get_question(item, 'Chris', debug=True)
            assert flag == 1

        test_q2 = [
            ' obtain all exploits targeting apache,',
            ' obtain all exploits targeting mozilla',
            ' obtain all exploits targeting this_guy',
            ' obtain all exploits targeting apple'
        ]

        for item in test_q2:
            flag = bot.get_question(item, 'Chris' , debug=True)
            assert flag == 2

        test_q3 = [

            ' is 133.133.133.133 a malicious ip?',
            ' is 133.138.12.19 a bad ip?',
            ' is 43.9.8.38 a dangerous ip?'
        ]

        for item in test_q3:
            flag = bot.get_question(item, 'Chris' , debug=True)
            assert flag == 3

        test_q4 = [
            ' is crw5996@protonmail.com a spam email?',
            ' is crw5996@8chan.co a malicious address?',
            ' is sms83@emailengine.net a junk email?',
            ' is ryguy83@fast-email.com a spam email?'
        ]

        for item in test_q4:
            flag = bot.get_question(item, 'Chris' , debug=True)
            assert flag == 4

    def test_json_iterator(self):
        print('')


values = Bot_Tests()

values.test_get_question()
