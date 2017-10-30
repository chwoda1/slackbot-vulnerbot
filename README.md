
### STATUS: [![Build Status](https://travis-ci.org/crw5996/slackbot-vulnerbot.svg?branch=master)](https://travis-ci.org/crw5996/slackbot-vulnerbot)	

## SETUP: 

	To use Vulnerbot you will also need a slack api key. After you generate one enter a shell and run "export API_TOKEN=**YOUR SLACK API TOKEN**"". This is necessary for slack
	interactivity. 

	To setup, simply run the run the shell script named "run" in the root of this directory. It will download all dependencies with it as well. To run the tests
	run the shell script along with a --test flag and you will see the tests pass. 

### USE:
	Currently, vulnerbot can only understand a very small set of commands and is very inflexible. However, this should
	change over time. It currently will answer...
	
	1.) @vulnerbot obtain all {low|medium|high} exploitability issues (if none specified, default is high)
	2.) @vulnerbot obtain all exploits targeting {manufacturers}
	3.) @vulnerbot is this ip malicious? {ip}
	4.) @vulnerbot is this email spam? {email}
	5.) @vulnerbot what is your name? 

### NOTE:
	Starting with four questions, I knew I wanted the first two questions to be in depth, very useful data that may require some reading. 
	If someone was researching apple security flaws or wanted a list of high profile vulnerabilities, they could get a comprehensive list 
	of them quickly using the National Vulnerability Database and Vulnerbot. With the remaining two questions, I wanted them to be a quick yes or no question. Instead of having to run a 
	google search, you could simply type it into a slack message quickly and figure out the information you needed to know. 

	One data set I am looking forward to implementing is the Intel Botnet tracker data feed. Unfortunately the stream is down right now, but I 
	will add it as soon as it's up


