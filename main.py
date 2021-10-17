#!/usr/bin/env python3

#######################################
#    Author: Daniel Zajork            #
#    Twitter: @danzajork              #
#######################################


import argparse
import re
import sys
import warnings
import math
from collections import Counter
from itertools import repeat
from math import log2
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import *
import json

import htmlmin
import urllib3
import requests
import termcolor
from bs4 import BeautifulSoup

parse = argparse.ArgumentParser()
parse.add_argument('-l', '--listfile', help="List file which contain list of URLs to be scanned for secrets.")
parse.add_argument('-u', '--url', help="Enter the URL in which you want to find secrets.")
parse.add_argument('-d', '--disable_entropy', help="Disable high entropy checks.")

args = parse.parse_args()
url = args.url
listfile = args.listfile
disable_entropy = args.disable_entropy

isSSL = True
jsLinkList = list()
jsname = list()
finalset = set()

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

rules = {}
regexes = {}

heads = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 'Cache-Control': 'no-cache'}

def get_urls_from_file():
    with open(args.listfile, 'rt') as f:
        urllst = f.readlines()
    urllst = [x.strip() for x in urllst if x != '']
    urllst = set(urllst)
    return urllst


class JsExtract:
    def IntJsExtract(self, url, heads):
        try:
            if url.startswith('http://') or url.startswith('https://'):
                if isSSL:
                    req = requests.get(url, headers=heads, verify=False, timeout=15, allow_redirects=False)
                else:
                    req = requests.get(url, headers=heads, timeout=15, allow_redirects=False)
            else:
                if isSSL:
                    req = requests.get(
                        'http://' + url, headers=heads, verify=False, timeout=15, allow_redirects=False)
                else:
                    req = requests.get('http://' + url, headers=heads, timeout=15, allow_redirects=False)

            print(termcolor.colored("Searching for Inline Javascripts.....",
                                    color='yellow', attrs=['bold']))

            try:
                html = unquote(req.content.decode('unicode-escape'))
                minhtml = htmlmin.minify(html, remove_empty_space=True)
                minhtml = minhtml.replace('\n', '')
                jsLinkList.append((url, minhtml))
                print(termcolor.colored(
                    "Successfully got all the Inline Scripts.", color='blue', attrs=['bold']))
            except UnicodeDecodeError:
                print(termcolor.colored("Decoding error...",
                                        color='red', attrs=['bold']))
        except Exception as ex:
            print("Error, continuing...")


    def ExtJsExtract(self, url, heads):
        print(termcolor.colored(
            "Searching for External Javascript links in page.....", color='yellow', attrs=['bold']))
        try:
            if url.startswith('http://') or url.startswith('https://'):
                if isSSL:
                    req = requests.get(url, headers=heads, verify=False, timeout=15, allow_redirects=False)
                else:
                    req = requests.get(url, headers=heads, timeout=15, allow_redirects=False)
            else:
                if isSSL:
                    req = requests.get(
                        'http://' + url, headers=heads, verify=False, timeout=15, allow_redirects=False)
                else:
                    req = requests.get('http://' + url, headers=heads, timeout=15, allow_redirects=False)
            try:
                html = unquote(req.content.decode('unicode-escape'))
                soup = BeautifulSoup(html, features='html.parser')

                for link in soup.find_all('script'):
                    if link.get('src'):
                        extracted_url = urljoin(url, link.get('src'))

                        if isSSL:
                            content = unquote(requests.get(
                                extracted_url, verify=False, timeout=15).content.decode('utf-8'))
                        else:
                            content = unquote(requests.get(extracted_url, timeout=15).content.decode('utf-8'))

                        jsLinkList.append((extracted_url, content))
                print(termcolor.colored("Successfully got all the external js links", color='blue', attrs=['bold']))
            except UnicodeDecodeError:
                print("Decoding error, continuing...")
        except:
            print("Error, continuing...")


def logo():
    return r"""
  __                 _____  _____.__              ____. _________
_/  |________ __ ___/ ____\/ ____\  |   ____     |    |/   _____/
\   __\_  __ \  |  \   __\\   __\|  | _/ __ \    |    |\_____  \ 
 |  |  |  | \/  |  /|  |   |  |  |  |_\  ___//\__|    |/        \
 |__|  |__|  |____/ |__|   |__|  |____/\___  >________/_______  /
                                           \/                 \/                                                                                                                                       
Find secrets hidden in the depths of JavaScript.
"""

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_results(printJson, issue):
    printableDiff = issue['printDiff']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)
        print(printableDiff)
        print("~~~~~~~~~~~~~~~~~~~~~")


def find_entropy(printableDiff, url):
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    printableDiff = bcolors.WARNING + string + bcolors.ENDC
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    printableDiff = bcolors.WARNING + string + bcolors.ENDC
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['path'] = url
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = printableDiff
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff

def regex_check(printableDiff, url):
    secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, bcolors.WARNING + str(found_string) + bcolors.ENDC)
        if found_strings:
            foundRegex = {}
            foundRegex['path'] = url
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            regex_matches.append(foundRegex)
    return regex_matches


def find_secrets(url_content):

    if disable_entropy is None:
        entropicDiff = find_entropy(url_content[1], url_content[0])
        if entropicDiff:
            print_results(False, entropicDiff)

    found_regexes = regex_check(url_content[1], url_content[0])
    for issue in found_regexes:
        print_results(False, issue)
    

def process_url(url):
    jsfile = JsExtract()
    jsfile.IntJsExtract(url, heads)
    jsfile.ExtJsExtract(url, heads)
    
    print(termcolor.colored("Finding secrets in all Javascript files...",
                        color='yellow',
                        attrs=['bold']))

    for url_content in jsLinkList:
        find_secrets(url_content) 
    
    jsLinkList.clear()
    print(termcolor.colored("Searching completed...", color='blue', attrs=['bold']))

def print_logo():
    return termcolor.colored(logo(), color='white', attrs=['bold'])

if __name__ == "__main__":

    domainSet = set()
    print(print_logo())

    try:
        with open("rules.json", "r") as ruleFile:
            rules = json.loads(ruleFile.read())
            for rule in rules:
                rules[rule] = re.compile(rules[rule])
    except (IOError, ValueError) as e:
        raise("Error reading rules file")
    for regex in dict(regexes):
        del regexes[regex]
    for regex in rules:
        regexes[regex] = rules[regex]

    # disable insecure ssl warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if listfile:
        urllist = get_urls_from_file()
        if urllist:
            for i in urllist:
                print(termcolor.colored("Extracting data from internal and external js for url:", color='blue',
                                        attrs=['bold']))
                print(termcolor.colored(
                    i, color='red', attrs=['bold']))
                try:
                    try:
                        process_url(i)
                    except requests.exceptions.ConnectionError:
                        print(
                            'An error occured while fetching URL, Might be URL is wrong, Please check!')
                except requests.exceptions.InvalidSchema:
                    print("Invalid Schema Provided!")
                    sys.exit(1)
    else:
        try:
            try:
                process_url(url)
            except requests.exceptions.ConnectionError:
                print(
                    termcolor.colored(
                        'An error occured while fetching URL, one or more of following are possibilities:'
                        '\n1. Might be server is down.\n2. SSL certificate issue.\n3. Domain does not exist. \nPlease check properly or try \'-k\' option, to disable SSL certificate verification.',
                        color='yellow', attrs=['bold']))
                sys.exit(1)
        except requests.exceptions.InvalidSchema:
            print("Invalid Schema Provided!")
            sys.exit(1)