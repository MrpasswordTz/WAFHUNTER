import os
import sys
import socket
import re
from wafsig import*
from colorama import Fore
import ssl
import urllib.parse

banner = Fore.GREEN +'''


 _    _  ___  ______ _                 _            
| |  | |/ _ \ |  ___| |               | |           
| |  | / /_\ \| |_  | |__  _   _ _ __ | |_ ___ _ __ 
| |/\| |  _  ||  _| | '_ \| | | | '_ \| __/ _ \ '__|
\  /\  / | | || |   | | | | |_| | | | | ||  __/ |   
 \/  \/\_| |_/\_|   |_| |_|\__,_|_| |_|\__\___|_|   
                                                    
                                                       
github : MrpasswordTz
version: 1.0
country: Tanzania
''' +Fore.RESET

checking = "[*]checking: "
detection = "[*]Generic Detection Results: "


def check_waf(host):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, 80))
            request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
            s.send(request)
            response = s.recv(1024)
            response_str = response.decode('utf-8')

            waf_signatures = waf_sig

            for waf, signature in waf_signatures.items():
                if re.search(signature, response_str, re.IGNORECASE):
                    return f"{waf} WAF detected"

            return "No WAF detected"
    except socket.gaierror as e:
        print(f"\nHostname '{host}' Could Not Be Resolved: {e}")
        sys.exit(1)
    except socket.error as e:
        print(f"\nError connecting to '{host}': {e}")
        sys.exit(1)