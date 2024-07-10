<img src="https://github.com/MrpasswordTz/WAFHUNTER/blob/main/logo/wafLogo.jpg" alt="Waf img">

# WAFHUNTER 

WAFHUNTER(WAFHUNTER(Web Application Firewall Detector): is a Python script designed to detect Web Application Firewalls (WAFs) on websites. It uses a comprehensive list of WAF signatures to identify the presence of a WAF on a target website.

# Features:
<ul>
  <li>Detects over 100 WAFs including popular one such as Cloudflare, AWS WAF and Imperva</li>
  <li>Uses a regularly updated list of WAF signatures to ensure accuracy</li>
  <li>Simple and easy to use</li>
  <li>command-line interface</li>
  <li>Supports scanning of multiple websites at once</li>
  <li>Supports both linux(Deb) and Termux </li>
</ul>

# installation termux:
```
pkg update

pkg install git

pkg install python python2 python3

git clone https://github.com/MrpasswordTz/WAFHUNTER.git

cd WAFHUNTER

pip install -r requirements.txt

python3 wafhunter.py
```
# Installation for Linux(Deb)
```
apt update

git clone https://github.com/MrpasswordTz/WAFHUNTER.git

cd WAFHUNTER

pip install -r requirements.txt

python3 wafhunter.py
```

# Contributing:
If you'd like to contribute to WAFHUNTER, please fork this repository and submit a pull request with your updates. We welcome additions to the WAF signature list and any other improvements to the script.

# Disclaimer:
This script is for educational and research purposes only. Do not use it to scan websites without permission.
