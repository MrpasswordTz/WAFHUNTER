waf_sig = {
  'Cloudflare': r'cloudflare|__cfduid',
  'Alibaba Cloud': r'Alibaba|aliyun',
  'Citrix': r'citrix|netscaler',
  'Nginx': r'nginx',
  'Instant': r'instant|incapsula',
  'IMPERVA': r'impera|incapsula',
  'Radware': r'radware|defensepro',
  'Cpanel': r'cpanel',
  'Akamai': r'akamai|akamaized',
  'Fortinet': r'fortinet|fortiguard',
  'F5': r'f5|big-ip',
  'Microsoft Azure': r'azure|azurefront',
  'Sucuri': r'sucuri|cloudproxy',
  'AWS WAF': r'aws|amazon-web-services',
  'Verizon Digital Media Services': r'verizon|vdms',
  'StackPath': r'stackpath',
  'Rackspace': r'rackspace',
  'USignal': r'usignal',
  'Distil Networks': r'distil',
  'Incapsula': r'incapsula',
  'SiteLock': r'sitelock',
  'Wordfence': r'wordfence',
  'MalCare': r'malcare',
  'Sitelock TrueShield': r'trueshield',
  'Cloudbric': r'cloudbric',
  'Barracuda': r'barracuda',
  'Palo Alto Networks': r'paloalto',
  'Cisco ASA': r'ciscoasa',
  'Juniper SRX': r'junos',
  'F5 BIG-IP': r'big-ip',
  'Imperva SecureSphere': r'securesphere',
  'Radware DefensePro': r'defensepro',
  'FortiWeb': r'fortiweb',
  'Citrix NetScaler': r'netscaler',
  'A10 Networks': r'a10',
  'Brocade Virtual Traffic Manager': r'brocade',
  'Riverbed Stingray': r'stingray',
  'KEMP Technologies': r'kemp',
  'Pulse Secure': r'pulsesecure',
  'SonicWall': r'sonicwall',
  'WatchGuard': r'watchguard',
  'Sophos UTM': r'sophosutm',
  'Sophos XG Firewall': r'sophosxg',
  'Sophos SFOS': r'sophossfos',
  'Sophos Cyberoam': r'sophoscyberoam',
  'ZScaler': r'zscaler',
  'Forcepoint': r'forcepoint',
  'McAfee Web Gateway': r'mcafeewebgateway',
  'Trend Micro Deep Security': r'trendmicro',
  'Symantec Web Gateway': r'symantecwebgateway',
  'Cisco IronPort': r'ciscoironport',
  'Barracuda Web Application Firewall': r'barracudawaf',
  'F5 BIG-IP ASM': r'big-ipasm',
  'Imperva Web Application Firewall': r'impervawaf',
  'Radware AppWall': r'radwareappwall',
  'FortiWeb Web Application Firewall': r'fortiwebwaf',
  'Citrix NetScaler AppFirewall': r'netscalerappfirewall',
  'A10 Networks Thunder': r'a10thunder',
  'Brocade Virtual Web Application Firewall': r'brocadevwaf',
  'Riverbed Stingray Web Application Firewall': r'stingraywaf',
  'KEMP Technologies LoadMaster': r'kemplm',
  'Pulse Secure Virtual Web Application Firewall': r'pulsesecurevwaf',
  'SonicWall Web Application Firewall': r'sonicwallwaf',
  'WatchGuard Web Application Firewall': r'watchguardwaf',
  'Sophos UTM Web Application Firewall': r'sophosutmwaf',
  'ZScaler Web Application Firewall': r'zscalerwaf',
  'Forcepoint Web Application Firewall': r'forcepointwaf',
  'McAfee Web Gateway Web Application Firewall': r'mcafeewebgatewaywaf',
  'Trend Micro Deep Security Web Application Firewall': r'trendmicrodswaf',
  'Symantec Web Gateway Web Application Firewall': r'symantecwebgatewaywaf',
  'Oracle Dyn WAF': r'oracle|dyn',
  'cwatch': r'cwatch',
  'Sonicwall waf': r'sonicwallwaf',
  'ivanti vADC': r'ivanti|vadc',
  'Fastly Next-Gen WAF(powered by signal sciences)': r'fastly|signal',
  'Reblaze': r'reblaze',
  'Fortiweb': r'fortiweb',
  'Akamai App& API Protector': r'akamai|app',
  'Loadbalancer Enterprise ADC': r'loadbalancer|adc',
  'Array ASF Series Web Application Firewall & DDoS': r'array|asf',
  'StackPath Edge Security': r'stackpath|edge',
  'Vercara UltraWAF': r'vercara|ultrawaf',
  'Haltdos WAF - Community Edition (Open-Source)': r'haltdos|community',
  'Modshield SB': r'modshield|sb',
  'PT Application Firewall': r'pt|appfw',
  'WAPPLES': r'wapples',
  'CDNetworks Application Shield': r'cdnetworks|appshield',
  'Instart Web Security': r'instart|websec',
  'Symantec Web Application Firewall (WAF) & Reverse Proxy': r'symantec|waf',
  'Tencent Cloud Web Application Firewall (WAF)': r'tencent|waf',
  'Huawei Cloud Web Application Firewall (WAF)': r'huawei|waf',
  'Cloudbric': r'cloudbric',
  'Astra Website Protection': r'astra|website',
  'iniOrange Reverse Proxy': r'miniorange|reverse',
  'Bekchy': r'bekchy',
  'HAProxy One': r'haproxy|one',
  'ModSecurity': r'modsecurity',
  'Quttera': r'quttera',
  'Wordfence': r'wordfence',
  'CenturyLink Web Application Firewall (WAF)': r'centurylink|waf',
  'Haltdos Web Application Firewall': r'haltdos|waf',
  'BitNinja': r'bitninja',
  'Edgio App Security': r'edgio|appsec',
  'Indusface AppTrana': r'indusface|appt',
  'Myra Security as a Service Platform': r'myra|saas',
  'open-appsec': r'open-appsec',
  'Imunify360': r'imunify360',
  'SiteLock': r'sitelock',
  'Sangfor NGAF': r'sangfor|ngaf',
  'VMware NSX Advanced Load Balancer': r'vmware|nsx',
  'Sqreen from Datadog': r'sqreen|datadog',
  'AWS Shield Advanced': r'aws|shield',
  'Google Cloud Armor': r'google|armor',
  'Microsoft Azure DDoS Protection': r'azure|ddos',
  'Cloudflare Magic Transit': r'cloudflare|magic',
  'Radware Cloud DDoS Protection': r'radware|cloud',
  'Imperva DDoS Protection': r'imperva|ddos',
  'Akamai Prolexic': r'akamai|prolexic',
  'Verisign DDoS Protection': r'verisign|ddos',
  'Neustar UltraDDoS Protect': r'neustar|ultradddos',
  'F5 DDoS Hybrid Defender': r'f5|ddoshdf',
  'Palo Alto Networks DDoS Protection': r'paloalto|ddos',
  'Cisco DDoS Protection': r'cisco|ddos',
  'Juniper Networks DDoS Protection': r'juniper|ddos',
  'Fortinet DDoS Protection': r'fortinet|ddos',
  'Check Point DDoS Protection': r'checkpoint|ddos',
  'SonicWall DDoS Protection': r'sonicwall|ddos',
  'WatchGuard DDoS Protection': r'watchguard|ddos',
  'Sophos DDoS Protection': r'sophos|ddos',
  'ZScaler DDoS Protection': r'zscaler|ddos',
  'Forcepoint DDoS Protection': r'forcepoint|ddos',
  'McAfee DDoS Protection': r'mcafee|ddos',
  'Trend Micro DDoS Protection': r'trendmicro|ddos',
  'Symantec DDoS Protection': r'symantec|ddos',
  'Kaspersky DDoS Protection': r'kaspersky|ddos',
  'ESET DDoS Protection': r'eset|ddos',
    'Bitdefender DDoS Protection': r'bitdefender',
  'Avast DDoS Protection': r'avast',
  'AVG DDoS Protection': r'avg',
  'Malwarebytes DDoS Protection': r'malwarebytes',
  'Norton DDoS Protection': r'norton',
  'Trend Micro Cloud App Security': r'trendmicro|cloudapp',
  'Symantec Cloud App Security': r'symantec|cloudapp',
  'McAfee Cloud App Security': r'mcafee|cloudapp',
  'Kaspersky Cloud App Security': r'kaspersky|cloudapp',
  'ESET Cloud App Security': r'eset|cloudapp',
  'Bitdefender Cloud App Security': r'bitdefender|cloudapp',
  'Avast Cloud App Security': r'avast|cloudapp',
  'AVG Cloud App Security': r'avg|cloudapp',
  'Malwarebytes Cloud App Security': r'malwarebytes|cloudapp',
  'Norton Cloud App Security': r'norton|cloudapp',
  'Cisco Cloud Web Security': r'cisco|cloudweb',
  'Juniper Cloud Web Security': r'juniper|cloudweb',
  'Fortinet Cloud Web Security': r'fortinet|cloudweb',
  'Check Point Cloud Web Security': r'checkpoint|cloudweb',
  'SonicWall Cloud Web Security': r'sonicwall|cloudweb',
  'WatchGuard Cloud Web Security': r'watchguard|cloudweb',
  'Sophos Cloud Web Security': r'sophos|cloudweb',
  'ZScaler Cloud Web Security': r'zscaler|cloudweb',
  'Forcepoint Cloud Web Security': r'forcepoint|cloudweb',
  'McAfee Cloud Web Security': r'mcafee|cloudweb',
  'Trend Micro Cloud Web Security': r'trendmicro|cloudweb',
  'Symantec Cloud Web Security': r'symantec|cloudweb',
  'Kaspersky Cloud Web Security': r'kaspersky|cloudweb',
  'ESET Cloud Web Security': r'eset|cloudweb',
  'Bitdefender Cloud Web Security': r'bitdefender|cloudweb',
  'Avast Cloud Web Security': r'avast|cloudweb',
  'AVG Cloud Web Security': r'avg|cloudweb',
  'Malwarebytes Cloud Web Security': r'malwarebytes|cloudweb',
  'Norton Cloud Web Security': r'norton|cloudweb',
  'F5 Cloud Web Security': r'f5|cloudweb',
  'Palo Alto Networks Cloud Web Security': r'paloalto|cloudweb',
  'Radware Cloud Web Security': r'radware|cloudweb',
  'Imperva Cloud Web Security': r'imperva|cloudweb',
  'Akamai Cloud Web Security': r'akamai|cloudweb',
  'Verisign Cloud Web Security': r'verisign|cloudweb',
  'Neustar Cloud Web Security': r'neustar|cloudweb',
  'Cloudflare Cloud Web Security': r'cloudflare|cloudweb',
  'Google Cloud Web Security': r'google|cloudweb',
  'Microsoft Azure Cloud Web Security': r'azure|cloudweb',
  'AWS Cloud Web Security': r'aws|cloudweb',
  'IBM Cloud Web Security': r'ibm|cloudweb',
  'Oracle Cloud Web Security': r'oracle|cloudweb',
  'Rackspace Cloud Web Security': r'rackspace|cloudweb',
  'USignal Cloud Web Security': r'usignal|cloudweb',
  'Distil Networks Cloud Web Security': r'distil|cloudweb',
  'Incapsula Cloud Web Security': r'incapsula|cloudweb',
  'SiteLock Cloud Web Security': r'sitelock|cloudweb',
  'Wordfence Cloud Web Security': r'wordfence|cloudweb',
  'MalCare Cloud Web Security': r'malcare|cloudweb',
  'Sitelock TrueShield Cloud Web Security': r'trueshield|cloudweb',
  'Cloudbric Cloud Web Security': r'cloudbric|cloudweb',
  'Barracuda Cloud Web Security': r'barracuda|cloudweb',
  'Palo Alto Networks Cloud Web Security': r'paloalto|cloudweb',
  'Cisco ASA Cloud Web Security': r'ciscoasa|cloudweb',
  'Juniper SRX Cloud Web Security': r'junos|cloudweb',
  'F5 BIG-IP Cloud Web Security': r'big-ip|cloudweb',
  'Imperva SecureSphere Cloud WebSecurity': r'securesphere|cloudweb',
  'Radware DefensePro Cloud Web Security': r'defensepro|cloudweb',
  'FortiWeb Cloud Web Security': r'fortiweb|cloudweb',
  'Citrix NetScaler Cloud Web Security': r'netscaler|cloudweb',
  'A10 Networks Cloud Web Security': r'a10|cloudweb',
  'Brocade Virtual Traffic Manager Cloud Web Security': r'brocade|cloudweb',
  'Riverbed Stingray Cloud Web Security': r'stingray|cloudweb',
  'KEMP Technologies Cloud Web Security': r'kemp|cloudweb',
  'Pulse Secure Cloud Web Security': r'pulsesecure|cloudweb',
  'SonicWall Cloud Web Security': r'sonicwall|cloudweb',
  'WatchGuard Cloud Web Security': r'watchguard|cloudweb',
  'Sophos UTM Cloud Web Security': r'sophosutm|cloudweb',
  'Sophos XG Firewall Cloud Web Security': r'sophosxg|cloudweb',
  'Sophos SFOS Cloud Web Security': r'sophossfos|cloudweb',
  'Sophos Cyberoam Cloud Web Security': r'sophoscyberoam|cloudweb',
  'ZScaler Cloud Web Security': r'zscaler|cloudweb',
  'Forcepoint Cloud Web Security': r'forcepoint|cloudweb',
  'McAfee Web Gateway Cloud Web Security': r'mcafeewebgateway|cloudweb',
  'Trend Micro Deep Security Cloud Web Security': r'trendmicro|cloudweb',
  'Symantec Web Gateway Cloud Web Security': r'symantecwebgateway|cloudweb',
  'Cisco IronPort Cloud Web Security': r'ciscoironport|cloudweb',
  'Barracuda Web Application Firewall Cloud Web Security': r'barracudawaf|cloudweb',
  'F5 BIG-IP ASM Cloud Web Security': r'big-ipasm|cloudweb',
  'Imperva Web Application Firewall Cloud Web Security': r'impervawaf|cloudweb',
  'Radware AppWall Cloud Web Security': r'radwareappwall|cloudweb',
  'FortiWeb Web Application Firewall Cloud Web Security': r'fortiwebwaf|cloudweb',
  'Citrix NetScaler AppFirewall Cloud Web Security': r'netscalerappfirewall|cloudweb',
  'A10 Networks Thunder Cloud Web Security': r'a10thunder|cloudweb',
  'Brocade Virtual Web Application Firewall Cloud Web Security': r'brocadevwaf|cloudweb',
  'Riverbed Stingray Web Application Firewall Cloud Web Security': r'stingraywaf|cloudweb',
  'KEMP Technologies LoadMaster Cloud Web Security': r'kemplm|cloudweb',
  'Pulse Secure Virtual Web Application Firewall Cloud Web Security': r'pulsesecurevwaf|cloudweb',
  'SonicWall Web Application Firewall Cloud Web Security': r'sonicwallwaf|cloudweb',
  'WatchGuard Web Application Firewall Cloud Web Security': r'watchguardwaf|cloudweb',
  'Sophos UTM Web Application Firewall Cloud Web Security': r'sophosutmwaf|cloudweb',
  'ZScaler Web Application Firewall Cloud Web Security': r'zscalerwaf|cloudweb',
  'Forcepoint Web Application Firewall Cloud Web Security': r'forcepointwaf|cloudweb',
  'McAfee Web Gateway Web Application Firewall Cloud Web Security': r'mcafeewebgatewaywaf|cloudweb',
  'Trend Micro Deep Security Web Application Firewall Cloud Web Security': r'trendmicrodswaf|cloudweb',
  'Symantec Web Gateway Web Application Firewall Cloud Web Security': r'symantecwebgatewaywaf|cloudweb',
  'Oracle Dyn WAF Cloud Web Security': r'oracle|dyn|cloudweb',
  'cwatch Cloud Web Security': r'cwatch|cloudweb',
  'Sonicwall waf Cloud Web Security': r'sonicwallwaf|cloudweb',
  'ivanti vADC Cloud Web Security': r'ivanti|vadc|cloudweb',
  'Fastly Next-Gen WAF(powered by signal sciences) Cloud Web Security': r'fastly|signal|cloudweb',
  'Reblaze Cloud Web Security': r'reblaze|cloudweb',
  'Fortiweb Cloud Web Security': r'fortiweb|cloudweb',
  'Akamai App& API Protector Cloud Web Security': r'akamai|app|cloudweb',
  'Loadbalancer Enterprise ADC Cloud Web Security': r'loadbalancer|adc|cloudweb',
    'Array ASF Series Web Application Firewall & DDoS Cloud Web Security': r'array|asf|cloudweb',
  'StackPath Edge Security Cloud Web Security': r'stackpath|edge|cloudweb',
  'Vercara UltraWAF Cloud Web Security': r'vercara|ultrawaf|cloudweb',
  'Haltdos WAF - Community Edition (Open-Source) Cloud Web Security': r'haltdos|community|cloudweb',
  'Modshield SB Cloud Web Security': r'modshield|sb|cloudweb',
  'PT Application Firewall Cloud Web Security': r'pt|appfw|cloudweb',
  'WAPPLES Cloud Web Security': r'wapples|cloudweb',
  'CDNetworks Application Shield Cloud Web Security': r'cdnetworks|appshield|cloudweb',
  'Instart Web Security Cloud Web Security': r'instart|websec|cloudweb',
  'Symantec Web Application Firewall (WAF) & Reverse Proxy Cloud Web Security': r'symantec|waf|cloudweb',
  'Tencent Cloud Web Application Firewall (WAF) Cloud Web Security': r'tencent|waf|cloudweb',
  'Huawei Cloud Web Application Firewall (WAF) Cloud Web Security': r'huawei|waf|cloudweb',
  'Cloudbric Cloud Web Security': r'cloudbric|cloudweb',
  'Astra Website Protection Cloud Web Security': r'astra|website|cloudweb',
  'iniOrange Reverse Proxy Cloud Web Security': r'miniorange|reverse|cloudweb',
  'Bekchy Cloud Web Security': r'bekchy|cloudweb',
  'HAProxy One Cloud Web Security': r'haproxy|one|cloudweb',
  'ModSecurity Cloud Web Security': r'modsecurity|cloudweb',
  'Quttera Cloud Web Security': r'quttera|cloudweb',
  'Wordfence Cloud Web Security': r'wordfence|cloudweb',
  'CenturyLink Web Application Firewall (WAF) Cloud Web Security': r'centurylink|waf|cloudweb',
  'Haltdos Web Application Firewall Cloud Web Security': r'haltdos|waf|cloudweb',
  'BitNinja Cloud Web Security': r'bitninja|cloudweb',
  'Edgio App Security Cloud Web Security': r'edgio|appsec|cloudweb',
  'Indusface AppTrana Cloud Web Security': r'indusface|appt|cloudweb',
  'Myra Security as a Service Platform Cloud Web Security': r'myra|saas|cloudweb',
  'open-appsec Cloud Web Security': r'open-appsec|cloudweb',
  'Imunify360 Cloud Web Security': r'imunify360|cloudweb',
  'SiteLock Cloud Web Security': r'sitelock|cloudweb',
  'Sangfor NGAF Cloud Web Security': r'sangfor|ngaf|cloudweb',
  'VMware NSX Advanced Load Balancer Cloud Web Security': r'vmware|nsx|cloudweb',
  'Sqreen from Datadog Cloud Web Security': r'sqreen|datadog|cloudweb',
  'AWS Shield Advanced Cloud Web Security': r'aws|shield|cloudweb',
  'Google Cloud Armor Cloud Web Security': r'google|armor|cloudweb',
  'Microsoft Azure DDoS Protection Cloud Web Security': r'azure|ddos|cloudweb',
  'Cloudflare Magic Transit Cloud Web Security': r'cloudflare|magic|cloudweb',
  'Radware Cloud DDoS Protection Cloud Web Security': r'radware|cloud|cloudweb',
  'Imperva DDoS Protection Cloud Web Security': r'imperva|ddos|cloudweb',
  'Akamai Prolexic Cloud Web Security': r'akamai|prolexic|cloudweb',
  'Verisign DDoS Protection Cloud Web Security': r'verisign|ddos|cloudweb',
  'Neustar UltraDDoS Protect Cloud Web Security': r'neustar|ultradddos|cloudweb',
    'F5 DDoS Hybrid Defender Cloud Web Security': r'f5|ddos|cloudweb',
  'Palo Alto Networks Panorama Cloud Web Security': r'paloalto|panorama|cloudweb',
  'Cisco Umbrella Cloud Web Security': r'cisco|umbrella|cloudweb',
  'Zscaler Cloud Security Platform Cloud Web Security': r'zscaler|cloud|cloudweb',
  'Forcepoint Cloud Security Gateway Cloud Web Security': r'forcepoint|cloud|cloudweb',
  'McAfee Cloud Workload Security Cloud Web Security': r'mcafee|cloud|cloudweb',
  'Trend Micro Cloud One Cloud Web Security': r'trendmicro|cloudone|cloudweb',
  'Symantec Cloud Workload Protection Cloud Web Security': r'symantec|cloud|cloudweb',
  'Kaspersky Hybrid Cloud Security Cloud Web Security': r'kaspersky|hybrid|cloudweb',
  'ESET Cloud Security Cloud Web Security': r'eset|cloud|cloudweb',
  'Bitdefender Cloud Security Cloud Web Security': r'bitdefender|cloud|cloudweb',
  'Avast Cloud Security Cloud Web Security': r'avast|cloud|cloudweb',
  'AVG Cloud Security Cloud Web Security': r'avg|cloud|cloudweb',
  'Malwarebytes Cloud Security Cloud Web Security': r'malwarebytes|cloud|cloudweb',
  'Norton Cloud Security Cloud Web Security': r'norton|cloud|cloudweb',
  'Check Point CloudGuard Cloud Web Security': r'checkpoint|cloudguard|cloudweb',
  'Juniper vSRX Cloud Web Security': r'juniper|vsrx|cloudweb',
  'Fortinet FortiGate Cloud Web Security': r'fortinet|fortigate|cloudweb',
  'SonicWall Cloud App Security Cloud Web Security': r'sonicwall|cloudapp|cloudweb',
  'WatchGuard Cloud Security Cloud Web Security': r'watchguard|cloud|cloudweb',
  'Sophos Cloud Security Cloud Web Security': r'sophos|cloud|cloudweb',
  'ZScaler Cloud Security Cloud Web Security': r'zscaler|cloud|cloudweb',
  'Forcepoint Cloud Security Cloud Web Security': r'forcepoint|cloud|cloudweb',
  'McAfee Cloud Security Cloud Web Security': r'mcafee|cloud|cloudweb',
  'Trend Micro Cloud Security Cloud Web Security': r'trendmicro|cloud|cloudweb',
  'Symantec Cloud Security Cloud Web Security': r'symantec|cloud|cloudweb',
  'Kaspersky Cloud Security Cloud Web Security': r'kaspersky|cloud|cloudweb',
  'ESET Cloud Security Cloud Web Security': r'eset|cloud|cloudweb',
  'Bitdefender Cloud Security Cloud Web Security': r'bitdefender|cloud|cloudweb',
  'Avast Cloud Security Cloud Web Security': r'avast|cloud|cloudweb',
  'AVG Cloud Security Cloud Web Security': r'avg|cloud|cloudweb',
  'Malwarebytes Cloud Security Cloud Web Security': r'malwarebytes|cloud|cloudweb',
  'Norton Cloud Security Cloud Web Security': r'norton|cloud|cloudweb',
  'F5 BIG-IP Cloud Security Cloud Web Security': r'f5|big-ip|cloudweb',
  'Imperva Cloud Security Cloud Web Security': r'imperva|cloud|cloudweb',
  'Radware Cloud Security Cloud Web Security': r'radware|cloud|cloudweb',
  'FortiWeb Cloud Security Cloud Web Security': r'fortiweb|cloud|cloudweb',
  'Citrix NetScaler Cloud Security Cloud Web Security': r'citrix|netscaler|cloudweb',
  'A10 Networks Cloud Security Cloud Web Security': r'a10|cloud|cloudweb',
  'Brocade Virtual Web Application Firewall Cloud Web Security': r'brocade|virtual|cloudweb',
  'Riverbed Stingray Cloud Web Security': r'riverbed|stingray|cloudweb',
  'KEMP Technologies LoadMaster Cloud Web Security': r'kemp|loadmaster|cloudweb',
  'Pulse Secure Virtual Web Application Firewall Cloud Web Security': r'pulsesecure|virtual|cloudweb',
  'SonicWall Web Application Firewall Cloud Web Security': r'sonicwall|waf|cloudweb',
  'WatchGuard Web Application Firewall Cloud Web Security': r'watchguard|waf|cloudweb',
  'Sophos UTM Web Application Firewall Cloud Web Security': r'sophosutm|waf|cloudweb',
  'ZScaler Web Application Firewall Cloud Web Security': r'zscaler|waf|cloudweb',
 'Forcepoint Web Application Firewall Cloud Web Security': r'forcepoint|waf|cloudweb',
  'McAfee Web Gateway Web Application Firewall Cloud Web Security': r'mcafeewebgateway|waf|cloudweb',
  'Trend Micro Deep Security Web Application Firewall Cloud Web Security': r'trendmicro|deep|cloudweb',
  'Symantec Web Gateway Web Application Firewall Cloud Web Security': r'symantecwebgateway|waf|cloudweb',
  'Oracle Dyn WAF Cloud Web Security': r'oracle|dyn|cloudweb',
  'cwatch Cloud Web Security': r'cwatch|cloudweb',
  'Sonicwall waf Cloud Web Security': r'sonicwallwaf|cloudweb',
  'ivanti vADC Cloud Web Security': r'ivanti|vadc|cloudweb',
  'Fastly Next-Gen WAF(powered by signal sciences) Cloud Web Security': r'fastly|signal|cloudweb',
  'Reblaze Cloud Web Security': r'reblaze|cloudweb',
  'Fortiweb Cloud Web Security': r'fortiweb|cloudweb',
  'Akamai App& API Protector Cloud Web Security': r'akamai|app|cloudweb',
  'Loadbalancer Enterprise ADC Cloud Web Security': r'loadbalancer|adc|cloudweb',
  'Array ASF Series Web Application Firewall & DDoS Cloud Web Security': r'array|asf|cloudweb',
  'StackPath Edge Security Cloud Web Security': r'stackpath|edge|cloudweb',
  'Vercara UltraWAF Cloud Web Security': r'vercara|ultrawaf|cloudweb',
  'Haltdos WAF - Community Edition (Open-Source) Cloud Web Security': r'haltdos|community|cloudweb',
  'Modshield SB Cloud Web Security': r'modshield|sb|cloudweb',
  'PT Application Firewall Cloud Web Security': r'pt|appfw|cloudweb',
  'WAPPLES Cloud Web Security': r'wapples|cloudweb',
  'CDNetworks Application Shield Cloud Web Security': r'cdnetworks|appshield|cloudweb',
  'Instart Web Security Cloud Web Security': r'instart|websec|cloudweb',
  'Symantec Web Application Firewall (WAF) & Reverse Proxy Cloud Web Security': r'symantec|waf|cloudweb',
  'Tencent Cloud Web Application Firewall (WAF) Cloud Web Security': r'tencent|waf|cloudweb',
  'Huawei Cloud Web Application Firewall (WAF) Cloud Web Security': r'huawei|waf|cloudweb',
  'Cloudbric Cloud Web Security': r'cloudbric|cloudweb',
  'Astra Website Protection Cloud Web Security': r'astra|website|cloudweb',
  'iniOrange Reverse Proxy Cloud Web Security': r'miniorange|reverse|cloudweb',
  'Bekchy Cloud Web Security': r'bekchy|cloudweb',
  'HAProxy One Cloud Web Security': r'haproxy|one|cloudweb',
  'ModSecurity Cloud Web Security': r'modsecurity|cloudweb',
  'Quttera Cloud Web Security': r'quttera|cloudweb',
  'Wordfence Cloud Web Security': r'wordfence|cloudweb',
  'CenturyLink Web Application Firewall (WAF) Cloud Web Security': r'centurylink|waf|cloudweb',
  'Haltdos Web Application Firewall Cloud Web Security': r'haltdos|waf|cloudweb',
  'BitNinja Cloud Web Security': r'bitninja|cloudweb',
  'Edgio App Security Cloud Web Security': r'edgio|appsec|cloudweb',
  'Indusface AppTrana Cloud Web Security': r'indusface|appt|cloudweb',
  'Myra Security as a Service Platform Cloud Web Security': r'myra|saas|cloudweb',
  'open-appsec Cloud Web Security': r'open-appsec|cloudweb',
  'Imunify360 Cloud Web Security': r'imunify360|cloudweb',
  'SiteLock Cloud Web Security': r'sitelock|cloudweb',
  'Sangfor NGAF Cloud Web Security': r'sangfor|ngaf|cloudweb',
  'VMware NSX Advanced Load Balancer Cloud Web Security': r'vmware|nsx|cloudweb',
  'Sqreen from Datadog Cloud Web Security': r'sqreen|datadog|cloudweb',
  'AWS Shield Advanced Cloud Web Security': r'aws|shield|cloudweb',
  'Google Cloud Armor Cloud Web Security': r'google|armor|cloudweb',
  'Microsoft Azure DDoS Protection Cloud Web Security': r'azure|ddos|cloudweb',
  'Cloudflare Magic Transit Cloud Web Security': r'cloudflare|magic|cloudweb',
  'Radware Cloud DDoS Protection Cloud Web Security': r'radware|cloud|cloudweb',
  'Imperva DDoS Protection Cloud Web Security': r'imperva|ddos|cloudweb',
  'Akamai Prolexic Cloud Web Security': r'akamai|prolexic|cloudweb',
  'Verisign DDoS Protection Cloud Web Security': r'verisign|ddos|cloudweb',
  'Neustar UltraDDoS Protect Cloud Web Security': r'neustar|ultradddos|cloudweb',
  'F5 DDoS Hybrid Defender Cloud Web Security': r'f5|ddos|cloudweb',
  'Palo Alto Networks Panorama Cloud Web Security': r'paloalto|panorama|cloudweb',
  'Cisco Umbrella Cloud Web Security': r'cisco|umbrella|cloudweb',
  'Zscaler Cloud Security Platform Cloud Web Security': r'zscaler|cloud|cloudweb',
  'Forcepoint Cloud Security Gateway Cloud Web Security': r'forcepoint|cloud|cloudweb',
  'McAfee Cloud Workload Security Cloud Web Security': r'mcafee|cloud|cloudweb',
  'Trend Micro Cloud One Cloud Web Security': r'trendmicro|cloudone|cloudweb',
  'Symantec Cloud Workload Protection Cloud Web Security': r'symantec|cloud|cloudweb',
  'Kaspersky Hybrid Cloud Security Cloud Web Security': r'kaspersky|hybrid|cloudweb',
  'ESET Cloud Security Cloud Web Security': r'eset|cloud|cloudweb',
  'Bitdefender Cloud Security Cloud Web Security': r'bitdefender|cloud|cloudweb',
  'Avast Cloud Security Cloud Web Security': r'avast|cloud|cloudweb',
  'AVG Cloud Security Cloud Web Security': r'avg|cloud|cloudweb',
  'Malwarebytes Cloud Security Cloud Web Security': r'malwarebytes|cloud|cloudweb',
  'Norton Cloud Security Cloud Web Security': r'norton|cloud|cloudweb',
  'Check Point CloudGuard Cloud Web Security': r'checkpoint|cloudguard|cloudweb',
  'Juniper vSRX Cloud Web Security': r'juniper|vsrx|cloudweb',
  'Fortinet FortiGate Cloud Web Security': r'fortinet|fortigate|cloudweb',
  'SonicWall Cloud App Security Cloud Web Security': r'sonicwall|cloudapp|cloudweb',
  'WatchGuard Cloud Security Cloud Web Security': r'watchguard|cloud|cloudweb',
  'Sophos Cloud Security Cloud Web Security': r'sophos|cloud|cloudweb',
  'ZScaler Cloud Security Cloud Web Security': r'zscaler|cloud|cloudweb',
  'Forcepoint Cloud Security Cloud Web Security': r'forcepoint|cloud|cloudweb',
  'McAfee Cloud Security Cloud Web Security': r'mcafee|cloud|cloudweb',
  'Trend Micro Cloud Security Cloud Web Security': r'trendmicro|cloud|cloudweb',
  'Symantec Cloud Security Cloud Web Security': r'symantec|cloud|cloudweb',
  'Kaspersky Cloud Security Cloud Web Security': r'kaspersky|cloud|cloudweb',
  'ESET Cloud Security Cloud Web Security': r'eset|cloud|cloudweb',
  'Bitdefender Cloud Security Cloud Web Security': r'bitdefender|cloud|cloudweb',
  'Avast Cloud Security Cloud Web Security': r'avast|cloud|cloudweb',
  'AVG Cloud Security Cloud Web Security': r'avg|cloud|cloudweb',
  'Malwarebytes Cloud Security Cloud Web Security': r'malwarebytes|cloud|cloudweb',
  'Norton Cloud Security Cloud Web Security': r'norton|cloud|cloudweb',
  'F5 BIG-IP Cloud Security Cloud Web Security': r'f5|big-ip|cloudweb',
  'Imperva Cloud Security Cloud Web Security': r'imperva|cloud|cloudweb',
  'Radware Cloud Security Cloud Web Security': r'radware|cloud|cloudweb',
  'FortiWebCloud Security Cloud Web Security': r'fortiweb|cloud|cloudweb',
  'Citrix NetScaler Cloud Security Cloud Web Security': r'citrix|netscaler|cloudweb',
  'A10 Networks Cloud Security Cloud Web Security': r'a10|cloud|cloudweb',
  'Brocade Virtual Web Application Firewall Cloud Web Security': r'brocade|virtual|cloudweb',
  'Riverbed Stingray Cloud Web Security': r'riverbed|stingray|cloudweb',
  'KEMP Technologies LoadMaster Cloud Web Security': r'kemp|loadmaster|cloudweb',
  'Pulse Secure Virtual Web Application Firewall Cloud Web Security': r'pulsesecure|virtual|cloudweb',
  'SonicWall Web Application Firewall Cloud Web Security': r'sonicwall|waf|cloudweb',
  'WatchGuard Web Application Firewall Cloud Web Security': r'watchguard|waf|cloudweb',
  'Sophos UTM Web Application Firewall Cloud Web Security': r'sophosutm|waf|cloudweb',
  'ZScaler Web Application Firewall Cloud Web Security': r'zscaler|waf|cloudweb',
  'Forcepoint Web Application Firewall Cloud Web Security': r'forcepoint|waf|cloudweb',
  'McAfee Web Gateway Web Application Firewall Cloud Web Security': r'mcafeewebgateway|waf|cloudweb',
  'Trend Micro Deep Security Web Application Firewall Cloud Web Security': r'trendmicro|deep|cloudweb',
  'Symantec Web Gateway Web Application Firewall Cloud Web Security': r'symantecwebgateway|waf|cloudweb',
  'Oracle Dyn WAF Cloud Web Security': r'oracle|dyn|cloudweb',
  'cwatch Cloud Web Security': r'cwatch|cloudweb',
  'Sonicwall waf Cloud Web Security': r'sonicwallwaf|cloudweb',
  'ivanti vADC Cloud Web Security': r'ivanti|vadc|cloudweb',
  'Fastly Next-Gen WAF(powered by signal sciences) Cloud Web Security': r'fastly|signal|cloudweb',
  'Reblaze Cloud Web Security': r'reblaze|cloudweb',
  'Fortiweb Cloud Web Security': r'fortiweb|cloudweb',
  'Akamai App& API Protector Cloud Web Security': r'akamai|app|cloudweb',
  'Loadbalancer Enterprise ADC Cloud Web Security': r'loadbalancer|adc|cloudweb',
  'Array ASF Series Web Application Firewall & DDoS Cloud Web Security': r'array|asf|cloudweb',
  'StackPath Edge Security Cloud Web Security': r'stackpath|edge|cloudweb',
  'Vercara UltraWAF Cloud Web Security': r'vercara|ultrawaf|cloudweb',
  'Haltdos WAF - Community Edition (Open-Source) Cloud Web Security': r'haltdos|community|cloudweb',
  'Modshield SB Cloud Web Security': r'modshield|sb|cloudweb',
  'PT Application Firewall Cloud Web Security': r'pt|appfw|cloudweb',
  'WAPPLES Cloud Web Security': r'wapples|cloudweb',
  'CDNetworks Application Shield Cloud Web Security': r'cdnetworks|appshield|cloudweb',
  'Instart Web Security Cloud Web Security': r'instart|websec|cloudweb',
  'Symantec Web Application Firewall (WAF) & Reverse Proxy Cloud Web Security': r'symantec|waf|cloudweb',
  'Tencent Cloud Web Application Firewall (WAF) Cloud Web Security': r'tencent|waf|cloudweb',
  'Huawei Cloud Web Application Firewall (WAF) Cloud Web Security': r'huawei|waf|cloudweb',
  'Cloudbric Cloud Web Security': r'cloudbric|cloudweb',
  'Astra Website Protection Cloud Web Security': r'astra|website|cloudweb',
  'iniOrange Reverse Proxy Cloud Web Security': r'miniorange|reverse|cloudweb',
  'Bekchy Cloud Web Security': r'bekchy|cloudweb',
  'HAProxy One Cloud Web Security': r'haproxy|one|',
  'Apache': r'apache|mod_security|mod_security2',
  'Apache ModSecurity Core Rule Set (CRS)': r'modsecurity|crs',
  'Apache OWASP ModSecurity Core Rule Set (CRS)': r'owasp|modsecurity|crs',
  'Apache ModSecurity with OWASP Core Rule Set (CRS)': r'modsecurity|owasp|crs',
   
}
