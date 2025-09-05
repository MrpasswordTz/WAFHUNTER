#!/usr/bin/env python3
"""
WAFHUNTER - Advanced WAF Signatures Database
Professional WAF detection signatures with version detection capabilities
"""

# Core WAF signatures with version detection patterns
WAF_SIGNATURES = {
    # Cloudflare (updated)
    'Cloudflare': {
        'patterns': [
            r'cloudflare',
            r'__cfduid',
            r'cf-ray',
            r'cf-cache-status',
            r'cf-request-id',
            r'cf-bgj',
            r'cf-polished',
            r'cf-mirage',
            r'__cf_bm',
            r'cf-country',
            r'cf-connecting-ip'
        ],
        'version_patterns': [
            r'cloudflare/([0-9.]+)',
            r'cf-ray: ([a-f0-9-]+)',
            r'cf-cache-status: ([A-Z]+)'
        ],
        'bypass_techniques': [
            'Use different User-Agent strings',
            'Try HTTP/2 requests',
            'Use IPv6 addresses',
            'Try different HTTP methods',
            'Use Cloudflare bypass tools'
        ]
    },
    
    # AWS WAF (updated)
    'AWS WAF': {
        'patterns': [
            r'aws',
            r'amazon-web-services',
            r'x-amzn-requestid',
            r'x-amz-cf-id',
            r'x-amz-cf-pop',
            r'x-amz-cf-ray',
            r'x-amzn-trace-id',
            r'x-amzn-remapped',
            r'x-amzn-errortype'
        ],
        'version_patterns': [
            r'aws-waf/([0-9.]+)',
            r'x-amz-cf-id: ([a-f0-9-]+)'
        ],
        'bypass_techniques': [
            'Use different regions',
            'Try different AWS services',
            'Use signed requests',
            'Modify request headers'
        ]
    },
    
    # Imperva Incapsula (updated)
    'Imperva Incapsula': {
        'patterns': [
            r'imperva',
            r'incapsula',
            r'x-iinfo',
            r'x-cdn',
            r'x-cache',
            r'x-served-by',
            r'x-cacheable',
            r'x-incap-id',
            r'visid_incap_',
            r'incap_ses_'
        ],
        'version_patterns': [
            r'incapsula/([0-9.]+)',
            r'x-iinfo: ([0-9-]+)'
        ],
        'bypass_techniques': [
            'Use different User-Agent',
            'Try mobile user agents',
            'Use different IP ranges',
            'Modify request timing'
        ]
    },
    
    # Akamai (updated)
    'Akamai': {
        'patterns': [
            r'akamai',
            r'akamaized',
            r'x-akamai-transformed',
            r'x-akamai-request-id',
            r'x-akamai-edge-ip',
            r'x-akamai-origin-hop',
            r'akamai-origin-hop',
            r'x-akamai-config-log-id',
            r'x-akamai-edgescape'
        ],
        'version_patterns': [
            r'akamai/([0-9.]+)',
            r'x-akamai-request-id: ([a-f0-9-]+)'
        ],
        'bypass_techniques': [
            'Use different edge servers',
            'Try different protocols',
            'Modify request headers',
            'Use different geographic locations'
        ]
    },
    
    # F5 BIG-IP (updated)
    'F5 BIG-IP': {
        'patterns': [
            r'f5',
            r'big-ip',
            r'bigip',
            r'x-f5-request-id',
            r'x-f5-new-ssl',
            r'x-f5-ssl',
            r'x-f5-trace-id',
            r'x-f5-host',
            r'x-f5-application'
        ],
        'version_patterns': [
            r'bigip/([0-9.]+)',
            r'f5-bigip/([0-9.]+)',
            r'x-f5-request-id: ([a-f0-9-]+)'
        ],
        'bypass_techniques': [
            'Use different virtual servers',
            'Try different pools',
            'Modify SSL/TLS settings',
            'Use different load balancing methods'
        ]
    },
    
    # Barracuda (updated)
    'Barracuda': {
        'patterns': [
            r'barracuda',
            r'barra',
            r'x-barracuda',
            r'x-barracuda-request-id',
            r'x-barracuda-ip',
            r'x-barracuda-version',
            r'barracuda_',
            r'bcsi-'
        ],
        'version_patterns': [
            r'barracuda/([0-9.]+)',
            r'x-barracuda-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Try different rule sets',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Fortinet FortiWeb (updated)
    'Fortinet FortiWeb': {
        'patterns': [
            r'fortinet',
            r'fortiweb',
            r'fortiguard',
            r'x-fortinet',
            r'x-fortiweb',
            r'x-fortiguard',
            r'fortigate',
            r'x-fortigate'
        ],
        'version_patterns': [
            r'fortiweb/([0-9.]+)',
            r'fortinet/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different security profiles',
            'Try different policy modes',
            'Modify request signatures',
            'Use different authentication methods'
        ]
    },
    
    # Citrix NetScaler (updated)
    'Citrix NetScaler': {
        'patterns': [
            r'citrix',
            r'netscaler',
            r'x-citrix',
            r'x-netscaler',
            r'x-citrix-app',
            r'x-citrix-gateway',
            r'ns_af',
            r'citrix_ns_id',
            r'cns_'
        ],
        'version_patterns': [
            r'netscaler/([0-9.]+)',
            r'citrix/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different virtual servers',
            'Try different policies',
            'Modify request routing',
            'Use different authentication'
        ]
    },
    
    # Radware (updated)
    'Radware': {
        'patterns': [
            r'radware',
            r'defensepro',
            r'appwall',
            r'x-radware',
            r'x-defensepro',
            r'x-appwall',
            r'radwareid',
            r'x-radware-appweb'
        ],
        'version_patterns': [
            r'radware/([0-9.]+)',
            r'defensepro/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different security policies',
            'Try different rule sets',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Sucuri (updated)
    'Sucuri': {
        'patterns': [
            r'sucuri',
            r'cloudproxy',
            r'x-sucuri',
            r'x-sucuri-id',
            r'x-sucuri-cache',
            r'sucuri_cloudproxy',
            r'x-sucuri-block'
        ],
        'version_patterns': [
            r'sucuri/([0-9.]+)',
            r'x-sucuri-id: ([a-f0-9-]+)'
        ],
        'bypass_techniques': [
            'Use different user agents',
            'Try different IP addresses',
            'Modify request headers',
            'Use different protocols'
        ]
    },
    
    # Wordfence (updated)
    'Wordfence': {
        'patterns': [
            r'wordfence',
            r'wf-',
            r'x-wordfence',
            r'x-wf-',
            r'wordfence-',
            r'wfwaf-',
            r'wf_'
        ],
        'version_patterns': [
            r'wordfence/([0-9.]+)',
            r'x-wf-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different user agents',
            'Try different IP addresses',
            'Modify request patterns',
            'Use different authentication'
        ]
    },
    
    # ModSecurity (updated)
    'ModSecurity': {
        'patterns': [
            r'modsecurity',
            r'mod_security',
            r'mod_security2',
            r'x-modsecurity',
            r'x-owasp',
            r'x-crs',
            r'modsec',
            r'modsec1'
        ],
        'version_patterns': [
            r'modsecurity/([0-9.]+)',
            r'x-modsecurity-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different rule sets',
            'Try different CRS versions',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Palo Alto Networks (updated)
    'Palo Alto Networks': {
        'patterns': [
            r'paloalto',
            r'pan-',
            r'x-pan-',
            r'palo-alto',
            r'panos',
            r'paloaltofirewall',
            r'x-panw-'
        ],
        'version_patterns': [
            r'paloalto/([0-9.]+)',
            r'panos/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different security policies',
            'Try different rule sets',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Microsoft Azure (updated)
    'Microsoft Azure': {
        'patterns': [
            r'azure',
            r'azurefront',
            r'x-azure-',
            r'x-ms-',
            r'microsoft-azure',
            r'azureapplicationgateway',
            r'x-azure-ref',
            r'x-azure-originip'
        ],
        'version_patterns': [
            r'azure/([0-9.]+)',
            r'x-azure-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different regions',
            'Try different services',
            'Modify request headers',
            'Use different protocols'
        ]
    },
    
    # Google Cloud Armor (updated)
    'Google Cloud Armor': {
        'patterns': [
            r'google',
            r'cloud-armor',
            r'x-google-',
            r'x-gfe-',
            r'google-cloud',
            r'x-google-cloud-armor',
            r'x-goog-'
        ],
        'version_patterns': [
            r'google-cloud/([0-9.]+)',
            r'x-google-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different regions',
            'Try different services',
            'Modify request headers',
            'Use different protocols'
        ]
    },
    
    # Nginx (updated)
    'Nginx': {
        'patterns': [
            r'nginx',
            r'x-nginx',
            r'nginx/',
            r'openresty',
            r'tengine',
            r'x-nginx-cache'
        ],
        'version_patterns': [
            r'nginx/([0-9.]+)',
            r'openresty/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different configurations',
            'Try different modules',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Apache (updated)
    'Apache': {
        'patterns': [
            r'apache',
            r'httpd',
            r'x-apache',
            r'apache/',
            r'apachetrafficserver',
            r'x-apache-traffic'
        ],
        'version_patterns': [
            r'apache/([0-9.]+)',
            r'httpd/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different modules',
            'Try different configurations',
            'Modify request patterns',
            'Use different protocols'
        ]
    },
    
    # Cloudflare Magic Transit (updated)
    'Cloudflare Magic Transit': {
        'patterns': [
            r'cloudflare-magic',
            r'cf-magic',
            r'x-cf-magic',
            r'magic-transit',
            r'x-cf-magic-ip',
            r'x-cf-magic-country'
        ],
        'version_patterns': [
            r'cf-magic/([0-9.]+)',
            r'x-cf-magic-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different routing',
            'Try different protocols',
            'Modify request patterns',
            'Use different authentication'
        ]
    },
    
    # StackPath (updated)
    'StackPath': {
        'patterns': [
            r'stackpath',
            r'x-stackpath',
            r'stack-path',
            r'x-sp-',
            r'sp-edge',
            r'sp-server'
        ],
        'version_patterns': [
            r'stackpath/([0-9.]+)',
            r'x-stackpath-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # KeyCDN (updated)
    'KeyCDN': {
        'patterns': [
            r'keycdn',
            r'x-keycdn',
            r'key-cdn',
            r'x-kcdn-',
            r'keycdn-edge',
            r'x-keycdn-ip'
        ],
        'version_patterns': [
            r'keycdn/([0-9.]+)',
            r'x-keycdn-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # MaxCDN (updated)
    'MaxCDN': {
        'patterns': [
            r'maxcdn',
            r'x-maxcdn',
            r'max-cdn',
            r'x-mcdn-',
            r'maxcdn-edge',
            r'x-maxcdn-ip'
        ],
        'version_patterns': [
            r'maxcdn/([0-9.]+)',
            r'x-maxcdn-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # BunnyCDN (updated)
    'BunnyCDN': {
        'patterns': [
            r'bunnycdn',
            r'x-bunnycdn',
            r'bunny-cdn',
            r'x-bcdn-',
            r'bunnycdn-edge',
            r'x-bunnycdn-ip'
        ],
        'version_patterns': [
            r'bunnycdn/([0-9.)+)',
            r'x-bunnycdn-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # Fastly (updated)
    'Fastly': {
        'patterns': [
            r'fastly',
            r'x-fastly',
            r'fastly-',
            r'x-fst-',
            r'fastly-ff',
            r'x-fastly-service'
        ],
        'version_patterns': [
            r'fastly/([0-9.]+)',
            r'x-fastly-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # CloudFront (updated)
    'CloudFront': {
        'patterns': [
            r'cloudfront',
            r'x-amz-cf-',
            r'x-cache',
            r'x-amzn-',
            r'x-amz-cf-pop',
            r'x-amz-cf-id'
        ],
        'version_patterns': [
            r'cloudfront/([0-9.]+)',
            r'x-amz-cf-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Try different protocols',
            'Modify request headers',
            'Use different authentication'
        ]
    },
    
    # NEW: Kona Site Defender (Akamai)
    'Kona Site Defender': {
        'patterns': [
            r'kona',
            r'x-kona-id',
            r'akamaighost',
            r'x-akamai-kona',
            r'kona-site-defender'
        ],
        'version_patterns': [
            r'kona/([0-9.]+)',
            r'x-kona-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Modify request headers',
            'Try different protocols',
            'Use different IP addresses'
        ]
    },
    
    # NEW: EdgeCast (Verizon Digital Media)
    'EdgeCast': {
        'patterns': [
            r'edgecast',
            r'ecd=',
            r'x-ec',
            r'x-ec-cache',
            r'x-ec-custom-error',
            r'x-ecid'
        ],
        'version_patterns': [
            r'edgecast/([0-9.]+)',
            r'x-ec-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different edge locations',
            'Modify request headers',
            'Try different protocols',
            'Use different IP addresses'
        ]
    },
    
    # NEW: ChinaCache
    'ChinaCache': {
        'patterns': [
            r'chinacache',
            r'cccache',
            r'x-cc',
            r'x-cc-id',
            r'x-cc-cache',
            r'x-cc-edge'
        ],
        'version_patterns': [
            r'chinacache/([0-9.]+)',
            r'x-cc-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: Wangsu (China)
    'Wangsu': {
        'patterns': [
            r'wangsu',
            r'wscdn',
            r'x-ws-',
            r'x-wangsu',
            r'x-ws-id',
            r'x-ws-cache'
        ],
        'version_patterns': [
            r'wangsu/([0-9.]+)',
            r'x-ws-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: Yunjiasu (Baidu)
    'Yunjiasu': {
        'patterns': [
            r'yunjiasu',
            r'x-yjs-',
            r'x-yjs-id',
            r'x-yjs-cache',
            r'x-baidu-yjs'
        ],
        'version_patterns': [
            r'yunjiasu/([0-9.]+)',
            r'x-yjs-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: Aliyun (Alibaba Cloud)
    'Aliyun': {
        'patterns': [
            r'aliyun',
            r'alibaba',
            r'x-ali-',
            r'x-aliyun',
            r'x-ali-cache',
            r'x-ali-id'
        ],
        'version_patterns': [
            r'aliyun/([0-9.]+)',
            r'x-ali-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: Tencent Cloud
    'Tencent Cloud': {
        'patterns': [
            r'tencent',
            r'x-tc-',
            r'x-tencent',
            r'x-tc-id',
            r'x-tc-cache',
            r'x-tc-edge'
        ],
        'version_patterns': [
            r'tencent/([0-9.]+)',
            r'x-tc-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: Huawei Cloud
    'Huawei Cloud': {
        'patterns': [
            r'huawei',
            r'hwcloud',
            r'x-hw-',
            r'x-huawei',
            r'x-hw-id',
            r'x-hw-cache'
        ],
        'version_patterns': [
            r'huawei/([0-9.]+)',
            r'x-hw-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different Chinese regions',
            'Modify request headers',
            'Try different protocols',
            'Use Chinese IP addresses'
        ]
    },
    
    # NEW: IBM DataPower
    'IBM DataPower': {
        'patterns': [
            r'datapower',
            r'x-backside',
            r'x-datapower',
            r'x-ibm-datapower',
            r'x-dp-',
            r'x-dp-id'
        ],
        'version_patterns': [
            r'datapower/([0-9.]+)',
            r'x-dp-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different services',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Oracle Cloud
    'Oracle Cloud': {
        'patterns': [
            r'oracle',
            r'x-oracle-',
            r'oracle-cloud',
            r'x-oci-',
            r'x-oracle-id',
            r'x-oracle-cache'
        ],
        'version_patterns': [
            r'oracle/([0-9.]+)',
            r'x-oracle-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different regions',
            'Modify request headers',
            'Try different protocols',
            'Use different services'
        ]
    },
    
    # NEW: Sophos UTM
    'Sophos UTM': {
        'patterns': [
            r'sophos',
            r'utm',
            r'x-sophos-',
            r'x-utm-',
            r'sophos-utm',
            r'x-sophos-id'
        ],
        'version_patterns': [
            r'sophos/([0-9.]+)',
            r'utm/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Check Point
    'Check Point': {
        'patterns': [
            r'checkpoint',
            r'check-point',
            r'x-checkpoint',
            r'x-cp-',
            r'x-cp-id',
            r'x-cp-waf'
        ],
        'version_patterns': [
            r'checkpoint/([0-9.]+)',
            r'x-cp-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: SonicWall
    'SonicWall': {
        'patterns': [
            r'sonicwall',
            r'sonic-wall',
            r'x-sonicwall',
            r'x-sonic-',
            r'x-sonic-id',
            r'x-sonic-cache'
        ],
        'version_patterns': [
            r'sonicwall/([0-9.]+)',
            r'x-sonic-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Juniper Networks
    'Juniper Networks': {
        'patterns': [
            r'juniper',
            r'juniper-networks',
            r'x-juniper',
            r'x-jnpr-',
            r'x-juniper-id',
            r'x-juniper-cache'
        ],
        'version_patterns': [
            r'juniper/([0-9.]+)',
            r'x-juniper-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Cisco ACE
    'Cisco ACE': {
        'patterns': [
            r'cisco',
            r'cisco-ace',
            r'x-cisco-',
            r'x-ace-',
            r'x-cisco-id',
            r'x-cisco-cache'
        ],
        'version_patterns': [
            r'cisco/([0-9.]+)',
            r'ace/([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Cisco Cloud Web Security
    'Cisco Cloud Web Security': {
        'patterns': [
            r'cisco-cws',
            r'ciscocws',
            r'x-cisco-cws',
            r'x-cws-',
            r'x-cisco-cws-id',
            r'x-cisco-cws-cache'
        ],
        'version_patterns': [
            r'cws/([0-9.]+)',
            r'x-cws-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Arbor Networks
    'Arbor Networks': {
        'patterns': [
            r'arbor',
            r'arbor-networks',
            r'x-arbor',
            r'x-arbor-',
            r'x-arbor-id',
            r'x-arbor-cache'
        ],
        'version_patterns': [
            r'arbor/([0-9.]+)',
            r'x-arbor-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: NSFOCUS
    'NSFOCUS': {
        'patterns': [
            r'nsfocus',
            r'ns-focus',
            r'x-nsfocus',
            r'x-ns-',
            r'x-nsfocus-id',
            r'x-nsfocus-cache'
        ],
        'version_patterns': [
            r'nsfocus/([0-9.]+)',
            r'x-ns-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: DenyAll
    'DenyAll': {
        'patterns': [
            r'denyall',
            r'deny-all',
            r'x-denyall',
            r'x-da-',
            r'x-denyall-id',
            r'x-denyall-cache'
        ],
        'version_patterns': [
            r'denyall/([0-9.]+)',
            r'x-da-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Ergon Informatik
    'Ergon Informatik': {
        'patterns': [
            r'ergon',
            r'ergon-informatik',
            r'x-ergon',
            r'x-ei-',
            r'x-ergon-id',
            r'x-ergon-cache'
        ],
        'version_patterns': [
            r'ergon/([0-9.]+)',
            r'x-ei-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Applicure Technologies
    'Applicure Technologies': {
        'patterns': [
            r'applicure',
            r'applicure-technologies',
            r'x-applicure',
            r'x-at-',
            r'x-applicure-id',
            r'x-applicure-cache'
        ],
        'version_patterns': [
            r'applicure/([0-9.]+)',
            r'x-at-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Positive Technologies
    'Positive Technologies': {
        'patterns': [
            r'positive',
            r'positive-technologies',
            r'x-positive',
            r'x-pt-',
            r'x-positive-id',
            r'x-positive-cache'
        ],
        'version_patterns': [
            r'positive/([0-9.]+)',
            r'x-pt-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Comodo
    'Comodo': {
        'patterns': [
            r'comodo',
            r'comodo-waf',
            r'x-comodo',
            r'x-cw-',
            r'x-comodo-id',
            r'x-comodo-cache'
        ],
        'version_patterns': [
            r'comodo/([0-9.]+)',
            r'x-cw-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: SiteLock
    'SiteLock': {
        'patterns': [
            r'sitelock',
            r'site-lock',
            r'x-sitelock',
            r'x-sl-',
            r'x-sitelock-id',
            r'x-sitelock-cache'
        ],
        'version_patterns': [
            r'sitelock/([0-9.]+)',
            r'x-sl-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Reblaze
    'Reblaze': {
        'patterns': [
            r'reblaze',
            r're-blaze',
            r'x-reblaze',
            r'x-rb-',
            r'x-reblaze-id',
            r'x-reblaze-cache'
        ],
        'version_patterns': [
            r'reblaze/([0-9.]+)',
            r'x-rb-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: ThreatX
    'ThreatX': {
        'patterns': [
            r'threatx',
            r'threat-x',
            r'x-threatx',
            r'x-tx-',
            r'x-threatx-id',
            r'x-threatx-cache'
        ],
        'version_patterns': [
            r'threatx/([0-9.]+)',
            r'x-tx-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Signal Sciences
    'Signal Sciences': {
        'patterns': [
            r'signalsciences',
            r'signal-sciences',
            r'x-signalsciences',
            r'x-ss-',
            r'x-signalsciences-id',
            r'x-signalsciences-cache'
        ],
        'version_patterns': [
            r'signalsciences/([0-9.]+)',
            r'x-ss-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Shape Security
    'Shape Security': {
        'patterns': [
            r'shapesecurity',
            r'shape-security',
            r'x-shapesecurity',
            r'x-ss-',
            r'x-shapesecurity-id',
            r'x-shapesecurity-cache'
        ],
        'version_patterns': [
            r'shapesecurity/([0-9.]+)',
            r'x-ss-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: PerimeterX
    'PerimeterX': {
        'patterns': [
            r'perimeterx',
            r'perimeter-x',
            r'x-perimeterx',
            r'x-px-',
            r'x-perimeterx-id',
            r'x-perimeterx-cache'
        ],
        'version_patterns': [
            r'perimeterx/([0-9.]+)',
            r'x-px-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Distil Networks
    'Distil Networks': {
        'patterns': [
            r'distil',
            r'distil-networks',
            r'x-distil',
            r'x-dn-',
            r'x-distil-id',
            r'x-distil-cache'
        ],
        'version_patterns': [
            r'distil/([0-9.]+)',
            r'x-dn-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: DataDome
    'DataDome': {
        'patterns': [
            r'datadome',
            r'data-dome',
            r'x-datadome',
            r'x-dd-',
            r'x-datadome-id',
            r'x-datadome-cache'
        ],
        'version_patterns': [
            r'datadome/([0-9.]+)',
            r'x-dd-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Wallarm
    'Wallarm': {
        'patterns': [
            r'wallarm',
            r'wall-arm',
            r'x-wallarm',
            r'x-wa-',
            r'x-wallarm-id',
            r'x-wallarm-cache'
        ],
        'version_patterns': [
            r'wallarm/([0-9.]+)',
            r'x-wa-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: A10 Networks
    'A10 Networks': {
        'patterns': [
            r'a10',
            r'a10-networks',
            r'x-a10',
            r'x-a10-',
            r'x-a10-id',
            r'x-a10-cache'
        ],
        'version_patterns': [
            r'a10/([0-9.]+)',
            r'x-a10-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Kemp Technologies
    'Kemp Technologies': {
        'patterns': [
            r'kemp',
            r'kemp-technologies',
            r'x-kemp',
            r'x-kt-',
            r'x-kemp-id',
            r'x-kemp-cache'
        ],
        'version_patterns': [
            r'kemp/([0-9.]+)',
            r'x-kt-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: NGINX App Protect
    'NGINX App Protect': {
        'patterns': [
            r'nginx-app-protect',
            r'nginx-app',
            r'x-nginx-app',
            r'x-nap-',
            r'x-nginx-app-id',
            r'x-nginx-app-cache'
        ],
        'version_patterns': [
            r'nginx-app/([0-9.]+)',
            r'x-nap-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: HAProxy
    'HAProxy': {
        'patterns': [
            r'haproxy',
            r'ha-proxy',
            r'x-haproxy',
            r'x-hp-',
            r'x-haproxy-id',
            r'x-haproxy-cache'
        ],
        'version_patterns': [
            r'haproxy/([0-9.]+)',
            r'x-hp-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Varnish
    'Varnish': {
        'patterns': [
            r'varnish',
            r'varnish-cache',
            r'x-varnish',
            r'x-v-',
            r'x-varnish-id',
            r'x-varnish-cache'
        ],
        'version_patterns': [
            r'varnish/([0-9.]+)',
            r'x-v-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Squid
    'Squid': {
        'patterns': [
            r'squid',
            r'squid-cache',
            r'x-squid',
            r'x-sq-',
            r'x-squid-id',
            r'x-squid-cache'
        ],
        'version_patterns': [
            r'squid/([0-9.]+)',
            r'x-sq-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Traefik
    'Traefik': {
        'patterns': [
            r'traefik',
            r'traefik-waf',
            r'x-traefik',
            r'x-tf-',
            r'x-traefik-id',
            r'x-traefik-cache'
        ],
        'version_patterns': [
            r'traefik/([0-9.]+)',
            r'x-tf-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Caddy
    'Caddy': {
        'patterns': [
            r'caddy',
            r'caddy-waf',
            r'x-caddy',
            r'x-cd-',
            r'x-caddy-id',
            r'x-caddy-cache'
        ],
        'version_patterns': [
            r'caddy/([0-9.]+)',
            r'x-cd-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Envoy
    'Envoy': {
        'patterns': [
            r'envoy',
            r'envoy-waf',
            r'x-envoy',
            r'x-ey-',
            r'x-envoy-id',
            r'x-envoy-cache'
        ],
        'version_patterns': [
            r'envoy/([0-9.]+)',
            r'x-ey-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Istio
    'Istio': {
        'patterns': [
            r'istio',
            r'istio-waf',
            r'x-istio',
            r'x-is-',
            r'x-istio-id',
            r'x-istio-cache'
        ],
        'version_patterns': [
            r'istio/([0-9.]+)',
            r'x-is-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Linkerd
    'Linkerd': {
        'patterns': [
            r'linkerd',
            r'linkerd-waf',
            r'x-linkerd',
            r'x-ld-',
            r'x-linkerd-id',
            r'x-linkerd-cache'
        ],
        'version_patterns': [
            r'linkerd/([0-9.]+)',
            r'x-ld-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: OpenResty
    'OpenResty': {
        'patterns': [
            r'openresty',
            r'open-resty',
            r'x-openresty',
            r'x-or-',
            r'x-openresty-id',
            r'x-openresty-cache'
        ],
        'version_patterns': [
            r'openresty/([0-9.]+)',
            r'x-or-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Tengine
    'Tengine': {
        'patterns': [
            r'tengine',
            r'tengine-waf',
            r'x-tengine',
            r'x-te-',
            r'x-tengine-id',
            r'x-tengine-cache'
        ],
        'version_patterns': [
            r'tengine/([0-9.]+)',
            r'x-te-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: LiteSpeed
    'LiteSpeed': {
        'patterns': [
            r'litespeed',
            r'lite-speed',
            r'x-litespeed',
            r'x-ls-',
            r'x-litespeed-id',
            r'x-litespeed-cache'
        ],
        'version_patterns': [
            r'litespeed/([0-9.]+)',
            r'x-ls-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Caddy
    'Caddy': {
        'patterns': [
            r'caddy',
            r'caddy-server',
            r'x-caddy',
            r'x-cd-',
            r'x-caddy-id',
            r'x-caddy-cache'
        ],
        'version_patterns': [
            r'caddy/([0-9.]+)',
            r'x-cd-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Cherokee
    'Cherokee': {
        'patterns': [
            r'cherokee',
            r'cherokee-server',
            r'x-cherokee',
            r'x-ch-',
            r'x-cherokee-id',
            r'x-cherokee-cache'
        ],
        'version_patterns': [
            r'cherokee/([0-9.]+)',
            r'x-ch-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Lighttpd
    'Lighttpd': {
        'patterns': [
            r'lighttpd',
            r'lighty',
            r'x-lighttpd',
            r'x-lt-',
            r'x-lighttpd-id',
            r'x-lighttpd-cache'
        ],
        'version_patterns': [
            r'lighttpd/([0-9.]+)',
            r'x-lt-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Monkey
    'Monkey': {
        'patterns': [
            r'monkey',
            r'monkey-server',
            r'x-monkey',
            r'x-mk-',
            r'x-monkey-id',
            r'x-monkey-cache'
        ],
        'version_patterns': [
            r'monkey/([0-9.]+)',
            r'x-mk-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: H2O
    'H2O': {
        'patterns': [
            r'h2o',
            r'h2o-server',
            r'x-h2o',
            r'x-h2-',
            r'x-h2o-id',
            r'x-h2o-cache'
        ],
        'version_patterns': [
            r'h2o/([0-9.]+)',
            r'x-h2-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: G-WAN
    'G-WAN': {
        'patterns': [
            r'gwan',
            r'g-wan',
            r'x-gwan',
            r'x-gw-',
            r'x-gwan-id',
            r'x-gwan-cache'
        ],
        'version_patterns': [
            r'gwan/([0-9.]+)',
            r'x-gw-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Boa
    'Boa': {
        'patterns': [
            r'boa',
            r'boa-server',
            r'x-boa',
            r'x-b-',
            r'x-boa-id',
            r'x-boa-cache'
        ],
        'version_patterns': [
            r'boa/([0-9.]+)',
            r'x-b-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Zeus
    'Zeus': {
        'patterns': [
            r'zeus',
            r'zeus-server',
            r'x-zeus',
            r'x-z-',
            r'x-zeus-id',
            r'x-zeus-cache'
        ],
        'version_patterns': [
            r'zeus/([0-9.]+)',
            r'x-z-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Roxen
    'Roxen': {
        'patterns': [
            r'roxen',
            r'roxen-server',
            r'x-roxen',
            r'x-rx-',
            r'x-roxen-id',
            r'x-roxen-cache'
        ],
        'version_patterns': [
            r'roxen/([0-9.]+)',
            r'x-rx-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Resin
    'Resin': {
        'patterns': [
            r'resin',
            r'resin-server',
            r'x-resin',
            r'x-rs-',
            r'x-resin-id',
            r'x-resin-cache'
        ],
        'version_patterns': [
            r'resin/([0-9.]+)',
            r'x-rs-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Jetty
    'Jetty': {
        'patterns': [
            r'jetty',
            r'jetty-server',
            r'x-jetty',
            r'x-jt-',
            r'x-jetty-id',
            r'x-jetty-cache'
        ],
        'version_patterns': [
            r'jetty/([0-9.]+)',
            r'x-jt-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: Tomcat
    'Tomcat': {
        'patterns': [
            r'tomcat',
            r'tomcat-server',
            r'x-tomcat',
            r'x-tc-',
            r'x-tomcat-id',
            r'x-tomcat-cache'
        ],
        'version_patterns': [
            r'tomcat/([0-9.]+)',
            r'x-tc-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: WebSphere
    'WebSphere': {
        'patterns': [
            r'websphere',
            r'websphere-server',
            r'x-websphere',
            r'x-ws-',
            r'x-websphere-id',
            r'x-websphere-cache'
        ],
        'version_patterns': [
            r'websphere/([0-9.]+)',
            r'x-ws-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: WebLogic
    'WebLogic': {
        'patterns': [
            r'weblogic',
            r'weblogic-server',
            r'x-weblogic',
            r'x-wl-',
            r'x-weblogic-id',
            r'x-weblogic-cache'
        ],
        'version_patterns': [
            r'weblogic/([0-9.]+)',
            r'x-wl-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: JBoss
    'JBoss': {
        'patterns': [
            r'jboss',
            r'jboss-server',
            r'x-jboss',
            r'x-jb-',
            r'x-jboss-id',
            r'x-jboss-cache'
        ],
        'version_patterns': [
            r'jboss/([0-9.]+)',
            r'x-jb-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: GlassFish
    'GlassFish': {
        'patterns': [
            r'glassfish',
            r'glassfish-server',
            r'x-glassfish',
            r'x-gf-',
            r'x-glassfish-id',
            r'x-glassfish-cache'
        ],
        'version_patterns': [
            r'glassfish/([0-9.]+)',
            r'x-gf-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: WildFly
    'WildFly': {
        'patterns': [
            r'wildfly',
            r'wildfly-server',
            r'x-wildfly',
            r'x-wf-',
            r'x-wildfly-id',
            r'x-wildfly-cache'
        ],
        'version_patterns': [
            r'wildfly/([0-9.]+)',
            r'x-wf-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: IIS
    'IIS': {
        'patterns': [
            r'iis',
            r'microsoft-iis',
            r'x-iis',
            r'x-ms-iis',
            r'x-iis-id',
            r'x-iis-cache'
        ],
        'version_patterns': [
            r'iis/([0-9.]+)',
            r'x-iis-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: IIS URL Rewrite
    'IIS URL Rewrite': {
        'patterns': [
            r'iis-url-rewrite',
            r'url-rewrite',
            r'x-url-rewrite',
            r'x-rewrite',
            r'x-iis-rewrite'
        ],
        'version_patterns': [
            r'url-rewrite/([0-9.]+)',
            r'x-rewrite-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    },
    
    # NEW: IIS ARR
    'IIS ARR': {
        'patterns': [
            r'iis-arr',
            r'arr',
            r'x-arr',
            r'x-iis-arr',
            r'x-arr-cache'
        ],
        'version_patterns': [
            r'arr/([0-9.]+)',
            r'x-arr-version: ([0-9.]+)'
        ],
        'bypass_techniques': [
            'Use different policies',
            'Modify request headers',
            'Try different protocols',
            'Use different authentication methods'
        ]
    }
}

# Additional detection patterns for advanced analysis
ADVANCED_PATTERNS = {
    'response_codes': {
        'blocked': [403, 406, 418, 429, 503, 504],
        'challenge': [200, 302, 307, 308]
    },
    'headers': {
        'security': [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy',
            'referrer-policy'
        ],
        'waf_indicators': [
            'x-waf',
            'x-security',
            'x-protection',
            'x-shield',
            'x-guard',
            'x-filter',
            'x-block'
        ]
    },
    'content_patterns': {
        'block_pages': [
            r'access denied',
            r'blocked by',
            r'security policy',
            r'forbidden',
            r'not allowed',
            r'request blocked',
            r'security violation',
            r'attack detected',
            r'malicious request',
            r'suspicious activity'
        ],
        'challenge_pages': [
            r'please wait',
            r'checking your browser',
            r'verifying you are human',
            r'security check',
            r'captcha',
            r'challenge',
            r'verification'
        ]
    }
}

# WAF bypass techniques by category
BYPASS_TECHNIQUES = {
    'general': [
        'Use different User-Agent strings',
        'Modify request headers',
        'Try different HTTP methods',
        'Use different protocols (HTTP/2, HTTP/3)',
        'Modify request timing',
        'Use different IP addresses',
        'Try different ports',
        'Use different paths',
        'Modify request body',
        'Use different encodings'
    ],
    'advanced': [
        'Use HTTP/2 multiplexing',
        'Try different TLS versions',
        'Use different cipher suites',
        'Modify request order',
        'Use different compression',
        'Try different encodings',
        'Use different protocols',
        'Modify request signatures',
        'Use different authentication',
        'Try different routing'
    ],
    'evasion': [
        'Use Unicode encoding',
        'Try different case variations',
        'Use different whitespace',
        'Modify request structure',
        'Use different protocols',
        'Try different encodings',
        'Use different compression',
        'Modify request timing',
        'Use different IP addresses',
        'Try different ports'
    ]
}