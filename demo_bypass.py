#!/usr/bin/env python3
"""
WAFHUNTER - Enhanced Bypass Techniques Demo
Demonstrates the advanced bypass techniques available in WAFHUNTER
"""

from plugins.bypass_techniques import BypassTechniques

def demo_bypass_techniques():
    """Demonstrate various bypass techniques"""
    print("🔧 WAFHUNTER Enhanced Bypass Techniques Demo")
    print("=" * 50)
    
    # Initialize bypass techniques
    bypass = BypassTechniques()
    
    # Test payloads
    test_payloads = [
        "SELECT * FROM users WHERE id='1'",
        "alert('XSS')",
        "ls -la",
        "test' OR '1'='1"
    ]
    
    # Categories to demonstrate
    categories = [
        'encoding',
        'case_variations', 
        'whitespace_manipulation',
        'unicode_evasion',
        'obfuscation',
        'sql_injection_evasion',
        'xss_evasion',
        'command_injection_evasion'
    ]
    
    for payload in test_payloads:
        print(f"\n🎯 Testing payload: {payload}")
        print("-" * 40)
        
        for category in categories:
            if category in bypass.techniques:
                techniques = bypass.techniques[category]
                print(f"\n📁 {category.replace('_', ' ').title()}:")
                
                # Show first 3 techniques from each category
                for technique in techniques[:3]:
                    try:
                        result = technique['example'](payload)
                        if result != payload:
                            print(f"  • {technique['name']}: {result[:50]}{'...' if len(result) > 50 else ''}")
                    except Exception as e:
                        print(f"  • {technique['name']}: Error - {str(e)[:30]}...")
    
    # Demonstrate WAF-specific techniques
    print(f"\n🛡️ WAF-Specific Techniques:")
    print("-" * 40)
    
    wafs = ['Cloudflare', 'AWS WAF', 'ModSecurity', 'Imperva Incapsula']
    for waf in wafs:
        techniques = bypass.get_bypass_techniques(waf)
        print(f"\n{waf}: {len(techniques)} techniques available")
        
        # Show first 2 techniques for each WAF
        for technique in techniques[:2]:
            print(f"  • {technique['name']}")
    
    # Demonstrate payload generation
    print(f"\n🚀 Payload Generation Demo:")
    print("-" * 40)
    
    base_payload = "test' OR '1'='1"
    for waf in ['Cloudflare', 'ModSecurity']:
        payloads = bypass.generate_evasion_payloads(base_payload, waf)
        print(f"\n{waf} evasion payloads for '{base_payload}':")
        for i, payload in enumerate(payloads[:5], 1):  # Show first 5
            print(f"  {i}. {payload}")

if __name__ == "__main__":
    demo_bypass_techniques()