from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os
import re
import aiohttp
import asyncio
import uuid
from datetime import datetime, timezone
import dns.resolver
import whois

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Keys from environment
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY', '')
ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY', '')
GREYNOISE_API_KEY = os.environ.get('GREYNOISE_API_KEY', '')

# IOC Patterns
IOC_PATTERNS = {
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
    'md5': r'^[a-fA-F0-9]{32}$',
    'sha1': r'^[a-fA-F0-9]{40}$',
    'sha256': r'^[a-fA-F0-9]{64}$',
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'url': r'^https?://[^\s/$.?#].[^\s]*$',
    'domain': r'^(?!https?://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
}

# Pydantic Models
class IOCRequest(BaseModel):
    ioc: str

class BulkIOCRequest(BaseModel):
    iocs: List[str]

class EmailHeaderRequest(BaseModel):
    headers: str

class IOCDetection(BaseModel):
    ioc: str
    ioc_type: str
    category: str

class VendorResult(BaseModel):
    vendor: str
    status: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class IOCAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc: str
    ioc_type: str
    category: str
    timestamp: str
    vendor_results: List[VendorResult]
    summary: Dict[str, Any]

def detect_ioc_type(ioc: str) -> tuple:
    ioc = ioc.strip()
    if re.match(IOC_PATTERNS['md5'], ioc): return 'md5', 'hash'
    if re.match(IOC_PATTERNS['sha1'], ioc): return 'sha1', 'hash'
    if re.match(IOC_PATTERNS['sha256'], ioc): return 'sha256', 'hash'
    if re.match(IOC_PATTERNS['ipv4'], ioc): return 'ipv4', 'ip'
    if re.match(IOC_PATTERNS['ipv6'], ioc): return 'ipv6', 'ip'
    if re.match(IOC_PATTERNS['email'], ioc): return 'email', 'email'
    if re.match(IOC_PATTERNS['url'], ioc): return 'url', 'url'
    if re.match(IOC_PATTERNS['domain'], ioc): return 'domain', 'domain'
    return 'unknown', 'unknown'

# Email Header Parser
def parse_email_headers(headers_text: str) -> Dict[str, Any]:
    result = {
        'from': None, 'to': None, 'subject': None, 'date': None,
        'message_id': None, 'return_path': None, 'received_chain': [],
        'authentication': {'spf': None, 'dkim': None, 'dmarc': None, 'arc': None},
        'x_headers': {}, 'originating_ip': None, 'warnings': []
    }
    
    lines = headers_text.split('\n')
    headers_dict = {}
    current_header, current_value = None, ''
    
    for line in lines:
        if line.startswith(' ') or line.startswith('\t'):
            current_value += ' ' + line.strip()
        else:
            if current_header:
                key = current_header.lower()
                if key in headers_dict:
                    if isinstance(headers_dict[key], list):
                        headers_dict[key].append(current_value)
                    else:
                        headers_dict[key] = [headers_dict[key], current_value]
                else:
                    headers_dict[key] = current_value
            if ':' in line:
                current_header, current_value = line.split(':', 1)
                current_value = current_value.strip()
            else:
                current_header, current_value = None, ''
    
    if current_header:
        headers_dict[current_header.lower()] = current_value
    
    result['from'] = headers_dict.get('from')
    result['to'] = headers_dict.get('to')
    result['subject'] = headers_dict.get('subject')
    result['date'] = headers_dict.get('date')
    result['return_path'] = headers_dict.get('return-path')
    
    received = headers_dict.get('received', [])
    if isinstance(received, str): received = [received]
    result['received_chain'] = received
    
    for recv in result['received_chain']:
        ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', recv)
        if ip_match:
            result['originating_ip'] = ip_match.group(1)
            break
    
    auth_results = headers_dict.get('authentication-results', '')
    if auth_results:
        if 'spf=pass' in auth_results.lower(): result['authentication']['spf'] = 'pass'
        elif 'spf=fail' in auth_results.lower(): result['authentication']['spf'] = 'fail'
        if 'dkim=pass' in auth_results.lower(): result['authentication']['dkim'] = 'pass'
        elif 'dkim=fail' in auth_results.lower(): result['authentication']['dkim'] = 'fail'
        if 'dmarc=pass' in auth_results.lower(): result['authentication']['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_results.lower(): result['authentication']['dmarc'] = 'fail'
    
    if result['authentication']['spf'] == 'fail':
        result['warnings'].append('SPF authentication failed - possible spoofing')
    if result['authentication']['dkim'] == 'fail':
        result['warnings'].append('DKIM authentication failed')
    
    return result

# Threat Intelligence Functions
async def query_virustotal(session, ioc, ioc_type, category):
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        if category == 'ip': url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
        elif category == 'domain': url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
        elif category == 'hash': url = f'https://www.virustotal.com/api/v3/files/{ioc}'
        elif category == 'email':
            domain = ioc.split('@')[1]
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        else: return VendorResult(vendor='VirusTotal', status='unsupported')
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                total = sum([stats.get('malicious', 0), stats.get('suspicious', 0), stats.get('harmless', 0), stats.get('undetected', 0)])
                return VendorResult(vendor='VirusTotal', status='success', data={
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'total_engines': total,
                    'country': attrs.get('country'),
                    'as_owner': attrs.get('as_owner')
                })
            return VendorResult(vendor='VirusTotal', status='not_found' if response.status == 404 else 'error')
    except Exception as e:
        return VendorResult(vendor='VirusTotal', status='error', error=str(e))

async def query_abuseipdb(session, ioc, ioc_type, category):
    if category != 'ip': return VendorResult(vendor='AbuseIPDB', status='unsupported', error='Only IP addresses supported')
    try:
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ioc, 'maxAgeInDays': '90'}
        async with session.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params) as response:
            if response.status == 200:
                data = await response.json()
                result = data.get('data', {})
                return VendorResult(vendor='AbuseIPDB', status='success', data={
                    'abuse_confidence_score': result.get('abuseConfidenceScore'),
                    'total_reports': result.get('totalReports'),
                    'country_code': result.get('countryCode'),
                    'isp': result.get('isp'),
                    'is_tor': result.get('isTor'),
                    'num_distinct_users': result.get('numDistinctUsers')
                })
            return VendorResult(vendor='AbuseIPDB', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        return VendorResult(vendor='AbuseIPDB', status='error', error=str(e))

async def query_greynoise(session, ioc, ioc_type, category):
    if category != 'ip': return VendorResult(vendor='GreyNoise', status='unsupported', error='Only IP addresses supported')
    try:
        headers = {'key': GREYNOISE_API_KEY, 'Accept': 'application/json'}
        async with session.get(f'https://api.greynoise.io/v3/community/{ioc}', headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return VendorResult(vendor='GreyNoise', status='success', data={
                    'noise': data.get('noise'),
                    'riot': data.get('riot'),
                    'classification': data.get('classification'),
                    'name': data.get('name'),
                    'last_seen': data.get('last_seen')
                })
            return VendorResult(vendor='GreyNoise', status='not_found' if response.status == 404 else 'error')
    except Exception as e:
        return VendorResult(vendor='GreyNoise', status='error', error=str(e))

async def query_alienvault(session, ioc, ioc_type, category):
    try:
        headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
        if category == 'ip': url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general'
        elif category == 'domain': url = f'https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general'
        elif category == 'hash': url = f'https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general'
        elif category == 'email':
            domain = ioc.split('@')[1]
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
        else: return VendorResult(vendor='AlienVault OTX', status='unsupported')
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return VendorResult(vendor='AlienVault OTX', status='success', data={
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],
                    'country_code': data.get('country_code')
                })
            return VendorResult(vendor='AlienVault OTX', status='not_found' if response.status == 404 else 'error')
    except Exception as e:
        return VendorResult(vendor='AlienVault OTX', status='error', error=str(e))

async def query_urlscan(session, ioc, ioc_type, category):
    if category not in ['url', 'domain', 'ip']: return VendorResult(vendor='URLScan', status='unsupported')
    try:
        headers = {'API-Key': URLSCAN_API_KEY}
        query = f'domain:{ioc}' if category == 'domain' else f'ip:{ioc}' if category == 'ip' else f'page.url:"{ioc}"'
        async with session.get(f'https://urlscan.io/api/v1/search/?q={query}&size=5', headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                results = data.get('results', [])
                if results:
                    latest = results[0]
                    return VendorResult(vendor='URLScan', status='success', data={
                        'total_results': len(results),
                        'latest_scan': {
                            'domain': latest.get('page', {}).get('domain'),
                            'ip': latest.get('page', {}).get('ip'),
                            'country': latest.get('page', {}).get('country')
                        }
                    })
                return VendorResult(vendor='URLScan', status='not_found')
            return VendorResult(vendor='URLScan', status='error')
    except Exception as e:
        return VendorResult(vendor='URLScan', status='error', error=str(e))

async def query_shodan(session, ioc, ioc_type, category):
    if category != 'ip': return VendorResult(vendor='Shodan', status='unsupported', error='Only IP addresses supported')
    try:
        async with session.get(f'https://internetdb.shodan.io/{ioc}') as response:
            if response.status == 200:
                data = await response.json()
                return VendorResult(vendor='Shodan', status='success', data={
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'vulns': data.get('vulns', []),
                    'tags': data.get('tags', [])
                })
            return VendorResult(vendor='Shodan', status='not_found' if response.status == 404 else 'error')
    except Exception as e:
        return VendorResult(vendor='Shodan', status='error', error=str(e))

async def query_ipinfo(session, ioc, ioc_type, category):
    if category != 'ip': return VendorResult(vendor='IPInfo', status='unsupported', error='Only IP addresses supported')
    try:
        async with session.get(f'https://ipinfo.io/{ioc}/json') as response:
            if response.status == 200:
                data = await response.json()
                return VendorResult(vendor='IPInfo', status='success', data={
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'org': data.get('org'),
                    'hostname': data.get('hostname')
                })
            return VendorResult(vendor='IPInfo', status='error')
    except Exception as e:
        return VendorResult(vendor='IPInfo', status='error', error=str(e))

async def query_whois(session, ioc, ioc_type, category):
    if category not in ['ip', 'domain', 'email']: return VendorResult(vendor='WHOIS', status='unsupported')
    try:
        lookup = ioc.split('@')[1] if category == 'email' else ioc
        if category == 'ip':
            async with session.get(f'http://ip-api.com/json/{lookup}?fields=66846719') as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return VendorResult(vendor='WHOIS', status='success', data={
                            'country': data.get('country'),
                            'city': data.get('city'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'proxy': data.get('proxy'),
                            'hosting': data.get('hosting'),
                            'mobile': data.get('mobile')
                        })
        else:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, lookup)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            ns = w.name_servers or []
            if isinstance(ns, str): ns = [ns]
            return VendorResult(vendor='WHOIS', status='success', data={
                'registrar': w.registrar,
                'creation_date': creation.strftime('%Y-%m-%d') if creation else None,
                'expiration_date': expiration.strftime('%Y-%m-%d') if expiration else None,
                'name_servers': list(set([n.lower() for n in ns]))[:6]
            })
    except Exception as e:
        return VendorResult(vendor='WHOIS', status='error', error=str(e))

async def query_mxtoolbox(session, ioc, ioc_type, category):
    if category not in ['domain', 'email']: return VendorResult(vendor='MXToolbox', status='unsupported')
    try:
        domain = ioc.split('@')[1] if '@' in ioc else ioc
        result_data = {'domain': domain, 'mx_records': [], 'spf_record': None, 'dmarc_record': None, 'issues': []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        try:
            mx = resolver.resolve(domain, 'MX')
            result_data['mx_records'] = [{'priority': r.preference, 'host': str(r.exchange).rstrip('.')} for r in mx]
        except: result_data['issues'].append('No MX records')
        
        try:
            txt = resolver.resolve(domain, 'TXT')
            for r in txt:
                val = str(r).strip('"')
                if val.startswith('v=spf1'): result_data['spf_record'] = val
        except: pass
        
        try:
            dmarc = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for r in dmarc:
                val = str(r).strip('"')
                if 'v=DMARC1' in val: result_data['dmarc_record'] = val
        except: result_data['issues'].append('No DMARC record')
        
        if not result_data['spf_record']: result_data['issues'].append('No SPF record')
        return VendorResult(vendor='MXToolbox', status='success', data=result_data)
    except Exception as e:
        return VendorResult(vendor='MXToolbox', status='error', error=str(e))

async def query_email_domain(session, ioc, ioc_type, category):
    if category != 'email': return VendorResult(vendor='Email Domain', status='unsupported')
    try:
        domain = ioc.split('@')[1]
        local = ioc.split('@')[0]
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com', 'icloud.com']
        disposable = ['tempmail', 'throwaway', 'guerrilla', 'mailinator', '10minute']
        
        data = {'email': ioc, 'domain': domain, 'free_provider': domain.lower() in free_providers, 'disposable': False, 'suspicious_patterns': []}
        for d in disposable:
            if d in domain.lower(): data['disposable'] = True
        if len(local) > 30: data['suspicious_patterns'].append('Unusually long local part')
        
        return VendorResult(vendor='Email Domain', status='success', data=data)
    except Exception as e:
        return VendorResult(vendor='Email Domain', status='error', error=str(e))

async def query_malwarebazaar(session, ioc, ioc_type, category):
    if category != 'hash': return VendorResult(vendor='MalwareBazaar', status='unsupported', error='Only file hashes supported')
    try:
        async with session.post('https://mb-api.abuse.ch/api/v1/', data={'query': 'get_info', 'hash': ioc}) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    sample = data['data'][0]
                    return VendorResult(vendor='MalwareBazaar', status='success', data={
                        'found': True,
                        'signature': sample.get('signature'),
                        'file_type': sample.get('file_type'),
                        'file_size': sample.get('file_size'),
                        'tags': sample.get('tags', [])
                    })
                return VendorResult(vendor='MalwareBazaar', status='not_found', data={'found': False})
            return VendorResult(vendor='MalwareBazaar', status='error')
    except Exception as e:
        return VendorResult(vendor='MalwareBazaar', status='error', error=str(e))

def generate_summary(vendor_results, ioc, ioc_type, category):
    summary = {'threat_level': 'unknown', 'confidence': 0, 'malicious_votes': 0, 'total_sources': len(vendor_results),
               'successful_queries': 0, 'key_findings': [], 'geolocation': {}, 'tags': [], 'open_ports': [],
               'vulnerabilities': [], 'email_security': {}, 'dns_records': {}}
    threat_scores = []
    
    for r in vendor_results:
        if r.status == 'success' and r.data:
            summary['successful_queries'] += 1
            d = r.data
            
            if r.vendor == 'VirusTotal':
                mal, sus, total = d.get('malicious_count', 0), d.get('suspicious_count', 0), d.get('total_engines', 0)
                if mal > 0 or sus > 0:
                    summary['malicious_votes'] += mal
                    threat_scores.append(min(100, mal * 10 + sus * 5))
                    summary['key_findings'].append(f"VirusTotal: {mal}/{total} malicious, {sus}/{total} suspicious")
            elif r.vendor == 'AbuseIPDB':
                score = d.get('abuse_confidence_score', 0)
                if score > 0:
                    threat_scores.append(score)
                    summary['key_findings'].append(f"AbuseIPDB: {score}% abuse confidence")
                if d.get('is_tor'): summary['tags'].append('TOR Exit Node')
            elif r.vendor == 'GreyNoise':
                if d.get('classification') == 'malicious':
                    threat_scores.append(80)
                    summary['key_findings'].append('GreyNoise: Classified as malicious')
                elif d.get('classification') == 'benign':
                    summary['tags'].append('Benign (GreyNoise)')
                if d.get('riot'): summary['tags'].append('RIOT')
            elif r.vendor == 'AlienVault OTX':
                pulses = d.get('pulse_count', 0)
                if pulses > 0:
                    threat_scores.append(min(100, pulses * 15))
                    summary['key_findings'].append(f"AlienVault: {pulses} threat pulses")
            elif r.vendor == 'Shodan':
                ports, vulns = d.get('ports', []), d.get('vulns', [])
                if ports: summary['open_ports'] = ports
                if vulns:
                    threat_scores.append(min(100, len(vulns) * 20))
                    summary['vulnerabilities'] = vulns
            elif r.vendor == 'MalwareBazaar':
                if d.get('found'):
                    threat_scores.append(100)
                    summary['key_findings'].append(f"MalwareBazaar: Known malware - {d.get('signature', 'Unknown')}")
            elif r.vendor == 'MXToolbox':
                summary['email_security']['spf'] = 'present' if d.get('spf_record') else 'missing'
                summary['email_security']['dmarc'] = 'present' if d.get('dmarc_record') else 'missing'
            elif r.vendor == 'Email Domain':
                if d.get('disposable'):
                    threat_scores.append(60)
                    summary['tags'].append('Disposable Email')
                if d.get('free_provider'): summary['tags'].append('Free Email Provider')
    
    if threat_scores:
        avg = sum(threat_scores) / len(threat_scores)
        summary['confidence'] = int(avg)
        if avg >= 70: summary['threat_level'] = 'high'
        elif avg >= 40: summary['threat_level'] = 'medium'
        elif avg >= 10: summary['threat_level'] = 'low'
        else: summary['threat_level'] = 'clean'
    elif summary['successful_queries'] > 0:
        summary['threat_level'] = 'clean'
    
    summary['tags'] = list(set(summary['tags']))
    return summary

@app.get("/api")
async def root():
    return {"message": "SOC IOC Analysis API", "version": "1.0"}

@app.post("/api/detect")
async def detect_ioc_endpoint(request: IOCRequest):
    ioc = request.ioc.strip()
    if not ioc: raise HTTPException(400, "IOC cannot be empty")
    ioc_type, category = detect_ioc_type(ioc)
    if category == 'unknown': raise HTTPException(400, f"Unable to determine IOC type: {ioc}")
    return IOCDetection(ioc=ioc, ioc_type=ioc_type, category=category)

@app.post("/api/analyze")
async def analyze_ioc_endpoint(request: IOCRequest):
    ioc = request.ioc.strip()
    if not ioc: raise HTTPException(400, "IOC cannot be empty")
    ioc_type, category = detect_ioc_type(ioc)
    if category == 'unknown': raise HTTPException(400, f"Unable to determine IOC type: {ioc}")
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            query_virustotal(session, ioc, ioc_type, category),
            query_abuseipdb(session, ioc, ioc_type, category),
            query_urlscan(session, ioc, ioc_type, category),
            query_alienvault(session, ioc, ioc_type, category),
            query_greynoise(session, ioc, ioc_type, category),
            query_ipinfo(session, ioc, ioc_type, category),
            query_malwarebazaar(session, ioc, ioc_type, category),
            query_whois(session, ioc, ioc_type, category),
            query_shodan(session, ioc, ioc_type, category),
            query_mxtoolbox(session, ioc, ioc_type, category),
            query_email_domain(session, ioc, ioc_type, category)
        ]
        vendor_results = await asyncio.gather(*tasks)
    
    summary = generate_summary(list(vendor_results), ioc, ioc_type, category)
    return IOCAnalysisResult(
        ioc=ioc, ioc_type=ioc_type, category=category,
        timestamp=datetime.now(timezone.utc).isoformat(),
        vendor_results=list(vendor_results), summary=summary
    )

@app.post("/api/analyze/bulk")
async def analyze_bulk_endpoint(request: BulkIOCRequest):
    if not request.iocs: raise HTTPException(400, "IOC list cannot be empty")
    if len(request.iocs) > 20: raise HTTPException(400, "Maximum 20 IOCs per request")
    
    results = []
    async with aiohttp.ClientSession() as session:
        for ioc in request.iocs:
            ioc = ioc.strip()
            if not ioc: continue
            ioc_type, category = detect_ioc_type(ioc)
            if category == 'unknown':
                results.append({'ioc': ioc, 'error': 'Unable to determine IOC type'})
                continue
            
            tasks = [
                query_virustotal(session, ioc, ioc_type, category),
                query_abuseipdb(session, ioc, ioc_type, category),
                query_urlscan(session, ioc, ioc_type, category),
                query_alienvault(session, ioc, ioc_type, category),
                query_greynoise(session, ioc, ioc_type, category),
                query_ipinfo(session, ioc, ioc_type, category),
                query_malwarebazaar(session, ioc, ioc_type, category),
                query_whois(session, ioc, ioc_type, category),
                query_shodan(session, ioc, ioc_type, category),
                query_mxtoolbox(session, ioc, ioc_type, category),
                query_email_domain(session, ioc, ioc_type, category)
            ]
            vendor_results = await asyncio.gather(*tasks)
            summary = generate_summary(list(vendor_results), ioc, ioc_type, category)
            results.append(IOCAnalysisResult(
                ioc=ioc, ioc_type=ioc_type, category=category,
                timestamp=datetime.now(timezone.utc).isoformat(),
                vendor_results=list(vendor_results), summary=summary
            ).model_dump())
            await asyncio.sleep(0.3)
    return {'results': results, 'total': len(results)}

@app.post("/api/analyze/email-headers")
async def analyze_headers_endpoint(request: EmailHeaderRequest):
    if not request.headers.strip(): raise HTTPException(400, "Headers cannot be empty")
    return {'timestamp': datetime.now(timezone.utc).isoformat(), 'analysis': parse_email_headers(request.headers)}

@app.get("/api/health")
async def health():
    return {'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()}
