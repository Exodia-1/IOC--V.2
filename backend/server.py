from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import re
import aiohttp
import asyncio
import dns.resolver

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# API Keys
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY', '')
ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY', '')
GREYNOISE_API_KEY = os.environ.get('GREYNOISE_API_KEY', '')

# Create the main app
app = FastAPI(title="SOC IOC Analysis Tool")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# IOC Type Detection Patterns
IOC_PATTERNS = {
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){0,6}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$',
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

# IOC Detection Functions
def detect_ioc_type(ioc: str) -> tuple:
    """Detect the type of IOC and return (type, category)"""
    ioc = ioc.strip()
    
    if re.match(IOC_PATTERNS['md5'], ioc):
        return 'md5', 'hash'
    if re.match(IOC_PATTERNS['sha1'], ioc):
        return 'sha1', 'hash'
    if re.match(IOC_PATTERNS['sha256'], ioc):
        return 'sha256', 'hash'
    if re.match(IOC_PATTERNS['ipv4'], ioc):
        return 'ipv4', 'ip'
    if re.match(IOC_PATTERNS['ipv6'], ioc):
        return 'ipv6', 'ip'
    if re.match(IOC_PATTERNS['email'], ioc):
        return 'email', 'email'
    if re.match(IOC_PATTERNS['url'], ioc):
        return 'url', 'url'
    if re.match(IOC_PATTERNS['domain'], ioc):
        return 'domain', 'domain'
    
    return 'unknown', 'unknown'

# Email Header Parser
def parse_email_headers(headers_text: str) -> Dict[str, Any]:
    """Parse email headers and extract security-relevant information"""
    result = {
        'from': None,
        'to': None,
        'subject': None,
        'date': None,
        'message_id': None,
        'return_path': None,
        'received_chain': [],
        'authentication': {
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'arc': None
        },
        'x_headers': {},
        'content_type': None,
        'reply_to': None,
        'originating_ip': None,
        'spam_score': None,
        'warnings': []
    }
    
    lines = headers_text.split('\n')
    current_header = None
    current_value = ''
    
    headers_dict = {}
    
    for line in lines:
        if line.startswith(' ') or line.startswith('\t'):
            current_value += ' ' + line.strip()
        else:
            if current_header:
                if current_header.lower() in headers_dict:
                    if isinstance(headers_dict[current_header.lower()], list):
                        headers_dict[current_header.lower()].append(current_value)
                    else:
                        headers_dict[current_header.lower()] = [headers_dict[current_header.lower()], current_value]
                else:
                    headers_dict[current_header.lower()] = current_value
            
            if ':' in line:
                current_header, current_value = line.split(':', 1)
                current_value = current_value.strip()
            else:
                current_header = None
                current_value = ''
    
    if current_header:
        headers_dict[current_header.lower()] = current_value
    
    # Extract standard headers
    result['from'] = headers_dict.get('from')
    result['to'] = headers_dict.get('to')
    result['subject'] = headers_dict.get('subject')
    result['date'] = headers_dict.get('date')
    result['message_id'] = headers_dict.get('message-id')
    result['return_path'] = headers_dict.get('return-path')
    result['reply_to'] = headers_dict.get('reply-to')
    result['content_type'] = headers_dict.get('content-type')
    
    # Extract received chain
    received = headers_dict.get('received', [])
    if isinstance(received, str):
        received = [received]
    result['received_chain'] = received
    
    # Extract originating IP from received headers
    for recv in result['received_chain']:
        ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', recv)
        if ip_match:
            result['originating_ip'] = ip_match.group(1)
            break
    
    # Extract authentication results
    auth_results = headers_dict.get('authentication-results', '')
    if auth_results:
        if 'spf=pass' in auth_results.lower():
            result['authentication']['spf'] = 'pass'
        elif 'spf=fail' in auth_results.lower():
            result['authentication']['spf'] = 'fail'
        elif 'spf=softfail' in auth_results.lower():
            result['authentication']['spf'] = 'softfail'
        elif 'spf=neutral' in auth_results.lower():
            result['authentication']['spf'] = 'neutral'
        elif 'spf=none' in auth_results.lower():
            result['authentication']['spf'] = 'none'
            
        if 'dkim=pass' in auth_results.lower():
            result['authentication']['dkim'] = 'pass'
        elif 'dkim=fail' in auth_results.lower():
            result['authentication']['dkim'] = 'fail'
        elif 'dkim=none' in auth_results.lower():
            result['authentication']['dkim'] = 'none'
            
        if 'dmarc=pass' in auth_results.lower():
            result['authentication']['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_results.lower():
            result['authentication']['dmarc'] = 'fail'
        elif 'dmarc=none' in auth_results.lower():
            result['authentication']['dmarc'] = 'none'
    
    # Check for ARC
    if 'arc-authentication-results' in headers_dict:
        result['authentication']['arc'] = 'present'
    
    # Extract X-headers
    for key, value in headers_dict.items():
        if key.startswith('x-'):
            result['x_headers'][key] = value
            if 'spam' in key.lower() and 'score' in key.lower():
                try:
                    score_match = re.search(r'[\d.]+', str(value))
                    if score_match:
                        result['spam_score'] = float(score_match.group())
                except Exception:
                    pass
    
    # Security warnings
    if result['authentication']['spf'] == 'fail':
        result['warnings'].append('SPF authentication failed - possible spoofing')
    if result['authentication']['dkim'] == 'fail':
        result['warnings'].append('DKIM authentication failed - message may be tampered')
    if result['authentication']['dmarc'] == 'fail':
        result['warnings'].append('DMARC authentication failed - domain alignment issue')
    if result['return_path'] and result['from']:
        from_domain = re.search(r'@([\w.-]+)', str(result['from']))
        return_domain = re.search(r'@([\w.-]+)', str(result['return_path']))
        if from_domain and return_domain and from_domain.group(1).lower() != return_domain.group(1).lower():
            result['warnings'].append('Return-Path domain differs from From domain')
    if result['reply_to'] and result['from']:
        from_domain = re.search(r'@([\w.-]+)', str(result['from']))
        reply_domain = re.search(r'@([\w.-]+)', str(result['reply_to']))
        if from_domain and reply_domain and from_domain.group(1).lower() != reply_domain.group(1).lower():
            result['warnings'].append('Reply-To domain differs from From domain')
    
    return result

# Threat Intelligence API Functions
async def query_virustotal(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query VirusTotal API"""
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        if category == 'ip':
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
        elif category == 'domain':
            url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
        elif category == 'url':
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
            url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        elif category == 'hash':
            url = f'https://www.virustotal.com/api/v3/files/{ioc}'
        elif category == 'email':
            domain = ioc.split('@')[1] if '@' in ioc else ioc
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        else:
            return VendorResult(vendor='VirusTotal', status='unsupported', error='IOC type not supported')
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                
                total_engines = sum([
                    stats.get('malicious', 0),
                    stats.get('suspicious', 0),
                    stats.get('harmless', 0),
                    stats.get('undetected', 0),
                    stats.get('timeout', 0)
                ])
                
                result_data = {
                    'raw_response': data,
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': stats,
                    'last_analysis_date': attrs.get('last_analysis_date'),
                    'country': attrs.get('country'),
                    'as_owner': attrs.get('as_owner'),
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'total_engines': total_engines
                }
                
                return VendorResult(vendor='VirusTotal', status='success', data=result_data)
            elif response.status == 404:
                return VendorResult(vendor='VirusTotal', status='not_found', data={'message': 'IOC not found in database'})
            else:
                return VendorResult(vendor='VirusTotal', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"VirusTotal error: {str(e)}")
        return VendorResult(vendor='VirusTotal', status='error', error=str(e))

async def query_abuseipdb(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query AbuseIPDB API"""
    try:
        if category != 'ip':
            return VendorResult(vendor='AbuseIPDB', status='unsupported', error='Only IP addresses supported')
        
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ioc,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        
        async with session.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params) as response:
            if response.status == 200:
                data = await response.json()
                result = data.get('data', {})
                
                result_data = {
                    'raw_response': data,
                    'abuse_confidence_score': result.get('abuseConfidenceScore'),
                    'total_reports': result.get('totalReports'),
                    'country_code': result.get('countryCode'),
                    'isp': result.get('isp'),
                    'domain': result.get('domain'),
                    'usage_type': result.get('usageType'),
                    'is_whitelisted': result.get('isWhitelisted'),
                    'is_tor': result.get('isTor'),
                    'last_reported_at': result.get('lastReportedAt'),
                    'num_distinct_users': result.get('numDistinctUsers')
                }
                
                return VendorResult(vendor='AbuseIPDB', status='success', data=result_data)
            else:
                return VendorResult(vendor='AbuseIPDB', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"AbuseIPDB error: {str(e)}")
        return VendorResult(vendor='AbuseIPDB', status='error', error=str(e))

async def query_urlscan(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query URLScan.io API"""
    try:
        if category not in ['url', 'domain', 'ip']:
            return VendorResult(vendor='URLScan', status='unsupported', error='Only URLs, domains, and IPs supported')
        
        headers = {'API-Key': URLSCAN_API_KEY}
        
        if category == 'url':
            search_query = f'page.url:"{ioc}"'
        elif category == 'domain':
            search_query = f'domain:{ioc}'
        else:
            search_query = f'ip:{ioc}'
        
        params = {'q': search_query, 'size': 10}
        
        async with session.get('https://urlscan.io/api/v1/search/', headers=headers, params=params) as response:
            if response.status == 200:
                data = await response.json()
                results = data.get('results', [])
                
                if results:
                    latest = results[0]
                    result_data = {
                        'raw_response': data,
                        'total_results': len(results),
                        'latest_scan': {
                            'uuid': latest.get('_id'),
                            'url': latest.get('page', {}).get('url'),
                            'domain': latest.get('page', {}).get('domain'),
                            'ip': latest.get('page', {}).get('ip'),
                            'country': latest.get('page', {}).get('country'),
                            'server': latest.get('page', {}).get('server'),
                            'status': latest.get('page', {}).get('status'),
                            'verdicts': latest.get('verdicts', {}),
                            'scan_time': latest.get('task', {}).get('time')
                        }
                    }
                    return VendorResult(vendor='URLScan', status='success', data=result_data)
                else:
                    return VendorResult(vendor='URLScan', status='not_found', data={'message': 'No scan results found'})
            else:
                return VendorResult(vendor='URLScan', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"URLScan error: {str(e)}")
        return VendorResult(vendor='URLScan', status='error', error=str(e))

async def query_alienvault(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query AlienVault OTX API"""
    try:
        headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
        
        if category == 'ip':
            url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general'
        elif category == 'domain':
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general'
        elif category == 'url':
            url = f'https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general'
        elif category == 'hash':
            url = f'https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general'
        elif category == 'email':
            domain = ioc.split('@')[1] if '@' in ioc else ioc
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
        else:
            return VendorResult(vendor='AlienVault OTX', status='unsupported', error='IOC type not supported')
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                
                result_data = {
                    'raw_response': data,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],
                    'reputation': data.get('reputation'),
                    'country_code': data.get('country_code'),
                    'asn': data.get('asn'),
                    'city': data.get('city'),
                    'validation': data.get('validation', []),
                    'sections': data.get('sections', [])
                }
                
                return VendorResult(vendor='AlienVault OTX', status='success', data=result_data)
            elif response.status == 404:
                return VendorResult(vendor='AlienVault OTX', status='not_found', data={'message': 'IOC not found'})
            else:
                return VendorResult(vendor='AlienVault OTX', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"AlienVault error: {str(e)}")
        return VendorResult(vendor='AlienVault OTX', status='error', error=str(e))

async def query_greynoise(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query GreyNoise API"""
    try:
        if category != 'ip':
            return VendorResult(vendor='GreyNoise', status='unsupported', error='Only IP addresses supported')
        
        headers = {
            'key': GREYNOISE_API_KEY,
            'Accept': 'application/json'
        }
        
        async with session.get(f'https://api.greynoise.io/v3/community/{ioc}', headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                
                result_data = {
                    'raw_response': data,
                    'noise': data.get('noise'),
                    'riot': data.get('riot'),
                    'classification': data.get('classification'),
                    'name': data.get('name'),
                    'link': data.get('link'),
                    'last_seen': data.get('last_seen'),
                    'message': data.get('message')
                }
                
                return VendorResult(vendor='GreyNoise', status='success', data=result_data)
            elif response.status == 404:
                return VendorResult(vendor='GreyNoise', status='not_found', data={'message': 'IP not found in GreyNoise database', 'classification': 'unknown'})
            else:
                return VendorResult(vendor='GreyNoise', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"GreyNoise error: {str(e)}")
        return VendorResult(vendor='GreyNoise', status='error', error=str(e))

async def query_ipinfo(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query IPInfo.io API (free tier)"""
    try:
        if category != 'ip':
            return VendorResult(vendor='IPInfo', status='unsupported', error='Only IP addresses supported')
        
        async with session.get(f'https://ipinfo.io/{ioc}/json') as response:
            if response.status == 200:
                data = await response.json()
                
                result_data = {
                    'raw_response': data,
                    'ip': data.get('ip'),
                    'hostname': data.get('hostname'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'location': data.get('loc'),
                    'org': data.get('org'),
                    'postal': data.get('postal'),
                    'timezone': data.get('timezone')
                }
                
                return VendorResult(vendor='IPInfo', status='success', data=result_data)
            else:
                return VendorResult(vendor='IPInfo', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"IPInfo error: {str(e)}")
        return VendorResult(vendor='IPInfo', status='error', error=str(e))

async def query_threatfox(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query ThreatFox API (abuse.ch)"""
    try:
        payload = {'query': 'search_ioc', 'search_term': ioc}
        
        async with session.post('https://threatfox-api.abuse.ch/api/v1/', json=payload) as response:
            if response.status == 200:
                data = await response.json()
                
                if data.get('query_status') == 'ok' and data.get('data'):
                    ioc_data = data.get('data', [])
                    result_data = {
                        'raw_response': data,
                        'found': True,
                        'count': len(ioc_data),
                        'iocs': [{
                            'id': item.get('id'),
                            'ioc_type': item.get('ioc_type'),
                            'threat_type': item.get('threat_type'),
                            'malware': item.get('malware'),
                            'malware_printable': item.get('malware_printable'),
                            'confidence_level': item.get('confidence_level'),
                            'first_seen': item.get('first_seen'),
                            'last_seen': item.get('last_seen'),
                            'reporter': item.get('reporter'),
                            'tags': item.get('tags', [])
                        } for item in ioc_data[:5]]
                    }
                    return VendorResult(vendor='ThreatFox', status='success', data=result_data)
                else:
                    return VendorResult(vendor='ThreatFox', status='not_found', data={'message': 'No threat data found', 'found': False})
            else:
                return VendorResult(vendor='ThreatFox', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"ThreatFox error: {str(e)}")
        return VendorResult(vendor='ThreatFox', status='error', error=str(e))

async def query_malwarebazaar(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query MalwareBazaar API (abuse.ch) for file hashes"""
    try:
        if category != 'hash':
            return VendorResult(vendor='MalwareBazaar', status='unsupported', error='Only file hashes supported')
        
        payload = {'query': 'get_info', 'hash': ioc}
        
        async with session.post('https://mb-api.abuse.ch/api/v1/', data=payload) as response:
            if response.status == 200:
                data = await response.json()
                
                if data.get('query_status') == 'ok' and data.get('data'):
                    sample = data.get('data', [{}])[0] if data.get('data') else {}
                    result_data = {
                        'raw_response': data,
                        'found': True,
                        'sha256_hash': sample.get('sha256_hash'),
                        'sha1_hash': sample.get('sha1_hash'),
                        'md5_hash': sample.get('md5_hash'),
                        'file_type': sample.get('file_type'),
                        'file_type_mime': sample.get('file_type_mime'),
                        'file_size': sample.get('file_size'),
                        'signature': sample.get('signature'),
                        'first_seen': sample.get('first_seen'),
                        'last_seen': sample.get('last_seen'),
                        'intelligence': sample.get('intelligence', {}),
                        'tags': sample.get('tags', []),
                        'origin_country': sample.get('origin_country'),
                        'delivery_method': sample.get('delivery_method')
                    }
                    return VendorResult(vendor='MalwareBazaar', status='success', data=result_data)
                else:
                    return VendorResult(vendor='MalwareBazaar', status='not_found', data={'message': 'Hash not found in MalwareBazaar', 'found': False})
            else:
                return VendorResult(vendor='MalwareBazaar', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"MalwareBazaar error: {str(e)}")
        return VendorResult(vendor='MalwareBazaar', status='error', error=str(e))

async def query_whois(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query WHOIS data via ip-api.com"""
    try:
        if category not in ['ip', 'domain', 'email']:
            return VendorResult(vendor='WHOIS', status='unsupported', error='Only IPs, domains and emails supported')
        
        lookup_target = ioc
        if category == 'email':
            lookup_target = ioc.split('@')[1] if '@' in ioc else ioc
        
        if category == 'ip':
            async with session.get(f'http://ip-api.com/json/{lookup_target}?fields=66846719') as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        result_data = {
                            'raw_response': data,
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'as': data.get('as'),
                            'as_name': data.get('asname'),
                            'reverse': data.get('reverse'),
                            'mobile': data.get('mobile'),
                            'proxy': data.get('proxy'),
                            'hosting': data.get('hosting')
                        }
                        return VendorResult(vendor='WHOIS', status='success', data=result_data)
                    else:
                        return VendorResult(vendor='WHOIS', status='error', error=data.get('message', 'Unknown error'))
                else:
                    return VendorResult(vendor='WHOIS', status='error', error=f'HTTP {response.status}')
        else:
            async with session.get(f'https://whois.freeaiapi.xyz/?name={lookup_target}') as response:
                if response.status == 200:
                    data = await response.json()
                    result_data = {
                        'raw_response': data,
                        'domain': data.get('domain_name'),
                        'registrar': data.get('registrar'),
                        'creation_date': data.get('creation_date'),
                        'expiration_date': data.get('expiration_date'),
                        'updated_date': data.get('updated_date'),
                        'name_servers': data.get('name_servers', []),
                        'status': data.get('status', []),
                        'dnssec': data.get('dnssec')
                    }
                    return VendorResult(vendor='WHOIS', status='success', data=result_data)
                else:
                    return VendorResult(vendor='WHOIS', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"WHOIS error: {str(e)}")
        return VendorResult(vendor='WHOIS', status='error', error=str(e))

async def query_shodan(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query Shodan InternetDB (free, no API key required)"""
    try:
        if category != 'ip':
            return VendorResult(vendor='Shodan', status='unsupported', error='Only IP addresses supported')
        
        async with session.get(f'https://internetdb.shodan.io/{ioc}') as response:
            if response.status == 200:
                data = await response.json()
                
                result_data = {
                    'raw_response': data,
                    'ip': data.get('ip'),
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'cpes': data.get('cpes', []),
                    'tags': data.get('tags', []),
                    'vulns': data.get('vulns', [])
                }
                
                return VendorResult(vendor='Shodan', status='success', data=result_data)
            elif response.status == 404:
                return VendorResult(vendor='Shodan', status='not_found', data={'message': 'IP not found in Shodan'})
            else:
                return VendorResult(vendor='Shodan', status='error', error=f'HTTP {response.status}')
    except Exception as e:
        logger.error(f"Shodan error: {str(e)}")
        return VendorResult(vendor='Shodan', status='error', error=str(e))

async def query_mxtoolbox(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Query MXToolbox-style DNS records for domain/email analysis"""
    try:
        if category not in ['domain', 'email']:
            return VendorResult(vendor='MXToolbox', status='unsupported', error='Only domains and emails supported')
        
        domain = ioc.split('@')[1] if '@' in ioc else ioc
        
        result_data = {
            'domain': domain,
            'mx_records': [],
            'txt_records': [],
            'spf_record': None,
            'dmarc_record': None,
            'dkim_selector': None,
            'a_records': [],
            'ns_records': [],
            'issues': []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # MX Records
        try:
            mx_answers = resolver.resolve(domain, 'MX')
            result_data['mx_records'] = [{'priority': r.preference, 'host': str(r.exchange).rstrip('.')} for r in mx_answers]
        except Exception:
            result_data['issues'].append('No MX records found')
        
        # TXT Records (including SPF)
        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            for r in txt_answers:
                txt_value = str(r).strip('"')
                result_data['txt_records'].append(txt_value)
                if txt_value.startswith('v=spf1'):
                    result_data['spf_record'] = txt_value
        except Exception:
            pass
        
        # DMARC Record
        try:
            dmarc_answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for r in dmarc_answers:
                txt_value = str(r).strip('"')
                if 'v=DMARC1' in txt_value:
                    result_data['dmarc_record'] = txt_value
        except Exception:
            result_data['issues'].append('No DMARC record found')
        
        # A Records
        try:
            a_answers = resolver.resolve(domain, 'A')
            result_data['a_records'] = [str(r) for r in a_answers]
        except Exception:
            pass
        
        # NS Records
        try:
            ns_answers = resolver.resolve(domain, 'NS')
            result_data['ns_records'] = [str(r).rstrip('.') for r in ns_answers]
        except Exception:
            pass
        
        # Check for common issues
        if not result_data['spf_record']:
            result_data['issues'].append('No SPF record found - email spoofing possible')
        elif '-all' not in result_data['spf_record'] and '~all' not in result_data['spf_record']:
            result_data['issues'].append('SPF record missing strict policy (-all or ~all)')
        
        if not result_data['dmarc_record']:
            result_data['issues'].append('No DMARC record - domain vulnerable to spoofing')
        
        return VendorResult(vendor='MXToolbox', status='success', data=result_data)
    except Exception as e:
        logger.error(f"MXToolbox error: {str(e)}")
        return VendorResult(vendor='MXToolbox', status='error', error=str(e))

async def query_email_domain(session: aiohttp.ClientSession, ioc: str, ioc_type: str, category: str) -> VendorResult:
    """Analyze email domain for security indicators"""
    try:
        if category != 'email':
            return VendorResult(vendor='Email Domain', status='unsupported', error='Only email addresses supported')
        
        domain = ioc.split('@')[1] if '@' in ioc else None
        if not domain:
            return VendorResult(vendor='Email Domain', status='error', error='Invalid email format')
        
        result_data = {
            'email': ioc,
            'domain': domain,
            'local_part': ioc.split('@')[0],
            'domain_age': None,
            'suspicious_patterns': [],
            'disposable': False,
            'free_provider': False,
            'business_domain': True
        }
        
        # Check for free email providers
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 
                         'mail.com', 'protonmail.com', 'icloud.com', 'yandex.com', 'gmx.com',
                         'zoho.com', 'tutanota.com', 'fastmail.com', 'live.com', 'msn.com']
        if domain.lower() in free_providers:
            result_data['free_provider'] = True
            result_data['business_domain'] = False
        
        # Check for disposable email patterns
        disposable_patterns = ['tempmail', 'throwaway', 'guerrilla', 'mailinator', '10minute',
                              'trashmail', 'fakeinbox', 'sharklasers', 'guerrillamail', 'maildrop']
        for pattern in disposable_patterns:
            if pattern in domain.lower():
                result_data['disposable'] = True
                result_data['suspicious_patterns'].append(f'Disposable email pattern: {pattern}')
        
        # Check local part for suspicious patterns
        local_part = result_data['local_part'].lower()
        if re.match(r'^[a-z]{1,2}\d{5,}', local_part):
            result_data['suspicious_patterns'].append('Local part matches bot pattern (letter + many numbers)')
        if len(local_part) > 30:
            result_data['suspicious_patterns'].append('Unusually long local part')
        if re.search(r'\d{8,}', local_part):
            result_data['suspicious_patterns'].append('Contains long number sequence')
        
        # Query domain creation via WHOIS
        try:
            async with session.get(f'https://whois.freeaiapi.xyz/?name={domain}') as response:
                if response.status == 200:
                    whois_data = await response.json()
                    result_data['domain_age'] = whois_data.get('creation_date')
                    result_data['registrar'] = whois_data.get('registrar')
        except Exception:
            pass
        
        return VendorResult(vendor='Email Domain', status='success', data=result_data)
    except Exception as e:
        logger.error(f"Email Domain error: {str(e)}")
        return VendorResult(vendor='Email Domain', status='error', error=str(e))

def generate_summary(vendor_results: List[VendorResult], ioc: str, ioc_type: str, category: str) -> Dict[str, Any]:
    """Generate consolidated summary from all vendor results"""
    summary = {
        'threat_level': 'unknown',
        'confidence': 0,
        'malicious_votes': 0,
        'total_sources': len(vendor_results),
        'successful_queries': 0,
        'key_findings': [],
        'geolocation': {},
        'tags': [],
        'open_ports': [],
        'vulnerabilities': [],
        'email_security': {},
        'dns_records': {}
    }
    
    threat_scores = []
    
    for result in vendor_results:
        if result.status == 'success' and result.data:
            summary['successful_queries'] += 1
            data = result.data
            
            if result.vendor == 'VirusTotal':
                malicious = data.get('malicious_count', 0)
                suspicious = data.get('suspicious_count', 0)
                total = data.get('total_engines', 0)
                if malicious > 0 or suspicious > 0:
                    summary['malicious_votes'] += malicious
                    threat_scores.append(min(100, malicious * 10 + suspicious * 5))
                    summary['key_findings'].append(f"VirusTotal: {malicious}/{total} malicious, {suspicious}/{total} suspicious")
                if data.get('country'):
                    summary['geolocation']['country'] = data.get('country')
                if data.get('as_owner'):
                    summary['geolocation']['as_owner'] = data.get('as_owner')
            
            elif result.vendor == 'AbuseIPDB':
                abuse_score = data.get('abuse_confidence_score', 0)
                if abuse_score > 0:
                    threat_scores.append(abuse_score)
                    summary['key_findings'].append(f"AbuseIPDB: {abuse_score}% abuse confidence, {data.get('total_reports', 0)} reports")
                if data.get('is_tor'):
                    summary['tags'].append('TOR Exit Node')
                if data.get('country_code'):
                    summary['geolocation']['country_code'] = data.get('country_code')
                if data.get('isp'):
                    summary['geolocation']['isp'] = data.get('isp')
            
            elif result.vendor == 'GreyNoise':
                classification = data.get('classification')
                if classification == 'malicious':
                    threat_scores.append(80)
                    summary['key_findings'].append("GreyNoise: Classified as malicious")
                elif classification == 'benign':
                    summary['key_findings'].append("GreyNoise: Classified as benign")
                    summary['tags'].append('Benign (GreyNoise)')
                if data.get('noise'):
                    summary['tags'].append('Internet Noise')
                if data.get('riot'):
                    summary['tags'].append('RIOT (Common Business Service)')
            
            elif result.vendor == 'AlienVault OTX':
                pulse_count = data.get('pulse_count', 0)
                if pulse_count > 0:
                    threat_scores.append(min(100, pulse_count * 15))
                    summary['key_findings'].append(f"AlienVault OTX: Found in {pulse_count} threat pulses")
                if data.get('country_code'):
                    summary['geolocation']['country'] = data.get('country_code')
            
            elif result.vendor == 'URLScan':
                latest = data.get('latest_scan', {})
                verdicts = latest.get('verdicts', {})
                if verdicts:
                    overall = verdicts.get('overall', {})
                    if overall.get('malicious'):
                        threat_scores.append(90)
                        summary['key_findings'].append("URLScan: Flagged as malicious")
                    summary['tags'].extend(overall.get('tags', []))
                if latest.get('country'):
                    summary['geolocation']['country'] = latest.get('country')
            
            elif result.vendor == 'ThreatFox':
                if data.get('found') and data.get('count', 0) > 0:
                    threat_scores.append(95)
                    iocs = data.get('iocs', [])
                    if iocs:
                        malware = iocs[0].get('malware_printable', 'Unknown')
                        summary['key_findings'].append(f"ThreatFox: Associated with {malware}")
                        for i in iocs:
                            summary['tags'].extend(i.get('tags', []))
            
            elif result.vendor == 'MalwareBazaar':
                if data.get('found'):
                    threat_scores.append(100)
                    signature = data.get('signature', 'Unknown')
                    summary['key_findings'].append(f"MalwareBazaar: Known malware - {signature}")
                    summary['tags'].extend(data.get('tags', []))
            
            elif result.vendor == 'Shodan':
                ports = data.get('ports', [])
                vulns = data.get('vulns', [])
                if ports:
                    summary['open_ports'] = ports
                    summary['key_findings'].append(f"Shodan: {len(ports)} open ports detected")
                if vulns:
                    threat_scores.append(min(100, len(vulns) * 20))
                    summary['vulnerabilities'] = vulns
                    summary['key_findings'].append(f"Shodan: {len(vulns)} known vulnerabilities")
                summary['tags'].extend(data.get('tags', []))
            
            elif result.vendor == 'IPInfo':
                if data.get('country'):
                    summary['geolocation']['country'] = data.get('country')
                if data.get('city'):
                    summary['geolocation']['city'] = data.get('city')
                if data.get('org'):
                    summary['geolocation']['org'] = data.get('org')
            
            elif result.vendor == 'WHOIS':
                if data.get('proxy'):
                    summary['tags'].append('Proxy')
                if data.get('hosting'):
                    summary['tags'].append('Hosting Provider')
                if data.get('mobile'):
                    summary['tags'].append('Mobile Network')
                if data.get('isp'):
                    summary['geolocation']['isp'] = data.get('isp')
                if data.get('country'):
                    summary['geolocation']['country'] = data.get('country')
            
            elif result.vendor == 'MXToolbox':
                mx_records = data.get('mx_records', [])
                if mx_records:
                    summary['dns_records']['mx'] = mx_records
                if data.get('spf_record'):
                    summary['dns_records']['spf'] = data.get('spf_record')
                    summary['email_security']['spf'] = 'present'
                else:
                    summary['email_security']['spf'] = 'missing'
                if data.get('dmarc_record'):
                    summary['dns_records']['dmarc'] = data.get('dmarc_record')
                    summary['email_security']['dmarc'] = 'present'
                else:
                    summary['email_security']['dmarc'] = 'missing'
                issues = data.get('issues', [])
                if issues:
                    for issue in issues:
                        summary['key_findings'].append(f"MXToolbox: {issue}")
                        if 'spoofing' in issue.lower():
                            threat_scores.append(40)
            
            elif result.vendor == 'Email Domain':
                if data.get('disposable'):
                    threat_scores.append(60)
                    summary['tags'].append('Disposable Email')
                    summary['key_findings'].append("Email Domain: Disposable email service detected")
                if data.get('free_provider'):
                    summary['tags'].append('Free Email Provider')
                suspicious = data.get('suspicious_patterns', [])
                if suspicious:
                    threat_scores.append(30)
                    for pattern in suspicious:
                        summary['key_findings'].append(f"Email Domain: {pattern}")
    
    # Calculate overall threat level
    if threat_scores:
        avg_score = sum(threat_scores) / len(threat_scores)
        summary['confidence'] = int(avg_score)
        
        if avg_score >= 70:
            summary['threat_level'] = 'high'
        elif avg_score >= 40:
            summary['threat_level'] = 'medium'
        elif avg_score >= 10:
            summary['threat_level'] = 'low'
        else:
            summary['threat_level'] = 'clean'
    else:
        if summary['successful_queries'] > 0:
            summary['threat_level'] = 'clean'
    
    summary['tags'] = list(set(summary['tags']))
    
    return summary

# API Endpoints
@api_router.get("/")
async def root():
    return {"message": "SOC IOC Analysis Tool API", "version": "1.0.0"}

@api_router.post("/detect", response_model=IOCDetection)
async def detect_ioc(request: IOCRequest):
    """Detect IOC type without querying threat intelligence"""
    ioc = request.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="IOC cannot be empty")
    ioc_type, category = detect_ioc_type(ioc)
    if category == 'unknown':
        raise HTTPException(status_code=400, detail=f"Unable to determine IOC type for: {ioc}")
    return IOCDetection(ioc=ioc, ioc_type=ioc_type, category=category)

@api_router.post("/analyze", response_model=IOCAnalysisResult)
async def analyze_ioc(request: IOCRequest):
    """Analyze a single IOC against all threat intelligence sources"""
    ioc = request.ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="IOC cannot be empty")
    
    ioc_type, category = detect_ioc_type(ioc)
    
    if category == 'unknown':
        raise HTTPException(status_code=400, detail=f"Unable to determine IOC type for: {ioc}")
    
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
        ioc=ioc,
        ioc_type=ioc_type,
        category=category,
        timestamp=datetime.now(timezone.utc).isoformat(),
        vendor_results=list(vendor_results),
        summary=summary
    )

@api_router.post("/analyze/bulk")
async def analyze_bulk_iocs(request: BulkIOCRequest):
    """Analyze multiple IOCs"""
    if not request.iocs:
        raise HTTPException(status_code=400, detail="IOC list cannot be empty")
    
    if len(request.iocs) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 IOCs per request")
    
    results = []
    
    async with aiohttp.ClientSession() as session:
        for ioc in request.iocs:
            ioc = ioc.strip()
            if not ioc:
                continue
                
            ioc_type, category = detect_ioc_type(ioc)
            
            if category == 'unknown':
                results.append({
                    'ioc': ioc,
                    'error': 'Unable to determine IOC type'
                })
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
                ioc=ioc,
                ioc_type=ioc_type,
                category=category,
                timestamp=datetime.now(timezone.utc).isoformat(),
                vendor_results=list(vendor_results),
                summary=summary
            ).model_dump())
            
            await asyncio.sleep(0.5)
    
    return {'results': results, 'total': len(results)}

@api_router.post("/analyze/email-headers")
async def analyze_email_headers(request: EmailHeaderRequest):
    """Analyze email headers for security indicators"""
    if not request.headers.strip():
        raise HTTPException(status_code=400, detail="Email headers cannot be empty")
    
    parsed = parse_email_headers(request.headers)
    
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'analysis': parsed
    }

@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'services': {
            'virustotal': bool(VIRUSTOTAL_API_KEY),
            'abuseipdb': bool(ABUSEIPDB_API_KEY),
            'urlscan': bool(URLSCAN_API_KEY),
            'alienvault': bool(ALIENVAULT_API_KEY),
            'greynoise': bool(GREYNOISE_API_KEY),
            'ipinfo': True,
            'threatfox': True,
            'malwarebazaar': True,
            'whois': True,
            'shodan': True,
            'mxtoolbox': True,
            'email_domain': True
        }
    }

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
