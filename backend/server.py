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
import hashlib

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
    
    # Check for file hashes first
    if re.match(IOC_PATTERNS['md5'], ioc):
        return 'md5', 'hash'
    if re.match(IOC_PATTERNS['sha1'], ioc):
        return 'sha1', 'hash'
    if re.match(IOC_PATTERNS['sha256'], ioc):
        return 'sha256', 'hash'
    
    # Check for IP addresses
    if re.match(IOC_PATTERNS['ipv4'], ioc):
        return 'ipv4', 'ip'
    if re.match(IOC_PATTERNS['ipv6'], ioc):
        return 'ipv6', 'ip'
    
    # Check for email
    if re.match(IOC_PATTERNS['email'], ioc):
        return 'email', 'email'
    
    # Check for URL
    if re.match(IOC_PATTERNS['url'], ioc):
        return 'url', 'url'
    
    # Check for domain
    if re.match(IOC_PATTERNS['domain'], ioc):
        return 'domain', 'domain'
    
    return 'unknown', 'unknown'

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
            # URL needs to be base64 encoded
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
            url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        elif category == 'hash':
            url = f'https://www.virustotal.com/api/v3/files/{ioc}'
        else:
            return VendorResult(vendor='VirusTotal', status='unsupported', error='IOC type not supported')
        
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                attrs = data.get('data', {}).get('attributes', {})
                
                result_data = {
                    'raw_response': data,
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': attrs.get('last_analysis_stats', {}),
                    'last_analysis_date': attrs.get('last_analysis_date'),
                    'country': attrs.get('country'),
                    'as_owner': attrs.get('as_owner'),
                    'malicious_count': attrs.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious_count': attrs.get('last_analysis_stats', {}).get('suspicious', 0),
                    'harmless_count': attrs.get('last_analysis_stats', {}).get('harmless', 0),
                    'undetected_count': attrs.get('last_analysis_stats', {}).get('undetected', 0)
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
        
        # Search for existing scans
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
        'recommendations': []
    }
    
    threat_scores = []
    
    for result in vendor_results:
        if result.status == 'success' and result.data:
            summary['successful_queries'] += 1
            data = result.data
            
            # VirusTotal analysis
            if result.vendor == 'VirusTotal':
                malicious = data.get('malicious_count', 0)
                suspicious = data.get('suspicious_count', 0)
                if malicious > 0:
                    summary['malicious_votes'] += malicious
                    threat_scores.append(min(100, malicious * 10 + suspicious * 5))
                    summary['key_findings'].append(f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections")
                if data.get('country'):
                    summary['geolocation']['country'] = data.get('country')
                if data.get('as_owner'):
                    summary['geolocation']['as_owner'] = data.get('as_owner')
            
            # AbuseIPDB analysis
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
            
            # GreyNoise analysis
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
            
            # AlienVault OTX analysis
            elif result.vendor == 'AlienVault OTX':
                pulse_count = data.get('pulse_count', 0)
                if pulse_count > 0:
                    threat_scores.append(min(100, pulse_count * 15))
                    summary['key_findings'].append(f"AlienVault OTX: Found in {pulse_count} threat pulses")
                if data.get('country_code'):
                    summary['geolocation']['country'] = data.get('country_code')
            
            # URLScan analysis
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
    
    # Calculate overall threat level
    if threat_scores:
        avg_score = sum(threat_scores) / len(threat_scores)
        summary['confidence'] = int(avg_score)
        
        if avg_score >= 70:
            summary['threat_level'] = 'high'
            summary['recommendations'].append('Block this IOC immediately')
            summary['recommendations'].append('Investigate any systems that communicated with this IOC')
        elif avg_score >= 40:
            summary['threat_level'] = 'medium'
            summary['recommendations'].append('Monitor traffic related to this IOC')
            summary['recommendations'].append('Consider blocking if suspicious activity continues')
        elif avg_score >= 10:
            summary['threat_level'] = 'low'
            summary['recommendations'].append('Continue monitoring')
        else:
            summary['threat_level'] = 'clean'
            summary['recommendations'].append('No immediate action required')
    else:
        if summary['successful_queries'] > 0:
            summary['threat_level'] = 'clean'
            summary['recommendations'].append('No threat indicators found')
        else:
            summary['recommendations'].append('Unable to determine threat level - check API connectivity')
    
    # Remove duplicates from tags
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
    
    # Query all threat intelligence sources concurrently
    async with aiohttp.ClientSession() as session:
        tasks = [
            query_virustotal(session, ioc, ioc_type, category),
            query_abuseipdb(session, ioc, ioc_type, category),
            query_urlscan(session, ioc, ioc_type, category),
            query_alienvault(session, ioc, ioc_type, category),
            query_greynoise(session, ioc, ioc_type, category)
        ]
        
        vendor_results = await asyncio.gather(*tasks)
    
    # Generate summary
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
                query_greynoise(session, ioc, ioc_type, category)
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
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.5)
    
    return {'results': results, 'total': len(results)}

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
            'greynoise': bool(GREYNOISE_API_KEY)
        }
    }

# Include the router in the main app
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
