import { useState } from "react";
import "./App.css";
import axios from "axios";
import { toast, Toaster } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "components/ui/tabs";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "components/ui/card";
import { Input } from "components/ui/input";
import { Button } from "components/ui/button";
import { Badge } from "components/ui/badge";
import { Textarea } from "components/ui/textarea";
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle,
  Globe, 
  Server, 
  Mail, 
  Hash, 
  Link2, 
  Loader2,
  Info,
  AlertCircle,
  Clock,
  ChevronRight,
  Zap,
  FileText,
  ShieldCheck,
  ShieldX,
  ShieldAlert,
  ExternalLink,
  TrendingUp
} from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "components/ui/tooltip";
import { Progress } from "components/ui/progress";

const API = '/api';

const IOCTypeIcon = ({ category, size = "w-5 h-5" }) => {
  switch(category) {
    case 'ip': return <Server className={size} />;
    case 'domain': return <Globe className={size} />;
    case 'url': return <Link2 className={size} />;
    case 'email': return <Mail className={size} />;
    case 'hash': return <Hash className={size} />;
    default: return <Shield className={size} />;
  }
};

const ThreatBadge = ({ level }) => {
  const configs = {
    'critical': { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', icon: ShieldX },
    'high': { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', icon: ShieldAlert },
    'medium': { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', icon: AlertTriangle },
    'low': { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', icon: Info },
    'clean': { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', icon: ShieldCheck },
  };
  const config = configs[level] || configs['low'];
  const Icon = config.icon;
  
  return (
    <Badge variant="outline" className={`${config.bg} ${config.text} ${config.border} border px-3 py-1.5 text-sm font-medium`}>
      <Icon className="w-3.5 h-3.5 mr-1.5" />
      {level.charAt(0).toUpperCase() + level.slice(1)} Risk
    </Badge>
  );
};

const VendorStatusBadge = ({ status }) => {
  if (status === 'success') return <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">Active</Badge>;
  if (status === 'error') return <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">Error</Badge>;
  if (status === 'not_found') return <Badge variant="outline" className="bg-slate-600/50 text-slate-400 border-slate-600 text-xs">No Data</Badge>;
  return <Badge variant="outline" className="bg-slate-600/50 text-slate-400 border-slate-600 text-xs">{status}</Badge>;
};

const VendorCard = ({ result, ioc, iocType, category }) => {
  const { vendor, status, data, error } = result;
  
  const getVendorUrl = () => {
    const encodedIOC = encodeURIComponent(ioc);
    
    switch (vendor) {
      case 'VirusTotal':
        if (category === 'ip') return `https://www.virustotal.com/gui/ip-address/${encodedIOC}`;
        if (category === 'domain') return `https://www.virustotal.com/gui/domain/${encodedIOC}`;
        if (category === 'url') return `https://www.virustotal.com/gui/url/${btoa(ioc)}/detection`;
        if (category === 'hash') return `https://www.virustotal.com/gui/file/${encodedIOC}`;
        return `https://www.virustotal.com/gui/search/${encodedIOC}`;
      case 'AbuseIPDB':
        return `https://www.abuseipdb.com/check/${encodedIOC}`;
      case 'GreyNoise':
        return `https://viz.greynoise.io/ip/${encodedIOC}`;
      case 'AlienVault OTX':
        if (category === 'ip') return `https://otx.alienvault.com/indicator/ip/${encodedIOC}`;
        if (category === 'domain') return `https://otx.alienvault.com/indicator/domain/${encodedIOC}`;
        if (category === 'hash') return `https://otx.alienvault.com/indicator/file/${encodedIOC}`;
        if (category === 'url') return `https://otx.alienvault.com/indicator/url/${encodedIOC}`;
        return `https://otx.alienvault.com/`;
      case 'URLScan':
        return `https://urlscan.io/search/#${encodedIOC}`;
      case 'Shodan':
        return `https://www.shodan.io/host/${encodedIOC}`;
      case 'IPInfo':
        return `https://ipinfo.io/${encodedIOC}`;
      case 'WHOIS':
        if (category === 'ip') return `https://who.is/whois-ip/ip-address/${encodedIOC}`;
        return `https://who.is/whois/${encodedIOC}`;
      case 'MalwareBazaar':
        return `https://bazaar.abuse.ch/browse/`;
      case 'MXToolbox':
        const domain = ioc.includes('@') ? ioc.split('@')[1] : ioc;
        return `https://mxtoolbox.com/SuperTool.aspx?action=mx:${encodeURIComponent(domain)}`;
      case 'Email Domain':
        const emailDomain = ioc.split('@')[1];
        return `https://who.is/whois/${encodeURIComponent(emailDomain)}`;
      default:
        return null;
    }
  };
  
  const vendorUrl = getVendorUrl();
  
  const renderVendorData = () => {
    if (status === 'error') {
      return (
        <div className="flex items-center gap-2 text-sm text-red-400/80">
          <AlertCircle className="w-4 h-4" />
          <p>{error || 'Failed to fetch data'}</p>
        </div>
      );
    }
    
    if (status !== 'success' || !data) {
      return (
        <p className="text-sm text-slate-500">
          {error || (status === 'not_found' ? 'No data available for this IOC' : 'Data not available')}
        </p>
      );
    }
    
    switch (vendor) {
      case 'VirusTotal':
        const total = data.total_engines || 0;
        return (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-slate-800/30 rounded-lg p-2.5">
                <p className="text-xs text-slate-400 mb-1">Malicious</p>
                <p className="text-lg font-semibold text-red-400">
                  {data.malicious_count || 0}
                  <span className="text-xs text-slate-500 font-normal ml-1">/{total}</span>
                </p>
              </div>
              <div className="bg-slate-800/30 rounded-lg p-2.5">
                <p className="text-xs text-slate-400 mb-1">Suspicious</p>
                <p className="text-lg font-semibold text-orange-400">
                  {data.suspicious_count || 0}
                  <span className="text-xs text-slate-500 font-normal ml-1">/{total}</span>
                </p>
              </div>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="bg-slate-800/30 rounded-lg p-2.5 cursor-help">
                      <p className="text-xs text-slate-400 mb-1 flex items-center gap-1">
                        Harmless
                        <Info className="w-3 h-3" />
                      </p>
                      <p className="text-lg font-semibold text-emerald-400">
                        {data.harmless_count || 0}
                        <span className="text-xs text-slate-500 font-normal ml-1">/{total}</span>
                      </p>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p className="text-xs">Engines actively determined this IOC is <strong>safe and benign</strong></p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="bg-slate-800/30 rounded-lg p-2.5 cursor-help">
                      <p className="text-xs text-slate-400 mb-1 flex items-center gap-1">
                        Undetected
                        <Info className="w-3 h-3" />
                      </p>
                      <p className="text-lg font-semibold text-slate-400">
                        {data.undetected_count || 0}
                        <span className="text-xs text-slate-500 font-normal ml-1">/{total}</span>
                      </p>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p className="text-xs">Engines scanned but <strong>found no threats</strong> (neutral result)</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
            {(data.country || data.as_owner) && (
              <div className="text-xs text-slate-400 space-y-1 border-t border-slate-700/50 pt-2">
                {data.country && <p>Country: {data.country}</p>}
                {data.as_owner && <p>Owner: {data.as_owner}</p>}
              </div>
            )}
          </div>
        );
        
      case 'AbuseIPDB':
        return (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">Confidence Score</span>
              <span className="text-sm font-semibold text-slate-200">{data.abuse_confidence_score}%</span>
            </div>
            <Progress value={data.abuse_confidence_score} className="h-1.5" />
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <p className="text-slate-400">Reports</p>
                <p className="text-slate-200 font-medium">{data.total_reports || 0}</p>
              </div>
              <div>
                <p className="text-slate-400">Distinct Users</p>
                <p className="text-slate-200 font-medium">{data.num_distinct_users || 0}</p>
              </div>
            </div>
            {data.country_code && <p className="text-xs text-slate-400">Country: {data.country_code}</p>}
          </div>
        );
        
      case 'GreyNoise':
        return (
          <div className="space-y-2">
            {data.classification && (
              <Badge variant="outline" className="bg-slate-700/50 text-slate-300 text-xs">
                {data.classification}
              </Badge>
            )}
            <div className="text-sm space-y-1">
              {data.name && <p className="text-slate-300">{data.name}</p>}
              <div className="flex gap-2 text-xs">
                {data.noise !== undefined && (
                  <span className={data.noise ? 'text-orange-400' : 'text-emerald-400'}>
                    {data.noise ? '⚠ Known Scanner' : '✓ Not Scanner'}
                  </span>
                )}
                {data.riot !== undefined && (
                  <span className={data.riot ? 'text-blue-400' : 'text-slate-400'}>
                    {data.riot ? '✓ Trusted' : ''}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
        
      case 'AlienVault OTX':
        return (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              <span className="text-sm font-semibold text-slate-200">
                {data.pulse_count || 0} Threat Pulses
              </span>
            </div>
            {data.pulses && data.pulses.length > 0 && (
              <div className="space-y-1">
                {data.pulses.slice(0, 3).map((pulse, idx) => (
                  <p key={idx} className="text-xs text-slate-400 truncate">
                    • {pulse.name}
                  </p>
                ))}
              </div>
            )}
          </div>
        );
        
      case 'MXToolbox':
        return (
          <div className="space-y-3">
            {data.mx_records && data.mx_records.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-1.5">MX Records</p>
                <div className="space-y-1">
                  {data.mx_records.slice(0, 5).map((mx, idx) => (
                    <div key={idx} className="text-xs text-slate-300 flex items-center gap-2">
                      <span className="text-slate-500">Priority {mx.priority}:</span>
                      <span className="font-mono">{mx.host}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.spf_record && (
              <div>
                <p className="text-xs text-slate-400 mb-1">SPF Record</p>
                <p className="text-xs text-slate-300 font-mono break-all">{data.spf_record}</p>
              </div>
            )}
            {data.dmarc_record && (
              <div>
                <p className="text-xs text-slate-400 mb-1">DMARC Record</p>
                <p className="text-xs text-slate-300 font-mono break-all">{data.dmarc_record}</p>
              </div>
            )}
          </div>
        );
        
      default:
        return (
          <div className="text-xs text-slate-400 space-y-1">
            {Object.entries(data).slice(0, 5).map(([key, value]) => (
              <div key={key}>
                <span className="text-slate-500">{key}:</span>{' '}
                <span className="text-slate-300">{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
              </div>
            ))}
          </div>
        );
    }
  };
  
  return (
    <Card className="bg-slate-800/40 border-slate-700/40 hover:border-slate-600/50 transition-all duration-200 shadow-sm hover:shadow-md">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium text-slate-200">{vendor}</CardTitle>
          <div className="flex items-center gap-1.5">
            <VendorStatusBadge status={status} />
            {vendorUrl && (
              <a
                href={vendorUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1 hover:bg-slate-700/50 rounded transition-colors"
                title={`View on ${vendor}`}
              >
                <ExternalLink className="w-3.5 h-3.5 text-slate-400 hover:text-slate-300" />
              </a>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {renderVendorData()}
      </CardContent>
    </Card>
  );
};

const AnalysisResults = ({ result }) => {
  if (!result) return null;
  
  const { ioc, ioc_type, category, summary, vendor_results, timestamp } = result;
  
  return (
    <div className="space-y-6" data-testid="analysis-results">
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardContent className="pt-6">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-slate-700/30 rounded-lg">
                <IOCTypeIcon category={category} />
              </div>
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Analyzed IOC</p>
                <p className="text-base font-mono text-slate-100 break-all" data-testid="analyzed-ioc-value">{ioc}</p>
                <div className="flex items-center gap-2 mt-1.5">
                  <Badge variant="outline" className="bg-slate-700/30 text-slate-300 text-xs border-slate-600">
                    {ioc_type.toUpperCase()}
                  </Badge>
                  <span className="text-xs text-slate-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(timestamp).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <ThreatBadge level={summary.threat_level} />
              {summary.confidence > 0 && (
                <div className="px-3 py-2 bg-slate-700/30 rounded-lg">
                  <p className="text-xs text-slate-400">Confidence</p>
                  <p className="text-sm font-semibold text-slate-200">{summary.confidence}%</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
      
      {(summary.key_findings?.length > 0 || summary.open_ports?.length > 0 || summary.vulnerabilities?.length > 0) && (
        <Card className="bg-slate-800/40 border-slate-700/40">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2 text-slate-200">
              <TrendingUp className="w-4 h-4 text-slate-400" />
              Intelligence Summary
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {summary.key_findings && summary.key_findings.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-2">Key Findings</p>
                <ul className="space-y-1.5">
                  {summary.key_findings.map((finding, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                      <ChevronRight className="w-3.5 h-3.5 text-slate-500 mt-0.5 flex-shrink-0" />
                      {finding}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            
            {summary.open_ports && summary.open_ports.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-2">Open Ports</p>
                <div className="flex flex-wrap gap-1.5">
                  {summary.open_ports.slice(0, 15).map((port, idx) => (
                    <Badge key={idx} variant="outline" className="bg-slate-700/30 text-slate-300 text-xs border-slate-600">
                      {port}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            
            {summary.vulnerabilities && summary.vulnerabilities.length > 0 && (
              <div>
                <p className="text-xs text-red-400 uppercase tracking-wide mb-2">Vulnerabilities</p>
                <div className="flex flex-wrap gap-1.5">
                  {summary.vulnerabilities.slice(0, 8).map((vuln, idx) => (
                    <Badge key={idx} variant="outline" className="bg-red-500/10 text-red-400 text-xs border-red-500/30">
                      {vuln}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
      
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2 text-slate-200">
            <Shield className="w-4 h-4 text-slate-400" />
            Vendor Intelligence
          </CardTitle>
          <CardDescription className="text-slate-500 text-sm">
            {vendor_results.filter(r => r.status !== 'unsupported').length} active sources · {summary.successful_queries} successful
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {vendor_results
              .filter(result => result.status !== 'unsupported')
              .map((result, idx) => (
                <VendorCard key={idx} result={result} ioc={ioc} iocType={ioc_type} category={category} />
              ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

const SOCDashboard = () => {
  const [activeTab, setActiveTab] = useState('ioc');
  const [iocInput, setIocInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [detectedType, setDetectedType] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [bulkMode, setBulkMode] = useState(false);
  const [bulkResults, setBulkResults] = useState([]);
  
  const detectIOC = async (value) => {
    if (!value.trim()) {
      setDetectedType(null);
      return;
    }
    
    try {
      const response = await axios.post(`${API}/detect`, { ioc: value.split('\n')[0].trim() });
      setDetectedType(response.data);
    } catch (error) {
      setDetectedType(null);
    }
  };
  
  const handleInputChange = (e) => {
    const value = e.target.value;
    setIocInput(value);
    
    const timer = setTimeout(() => detectIOC(value), 300);
    return () => clearTimeout(timer);
  };
  
  const analyzeIOC = async () => {
    if (!iocInput.trim()) {
      toast.error('Please enter an IOC to analyze');
      return;
    }
    
    setIsLoading(true);
    setAnalysisResult(null);
    setBulkResults([]);
    
    try {
      if (bulkMode) {
        const iocs = iocInput.split('\n').filter(i => i.trim());
        if (iocs.length > 20) {
          toast.error('Maximum 20 IOCs allowed per request');
          setIsLoading(false);
          return;
        }
        
        const response = await axios.post(`${API}/analyze/bulk`, { iocs });
        setBulkResults(response.data.results);
        toast.success(`Analyzed ${response.data.total} IOCs`);
      } else {
        const response = await axios.post(`${API}/analyze`, { ioc: iocInput.trim() });
        setAnalysisResult(response.data);
        toast.success('Analysis complete');
      }
    } catch (error) {
      const errorMsg = error.response?.data?.detail || 'Failed to analyze IOC. Please check your input and try again.';
      toast.error(errorMsg);
      console.error('Analysis error:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="min-h-screen bg-slate-950" data-testid="soc-dashboard">
      <Toaster position="top-right" theme="dark" richColors />
      
      <header className="border-b border-slate-800 bg-slate-900/50 sticky top-0 z-50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-800/50 rounded-lg">
                <Shield className="w-5 h-5 text-slate-400" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-slate-100">IOC Analyzer</h1>
                <p className="text-xs text-slate-500">Threat Intelligence Platform</p>
              </div>
            </div>
            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs">
              <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full mr-1.5"></span>
              Active
            </Badge>
          </div>
        </div>
      </header>
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="mb-6">
          <TabsList className="bg-slate-800/50 border border-slate-700/50">
            <TabsTrigger value="ioc" className="data-[state=active]:bg-slate-700 data-[state=active]:text-slate-100 text-sm">
              <Search className="w-3.5 h-3.5 mr-1.5" />
              IOC Analysis
            </TabsTrigger>
            <TabsTrigger value="email-headers" className="data-[state=active]:bg-slate-700 data-[state=active]:text-slate-100 text-sm">
              <FileText className="w-3.5 h-3.5 mr-1.5" />
              Email Headers
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="ioc" className="mt-6">
            <Card className="bg-slate-800/40 border-slate-700/40 mb-6">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base text-slate-100">Analyze Indicators</CardTitle>
                    <CardDescription className="text-slate-500 text-sm">Enter IPs, domains, URLs, emails, or hashes</CardDescription>
                  </div>
                  <Button
                    variant={bulkMode ? "default" : "outline"}
                    size="sm"
                    onClick={() => setBulkMode(!bulkMode)}
                    className={bulkMode ? "bg-slate-700 hover:bg-slate-600 text-slate-100 text-xs" : "border-slate-600 text-slate-400 hover:bg-slate-800 text-xs"}
                    data-testid="bulk-mode-toggle"
                  >
                    {bulkMode ? 'Single Mode' : 'Bulk Mode'}
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="max-w-3xl">
                  {bulkMode ? (
                    <Textarea
                      value={iocInput}
                      onChange={handleInputChange}
                      placeholder="Enter IOCs (one per line, max 20)...\n8.8.8.8\nexample.com\nhttps://suspicious-site.com"
                      className="bg-slate-900/50 border-slate-700 text-slate-200 placeholder:text-slate-600 focus:ring-1 focus:ring-slate-600 font-mono text-sm h-32 resize-none"
                      data-testid="ioc-input-bulk"
                    />
                  ) : (
                    <Input
                      type="text"
                      value={iocInput}
                      onChange={handleInputChange}
                      placeholder="Enter IOC (e.g., 8.8.8.8, google.com, user@example.com...)"
                      className="bg-slate-900/50 border-slate-700 text-slate-200 placeholder:text-slate-600 focus:ring-1 focus:ring-slate-600 h-11 font-mono text-sm"
                      onKeyDown={(e) => e.key === 'Enter' && analyzeIOC()}
                      data-testid="ioc-input"
                    />
                  )}
                </div>
                
                {detectedType && !bulkMode && (
                  <div className="flex items-center gap-3 p-3 bg-slate-700/20 rounded-lg border border-slate-700/50" data-testid="detection-preview">
                    <div className="p-2 bg-slate-700/40 rounded">
                      <IOCTypeIcon category={detectedType.category} size="w-4 h-4" />
                    </div>
                    <div className="flex-1">
                      <p className="text-xs text-slate-400">Detected Type</p>
                      <p className="text-sm text-slate-200">
                        {detectedType.ioc_type.toUpperCase()} <span className="text-slate-500">({detectedType.category})</span>
                      </p>
                    </div>
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  </div>
                )}
                
                <div className="flex items-center gap-3">
                  <Button
                    onClick={analyzeIOC}
                    disabled={isLoading || !iocInput.trim()}
                    className="bg-slate-700 hover:bg-slate-600 text-slate-100 px-6 text-sm h-10 disabled:opacity-50"
                    data-testid="analyze-button"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4 mr-2" />
                        Analyze
                      </>
                    )}
                  </Button>
                  
                  {(analysisResult || bulkResults.length > 0) && (
                    <Button
                      variant="outline"
                      onClick={() => {
                        setAnalysisResult(null);
                        setBulkResults([]);
                        setIocInput('');
                        setDetectedType(null);
                      }}
                      className="border-slate-600 text-slate-400 hover:bg-slate-800 text-sm h-10"
                      data-testid="clear-button"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
            
            {analysisResult && <AnalysisResults result={analysisResult} />}
            
            {bulkResults.length > 0 && (
              <div className="space-y-4">
                {bulkResults.map((result, idx) => (
                  <div key={idx}>
                    <AnalysisResults result={result} />
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="email-headers" className="mt-6">
            <Card className="bg-slate-800/40 border-slate-700/40">
              <CardHeader>
                <CardTitle className="text-base text-slate-100">Email Header Analyzer</CardTitle>
                <CardDescription className="text-slate-500 text-sm">Paste email headers for security analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-slate-400">Email header analysis coming soon...</p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
};

function App() {
  return <SOCDashboard />;
}

export default App;
