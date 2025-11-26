import { useState } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Toaster, toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "components/ui/card";
import { Button } from "components/ui/button";
import { Input } from "components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "components/ui/tabs";
import { Badge } from "components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "components/ui/accordion";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "components/ui/tooltip";
import { Progress } from "components/ui/progress";
import { Textarea } from "components/ui/textarea";
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Globe, 
  Server, 
  Mail, 
  Hash, 
  Link2, 
  Loader2,
  Info,
  AlertCircle,
  Clock,
  MapPin,
  Building,
  Tag,
  FileWarning,
  ChevronRight,
  Zap,
  Radio,
  Bug,
  Network,
  Eye,
  FileText,
  AtSign,
  ShieldCheck,
  ShieldX,
  ShieldAlert
} from "lucide-react";

const API = '/api';

const IOCTypeIcon = ({ category }) => {
  switch (category) {
    case 'ip': return <Server className="w-4 h-4" />;
    case 'domain': return <Globe className="w-4 h-4" />;
    case 'url': return <Link2 className="w-4 h-4" />;
    case 'email': return <Mail className="w-4 h-4" />;
    case 'hash': return <Hash className="w-4 h-4" />;
    default: return <AlertCircle className="w-4 h-4" />;
  }
};

const ThreatBadge = ({ level }) => {
  const config = {
    high: { className: "bg-red-500/20 text-red-400 border-red-500/30", icon: AlertTriangle },
    medium: { className: "bg-amber-500/20 text-amber-400 border-amber-500/30", icon: AlertCircle },
    low: { className: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", icon: Info },
    clean: { className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle },
    unknown: { className: "bg-slate-500/20 text-slate-400 border-slate-500/30", icon: AlertCircle }
  };
  
  const { className, icon: Icon } = config[level] || config.unknown;
  
  return (
    <Badge variant="outline" className={`${className} font-semibold uppercase tracking-wide`} data-testid={`threat-badge-${level}`}>
      <Icon className="w-3 h-3 mr-1" />
      {level}
    </Badge>
  );
};

const VendorStatusBadge = ({ status }) => {
  const config = {
    success: { className: "bg-emerald-500/20 text-emerald-400", label: "Success" },
    not_found: { className: "bg-slate-500/20 text-slate-400", label: "Not Found" },
    unsupported: { className: "bg-slate-600/20 text-slate-500", label: "N/A" },
    error: { className: "bg-red-500/20 text-red-400", label: "Error" }
  };
  
  const { className, label } = config[status] || config.error;
  
  return <Badge variant="outline" className={className}>{label}</Badge>;
};

const AuthBadge = ({ status }) => {
  if (status === 'pass' || status === 'present') {
    return <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400"><ShieldCheck className="w-3 h-3 mr-1" />Pass</Badge>;
  } else if (status === 'fail') {
    return <Badge variant="outline" className="bg-red-500/20 text-red-400"><ShieldX className="w-3 h-3 mr-1" />Fail</Badge>;
  } else if (status === 'missing' || status === 'none') {
    return <Badge variant="outline" className="bg-amber-500/20 text-amber-400"><ShieldAlert className="w-3 h-3 mr-1" />Missing</Badge>;
  }
  return <Badge variant="outline" className="bg-slate-500/20 text-slate-400">N/A</Badge>;
};

const VendorCard = ({ result }) => {
  const { vendor, status, data, error } = result;
  
  const renderVendorData = () => {
    if (status !== 'success' || !data) {
      return (
        <p className="text-slate-400 text-sm">
          {error || (status === 'not_found' ? 'No data found for this IOC' : 'Data not available')}
        </p>
      );
    }
    
    switch (vendor) {
      case 'VirusTotal':
        const total = data.total_engines || 0;
        return (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Malicious</p>
                <p className="text-2xl font-bold text-red-400">
                  {data.malicious_count || 0}
                  <span className="text-sm text-slate-500 font-normal">/{total}</span>
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Suspicious</p>
                <p className="text-2xl font-bold text-amber-400">
                  {data.suspicious_count || 0}
                  <span className="text-sm text-slate-500 font-normal">/{total}</span>
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Harmless</p>
                <p className="text-2xl font-bold text-emerald-400">
                  {data.harmless_count || 0}
                  <span className="text-sm text-slate-500 font-normal">/{total}</span>
                </p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Undetected</p>
                <p className="text-2xl font-bold text-slate-400">
                  {data.undetected_count || 0}
                  <span className="text-sm text-slate-500 font-normal">/{total}</span>
                </p>
              </div>
            </div>
            {data.country && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <MapPin className="w-4 h-4 text-slate-400" />
                <span>Country: {data.country}</span>
              </div>
            )}
            {data.as_owner && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Building className="w-4 h-4 text-slate-400" />
                <span>ASN: {data.as_owner}</span>
              </div>
            )}
          </div>
        );
        
      case 'AbuseIPDB':
        return (
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <p className="text-xs text-slate-400 mb-1">Abuse Confidence Score</p>
                <div className="flex items-center gap-3">
                  <Progress 
                    value={data.abuse_confidence_score || 0} 
                    className="flex-1 h-2" 
                  />
                  <span className={`text-lg font-bold ${
                    (data.abuse_confidence_score || 0) > 50 ? 'text-red-400' : 
                    (data.abuse_confidence_score || 0) > 20 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {data.abuse_confidence_score || 0}%
                  </span>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Total Reports</p>
                <p className="text-xl font-bold text-slate-200">{data.total_reports || 0}</p>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3">
                <p className="text-xs text-slate-400 mb-1">Distinct Users</p>
                <p className="text-xl font-bold text-slate-200">{data.num_distinct_users || 0}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {data.is_tor && <Badge variant="outline" className="bg-purple-500/20 text-purple-400">TOR Exit Node</Badge>}
              {data.is_whitelisted && <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400">Whitelisted</Badge>}
            </div>
            {data.isp && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Building className="w-4 h-4 text-slate-400" />
                <span>ISP: {data.isp}</span>
              </div>
            )}
          </div>
        );
        
      case 'GreyNoise':
        return (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <p className="text-sm text-slate-400">Classification:</p>
              <Badge variant="outline" className={`
                ${data.classification === 'malicious' ? 'bg-red-500/20 text-red-400' : 
                  data.classification === 'benign' ? 'bg-emerald-500/20 text-emerald-400' : 
                  'bg-slate-500/20 text-slate-400'}
              `}>
                {data.classification || 'Unknown'}
              </Badge>
            </div>
            <div className="flex flex-wrap gap-2">
              {data.noise && <Badge variant="outline" className="bg-amber-500/20 text-amber-400">Internet Noise</Badge>}
              {data.riot && <Badge variant="outline" className="bg-cyan-500/20 text-cyan-400">RIOT</Badge>}
            </div>
            {data.name && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Tag className="w-4 h-4 text-slate-400" />
                <span>Name: {data.name}</span>
              </div>
            )}
            {data.last_seen && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Clock className="w-4 h-4 text-slate-400" />
                <span>Last Seen: {data.last_seen}</span>
              </div>
            )}
          </div>
        );
        
      case 'AlienVault OTX':
        return (
          <div className="space-y-3">
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-400 mb-1">Threat Pulses</p>
              <p className={`text-2xl font-bold ${(data.pulse_count || 0) > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {data.pulse_count || 0}
              </p>
            </div>
            {data.pulses && data.pulses.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs text-slate-400">Recent Pulses:</p>
                {data.pulses.slice(0, 3).map((pulse, idx) => (
                  <div key={idx} className="bg-slate-800/30 rounded p-2 text-xs text-slate-300">
                    {pulse.name || 'Unnamed Pulse'}
                  </div>
                ))}
              </div>
            )}
          </div>
        );
        
      case 'URLScan':
        const latest = data.latest_scan;
        return (
          <div className="space-y-3">
            <div className="bg-slate-800/50 rounded-lg p-3">
              <p className="text-xs text-slate-400 mb-1">Total Scan Results</p>
              <p className="text-2xl font-bold text-slate-200">{data.total_results || 0}</p>
            </div>
            {latest && (
              <>
                {latest.domain && (
                  <div className="flex items-center gap-2 text-sm text-slate-300">
                    <Globe className="w-4 h-4 text-slate-400" />
                    <span>Domain: {latest.domain}</span>
                  </div>
                )}
                {latest.ip && (
                  <div className="flex items-center gap-2 text-sm text-slate-300">
                    <Server className="w-4 h-4 text-slate-400" />
                    <span>IP: {latest.ip}</span>
                  </div>
                )}
              </>
            )}
          </div>
        );
      
      case 'Shodan':
        return (
          <div className="space-y-3">
            {data.ports && data.ports.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-2">Open Ports ({data.ports.length})</p>
                <div className="flex flex-wrap gap-1">
                  {data.ports.slice(0, 12).map((port, idx) => (
                    <Badge key={idx} variant="outline" className="bg-slate-700/50 text-slate-300 text-xs">
                      {port}
                    </Badge>
                  ))}
                  {data.ports.length > 12 && (
                    <Badge variant="outline" className="bg-slate-700/50 text-slate-400 text-xs">
                      +{data.ports.length - 12} more
                    </Badge>
                  )}
                </div>
              </div>
            )}
            {data.vulns && data.vulns.length > 0 && (
              <div>
                <p className="text-xs text-red-400 mb-2">Vulnerabilities ({data.vulns.length})</p>
                <div className="flex flex-wrap gap-1">
                  {data.vulns.slice(0, 5).map((vuln, idx) => (
                    <Badge key={idx} variant="outline" className="bg-red-500/20 text-red-400 text-xs">
                      {vuln}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {data.hostnames && data.hostnames.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Globe className="w-4 h-4 text-slate-400" />
                <span className="truncate">{data.hostnames[0]}</span>
              </div>
            )}
          </div>
        );
      
      case 'IPInfo':
        return (
          <div className="space-y-3">
            {data.city && data.country && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <MapPin className="w-4 h-4 text-slate-400" />
                <span>{data.city}, {data.region}, {data.country}</span>
              </div>
            )}
            {data.org && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Building className="w-4 h-4 text-slate-400" />
                <span>{data.org}</span>
              </div>
            )}
            {data.hostname && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Globe className="w-4 h-4 text-slate-400" />
                <span>{data.hostname}</span>
              </div>
            )}
          </div>
        );
      
      case 'MalwareBazaar':
        return (
          <div className="space-y-3">
            {data.found ? (
              <>
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                  <p className="text-xs text-red-400 mb-1">Known Malware</p>
                  <p className="text-lg font-bold text-red-400">
                    {data.signature || 'Unknown Signature'}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-slate-800/50 rounded p-2">
                    <p className="text-xs text-slate-400">File Type</p>
                    <p className="text-sm text-slate-200">{data.file_type || 'N/A'}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded p-2">
                    <p className="text-xs text-slate-400">File Size</p>
                    <p className="text-sm text-slate-200">{data.file_size ? `${Math.round(data.file_size / 1024)} KB` : 'N/A'}</p>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-sm text-emerald-400">Hash not found in MalwareBazaar</p>
            )}
          </div>
        );
      
      case 'WHOIS':
        return (
          <div className="space-y-3">
            {/* Domain Registration Info */}
            {(data.creation_date || data.expiration_date) && (
              <div className="grid grid-cols-2 gap-2">
                {data.creation_date && (
                  <div className="bg-slate-800/50 rounded-lg p-2">
                    <p className="text-xs text-slate-400 mb-1">Registered</p>
                    <p className="text-sm font-medium text-emerald-400">{data.creation_date}</p>
                  </div>
                )}
                {data.expiration_date && (
                  <div className="bg-slate-800/50 rounded-lg p-2">
                    <p className="text-xs text-slate-400 mb-1">Expires</p>
                    <p className="text-sm font-medium text-amber-400">{data.expiration_date}</p>
                  </div>
                )}
              </div>
            )}
            {data.registrar && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Building className="w-4 h-4 text-slate-400" />
                <span>Registrar: {data.registrar}</span>
              </div>
            )}
            {data.country && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <MapPin className="w-4 h-4 text-slate-400" />
                <span>{data.city ? `${data.city}, ` : ''}{data.country}</span>
              </div>
            )}
            {data.isp && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Building className="w-4 h-4 text-slate-400" />
                <span>ISP: {data.isp}</span>
              </div>
            )}
            {data.org && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Network className="w-4 h-4 text-slate-400" />
                <span>{data.org}</span>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {data.proxy && <Badge variant="outline" className="bg-amber-500/20 text-amber-400">Proxy</Badge>}
              {data.hosting && <Badge variant="outline" className="bg-cyan-500/20 text-cyan-400">Hosting</Badge>}
              {data.mobile && <Badge variant="outline" className="bg-purple-500/20 text-purple-400">Mobile</Badge>}
            </div>
            {data.name_servers && data.name_servers.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Name Servers</p>
                <div className="flex flex-wrap gap-1">
                  {data.name_servers.slice(0, 4).map((ns, idx) => (
                    <Badge key={idx} variant="outline" className="bg-slate-700/50 text-slate-300 text-xs">
                      {ns}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      
      case 'MXToolbox':
        return (
          <div className="space-y-3">
            {data.mx_records && data.mx_records.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 mb-2">MX Records</p>
                <div className="space-y-1">
                  {data.mx_records.slice(0, 3).map((mx, idx) => (
                    <div key={idx} className="bg-slate-800/50 rounded p-2 text-xs text-slate-300 flex justify-between">
                      <span>{mx.host}</span>
                      <Badge variant="outline" className="bg-slate-700/50 text-slate-400 text-xs">Priority: {mx.priority}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-400 mb-1">SPF</p>
                <AuthBadge status={data.spf_record ? 'present' : 'missing'} />
              </div>
              <div className="bg-slate-800/50 rounded p-2">
                <p className="text-xs text-slate-400 mb-1">DMARC</p>
                <AuthBadge status={data.dmarc_record ? 'present' : 'missing'} />
              </div>
            </div>
            {data.issues && data.issues.length > 0 && (
              <div>
                <p className="text-xs text-amber-400 mb-2">Issues Found</p>
                {data.issues.map((issue, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-amber-300">
                    <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                    <span>{issue}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      
      case 'Email Domain':
        return (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <AtSign className="w-4 h-4 text-slate-400" />
              <span>{data.email}</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {data.disposable && <Badge variant="outline" className="bg-red-500/20 text-red-400">Disposable</Badge>}
              {data.free_provider && <Badge variant="outline" className="bg-amber-500/20 text-amber-400">Free Provider</Badge>}
              {data.business_domain && !data.free_provider && <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400">Business Domain</Badge>}
            </div>
            {data.suspicious_patterns && data.suspicious_patterns.length > 0 && (
              <div>
                <p className="text-xs text-amber-400 mb-2">Suspicious Patterns</p>
                {data.suspicious_patterns.map((pattern, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-amber-300">
                    <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                    <span>{pattern}</span>
                  </div>
                ))}
              </div>
            )}
            {data.domain_age && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Clock className="w-4 h-4 text-slate-400" />
                <span>Created: {data.domain_age}</span>
              </div>
            )}
          </div>
        );
        
      default:
        return <pre className="text-xs text-slate-400 overflow-auto">{JSON.stringify(data, null, 2)}</pre>;
    }
  };
  
  return (
    <Card className="bg-slate-800/30 border-slate-700/50" data-testid={`vendor-card-${vendor.toLowerCase().replace(/\s+/g, '-')}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium text-slate-200">{vendor}</CardTitle>
          <VendorStatusBadge status={status} />
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
      {/* Header Section */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardContent className="pt-6">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-slate-700/50 rounded-xl">
                <IOCTypeIcon category={category} />
              </div>
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wider mb-1">Analyzed IOC</p>
                <p className="text-lg font-mono text-slate-200 break-all" data-testid="analyzed-ioc-value">{ioc}</p>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="outline" className="bg-slate-700/50 text-slate-300 text-xs">
                    {ioc_type.toUpperCase()}
                  </Badge>
                  <span className="text-xs text-slate-500">
                    <Clock className="w-3 h-3 inline mr-1" />
                    {new Date(timestamp).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <ThreatBadge level={summary.threat_level} />
              {summary.confidence > 0 && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger>
                      <Badge variant="outline" className="bg-slate-700/50 text-slate-300">
                        {summary.confidence}% confidence
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Threat confidence score based on aggregated data</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
      
      {/* Summary Section */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2 text-slate-200">
            <Zap className="w-5 h-5 text-cyan-400" />
            Threat Summary
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Key Findings */}
          {summary.key_findings && summary.key_findings.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">Key Findings</p>
              <ul className="space-y-2">
                {summary.key_findings.map((finding, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                    <ChevronRight className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                    {finding}
                  </li>
                ))}
              </ul>
            </div>
          )}
          
          {/* Email Security */}
          {summary.email_security && Object.keys(summary.email_security).length > 0 && (
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">Email Security</p>
              <div className="flex gap-4">
                {summary.email_security.spf && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">SPF:</span>
                    <AuthBadge status={summary.email_security.spf} />
                  </div>
                )}
                {summary.email_security.dmarc && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">DMARC:</span>
                    <AuthBadge status={summary.email_security.dmarc} />
                  </div>
                )}
              </div>
            </div>
          )}
          
          {/* Open Ports */}
          {summary.open_ports && summary.open_ports.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">Open Ports</p>
              <div className="flex flex-wrap gap-1">
                {summary.open_ports.slice(0, 20).map((port, idx) => (
                  <Badge key={idx} variant="outline" className="bg-slate-700/50 text-slate-300 text-xs">
                    {port}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          
          {/* Vulnerabilities */}
          {summary.vulnerabilities && summary.vulnerabilities.length > 0 && (
            <div>
              <p className="text-xs text-red-400 uppercase tracking-wider mb-2">Known Vulnerabilities</p>
              <div className="flex flex-wrap gap-1">
                {summary.vulnerabilities.slice(0, 10).map((vuln, idx) => (
                  <Badge key={idx} variant="outline" className="bg-red-500/20 text-red-400 text-xs">
                    {vuln}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          
          {/* Tags */}
          {summary.tags && summary.tags.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">Tags</p>
              <div className="flex flex-wrap gap-2">
                {summary.tags.map((tag, idx) => (
                  <Badge key={idx} variant="outline" className="bg-slate-700/50 text-slate-300">
                    <Tag className="w-3 h-3 mr-1" />
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          
          {/* Geolocation */}
          {summary.geolocation && Object.keys(summary.geolocation).length > 0 && (
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-2">Geolocation</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(summary.geolocation).map(([key, value]) => (
                  <div key={key} className="bg-slate-800/50 rounded-lg p-2">
                    <p className="text-xs text-slate-500 capitalize">{key.replace('_', ' ')}</p>
                    <p className="text-sm text-slate-300 truncate">{value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      
      {/* Vendor Results */}
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2 text-slate-200">
            <Shield className="w-5 h-5 text-cyan-400" />
            Vendor Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">
            {summary.successful_queries} of {summary.total_sources} sources returned data
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="columns-1 md:columns-2 xl:columns-3 gap-4 space-y-4">
            {vendor_results.map((result, idx) => (
              <div key={idx} className="break-inside-avoid">
                <VendorCard result={result} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

const EmailHeaderAnalyzer = () => {
  const [headers, setHeaders] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  
  const analyzeHeaders = async () => {
    if (!headers.trim()) {
      toast.error('Please paste email headers to analyze');
      return;
    }
    
    setIsLoading(true);
    setResult(null);
    
    try {
      const response = await axios.post(`${API}/analyze/email-headers`, { headers });
      setResult(response.data.analysis);
      toast.success('Email headers analyzed');
    } catch (error) {
      toast.error('Failed to analyze email headers');
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="space-y-6">
      <Card className="bg-slate-800/50 border-slate-700/50">
        <CardHeader>
          <CardTitle className="text-slate-200 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            Email Header Analyzer
          </CardTitle>
          <CardDescription className="text-slate-400">
            Paste raw email headers to analyze authentication and security indicators
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder="Paste email headers here..."
            className="bg-slate-900/50 border-slate-700 text-slate-200 placeholder:text-slate-500 min-h-[200px] font-mono text-sm"
            data-testid="email-headers-input"
          />
          <Button
            onClick={analyzeHeaders}
            disabled={isLoading || !headers.trim()}
            className="bg-cyan-600 hover:bg-cyan-700 text-white"
            data-testid="analyze-headers-button"
          >
            {isLoading ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing...</>
            ) : (
              <><Search className="w-4 h-4 mr-2" />Analyze Headers</>
            )}
          </Button>
        </CardContent>
      </Card>
      
      {result && (
        <Card className="bg-slate-800/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2 text-slate-200">
              <Shield className="w-5 h-5 text-cyan-400" />
              Analysis Results
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Basic Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {result.from && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-1">From</p>
                  <p className="text-sm text-slate-200 break-all">{result.from}</p>
                </div>
              )}
              {result.to && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-1">To</p>
                  <p className="text-sm text-slate-200 break-all">{result.to}</p>
                </div>
              )}
              {result.subject && (
                <div className="bg-slate-800/50 rounded-lg p-3 md:col-span-2">
                  <p className="text-xs text-slate-400 mb-1">Subject</p>
                  <p className="text-sm text-slate-200">{result.subject}</p>
                </div>
              )}
              {result.date && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-1">Date</p>
                  <p className="text-sm text-slate-200">{result.date}</p>
                </div>
              )}
              {result.originating_ip && (
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-1">Originating IP</p>
                  <p className="text-sm text-slate-200 font-mono">{result.originating_ip}</p>
                </div>
              )}
            </div>
            
            {/* Authentication */}
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wider mb-3">Authentication Results</p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-2">SPF</p>
                  <AuthBadge status={result.authentication?.spf} />
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-2">DKIM</p>
                  <AuthBadge status={result.authentication?.dkim} />
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-2">DMARC</p>
                  <AuthBadge status={result.authentication?.dmarc} />
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <p className="text-xs text-slate-400 mb-2">ARC</p>
                  <AuthBadge status={result.authentication?.arc} />
                </div>
              </div>
            </div>
            
            {/* Warnings */}
            {result.warnings && result.warnings.length > 0 && (
              <div>
                <p className="text-xs text-red-400 uppercase tracking-wider mb-3">Security Warnings</p>
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 space-y-2">
                  {result.warnings.map((warning, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-sm text-red-300">
                      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      {warning}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Received Chain */}
            {result.received_chain && result.received_chain.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wider mb-3">Received Chain ({result.received_chain.length} hops)</p>
                <div className="space-y-2 max-h-[200px] overflow-y-auto">
                  {result.received_chain.map((hop, idx) => (
                    <div key={idx} className="bg-slate-800/50 rounded p-2 text-xs text-slate-300 font-mono">
                      <span className="text-slate-500 mr-2">#{idx + 1}</span>
                      {hop.substring(0, 150)}...
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
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
      const errorMsg = error.response?.data?.detail || 'Failed to analyze IOC';
      toast.error(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="min-h-screen bg-slate-900" data-testid="soc-dashboard">
      <Toaster position="top-right" theme="dark" richColors />
      
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <Shield className="w-6 h-6 text-cyan-400" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-slate-100 font-['Space_Grotesk']">SOC IOC Analyzer</h1>
                <p className="text-xs text-slate-400">Threat Intelligence Hub</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                <span className="w-2 h-2 bg-emerald-400 rounded-full mr-2 animate-pulse"></span>
                Online
              </Badge>
            </div>
          </div>
        </div>
      </header>
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="mb-8">
          <TabsList className="bg-slate-800/50 border border-slate-700/50">
            <TabsTrigger value="ioc" className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white">
              <Search className="w-4 h-4 mr-2" />
              IOC Analysis
            </TabsTrigger>
            <TabsTrigger value="email-headers" className="data-[state=active]:bg-cyan-600 data-[state=active]:text-white">
              <FileText className="w-4 h-4 mr-2" />
              Email Headers
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="ioc" className="mt-6">
            {/* Input Section */}
            <Card className="bg-slate-800/50 border-slate-700/50 mb-8">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-slate-200 flex items-center gap-2">
                      <Search className="w-5 h-5 text-cyan-400" />
                      IOC Analysis
                    </CardTitle>
                    <CardDescription className="text-slate-400">
                      Enter IP, domain, URL, email, or file hash to analyze
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant={bulkMode ? "default" : "outline"}
                      size="sm"
                      onClick={() => setBulkMode(!bulkMode)}
                      className={bulkMode ? "bg-cyan-600 hover:bg-cyan-700" : "border-slate-600 text-slate-300 hover:bg-slate-700"}
                      data-testid="bulk-mode-toggle"
                    >
                      Bulk Mode
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="relative">
                  {bulkMode ? (
                    <textarea
                      value={iocInput}
                      onChange={handleInputChange}
                      placeholder="Enter IOCs (one per line, max 20)..."
                      className="w-full h-32 bg-slate-900/50 border border-slate-700 rounded-lg px-4 py-3 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 font-mono text-sm resize-none"
                      data-testid="ioc-input-bulk"
                    />
                  ) : (
                    <Input
                      type="text"
                      value={iocInput}
                      onChange={handleInputChange}
                      placeholder="Enter IOC (e.g., 8.8.8.8, google.com, user@example.com, hash...)"
                      className="bg-slate-900/50 border-slate-700 text-slate-200 placeholder:text-slate-500 focus:ring-cyan-500/50 focus:border-cyan-500/50 h-12 font-mono"
                      onKeyDown={(e) => e.key === 'Enter' && analyzeIOC()}
                      data-testid="ioc-input"
                    />
                  )}
                </div>
                
                {/* Detection Preview */}
                {detectedType && !bulkMode && (
                  <div className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-lg border border-slate-700/50" data-testid="detection-preview">
                    <div className="p-2 bg-cyan-500/20 rounded">
                      <IOCTypeIcon category={detectedType.category} />
                    </div>
                    <div>
                      <p className="text-xs text-slate-400">Detected Type</p>
                      <p className="text-sm font-medium text-slate-200">
                        {detectedType.ioc_type.toUpperCase()} 
                        <span className="text-slate-400 font-normal"> ({detectedType.category})</span>
                      </p>
                    </div>
                  </div>
                )}
                
                <div className="flex items-center gap-3">
                  <Button
                    onClick={analyzeIOC}
                    disabled={isLoading || !iocInput.trim()}
                    className="bg-cyan-600 hover:bg-cyan-700 text-white px-6"
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
                        Analyze {bulkMode ? 'All' : 'IOC'}
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
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                      data-testid="clear-button"
                    >
                      Clear Results
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
            
            {/* Results Section */}
            {analysisResult && <AnalysisResults result={analysisResult} />}
            
            {/* Bulk Results */}
            {bulkResults.length > 0 && (
              <div className="space-y-4" data-testid="bulk-results">
                <h2 className="text-lg font-semibold text-slate-200">Bulk Analysis Results ({bulkResults.length})</h2>
                <Accordion type="single" collapsible className="space-y-2">
                  {bulkResults.map((result, idx) => (
                    <AccordionItem 
                      key={idx} 
                      value={`item-${idx}`}
                      className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden"
                    >
                      <AccordionTrigger className="px-4 py-3 hover:no-underline hover:bg-slate-800/80">
                        <div className="flex items-center gap-3 w-full">
                          <IOCTypeIcon category={result.category} />
                          <span className="font-mono text-sm text-slate-200 truncate flex-1 text-left">
                            {result.ioc}
                          </span>
                          <ThreatBadge level={result.summary?.threat_level || 'unknown'} />
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        <AnalysisResults result={result} />
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </div>
            )}
            
            {/* Empty State */}
            {!analysisResult && bulkResults.length === 0 && !isLoading && (
              <div className="text-center py-16" data-testid="empty-state">
                <div className="inline-flex p-4 bg-slate-800/50 rounded-full mb-4">
                  <Shield className="w-12 h-12 text-slate-600" />
                </div>
                <h3 className="text-lg font-medium text-slate-400 mb-2">Ready to Analyze</h3>
                <p className="text-sm text-slate-500 max-w-md mx-auto">
                  Enter an IOC above to query multiple threat intelligence sources and get consolidated security insights.
                </p>
                <div className="flex flex-wrap justify-center gap-2 mt-6">
                  <Badge variant="outline" className="bg-slate-800/50 text-slate-400 border-slate-700">
                    <Server className="w-3 h-3 mr-1" /> IP Addresses
                  </Badge>
                  <Badge variant="outline" className="bg-slate-800/50 text-slate-400 border-slate-700">
                    <Globe className="w-3 h-3 mr-1" /> Domains
                  </Badge>
                  <Badge variant="outline" className="bg-slate-800/50 text-slate-400 border-slate-700">
                    <Link2 className="w-3 h-3 mr-1" /> URLs
                  </Badge>
                  <Badge variant="outline" className="bg-slate-800/50 text-slate-400 border-slate-700">
                    <Mail className="w-3 h-3 mr-1" /> Emails
                  </Badge>
                  <Badge variant="outline" className="bg-slate-800/50 text-slate-400 border-slate-700">
                    <Hash className="w-3 h-3 mr-1" /> File Hashes
                  </Badge>
                </div>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="email-headers" className="mt-6">
            <EmailHeaderAnalyzer />
          </TabsContent>
        </Tabs>
      </main>
      
      {/* Footer */}
      <footer className="border-t border-slate-800 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <p>SOC IOC Analyzer v1.0</p>
            <p>VirusTotal, AbuseIPDB, URLScan, AlienVault OTX, GreyNoise, Shodan, MalwareBazaar, MXToolbox</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<SOCDashboard />} />
          <Route path="*" element={<SOCDashboard />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
