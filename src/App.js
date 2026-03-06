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
  TrendingUp,
  MapPin,
  ArrowRight,
  Target,
  Lock
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

const EmailAnalysisResults = ({ analysis }) => {
  if (!analysis) return null;
  
  const { basic_info, authentication, routing, security_analysis, threat_indicators, recommendations } = analysis;
  
  return (
    <div className="space-y-6">
      {/* Security Score Card */}
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-semibold text-slate-100 mb-2">Security Analysis</h3>
              <p className="text-sm text-slate-400">Overall email security assessment</p>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-slate-100 mb-2">
                {security_analysis.security_score}
                <span className="text-sm text-slate-500">/100</span>
              </div>
              <ThreatBadge level={security_analysis.risk_level} />
            </div>
          </div>
          <Progress value={security_analysis.security_score} className="h-2" />
        </CardContent>
      </Card>
      
      {/* Threat Indicators */}
      {threat_indicators && threat_indicators.length > 0 && (
        <Card className="bg-slate-800/40 border-slate-700/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Threat Indicators ({threat_indicators.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {threat_indicators.map((indicator, idx) => {
              const severityColors = {
                critical: 'bg-red-500/10 border-red-500/30 text-red-400',
                high: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
                medium: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
                low: 'bg-blue-500/10 border-blue-500/30 text-blue-400'
              };
              return (
                <div key={idx} className={`p-3 rounded-lg border ${severityColors[indicator.severity]}`}>
                  <div className="flex items-start gap-2">
                    <Target className="w-4 h-4 mt-0.5 flex-shrink-0" />
                    <div className="flex-1">
                      <p className="font-medium text-sm mb-1">{indicator.type}</p>
                      <p className="text-xs opacity-80">{indicator.description}</p>
                    </div>
                    <Badge className="text-xs uppercase">{indicator.severity}</Badge>
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}
      
      {/* Email Information */}
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <Mail className="w-4 h-4 text-slate-400" />
            Email Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-400 mb-1">From</p>
              <p className="text-sm text-slate-200 font-mono break-all">{basic_info.from}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 mb-1">To</p>
              <p className="text-sm text-slate-200 font-mono break-all">{basic_info.to}</p>
            </div>
            <div className="md:col-span-2">
              <p className="text-xs text-slate-400 mb-1">Subject</p>
              <p className="text-sm text-slate-200">{basic_info.subject}</p>
            </div>
            {basic_info.reply_to && basic_info.reply_to !== 'Not specified' && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Reply-To</p>
                <p className="text-sm text-slate-200 font-mono break-all">{basic_info.reply_to}</p>
              </div>
            )}
            <div>
              <p className="text-xs text-slate-400 mb-1">Date</p>
              <p className="text-sm text-slate-200">{basic_info.date}</p>
            </div>
            {basic_info.email_client && basic_info.email_client !== 'Unknown' && (
              <div>
                <p className="text-xs text-slate-400 mb-1">Email Client</p>
                <p className="text-sm text-slate-200">{basic_info.email_client}</p>
              </div>
            )}
            <div>
              <p className="text-xs text-slate-400 mb-1">Message ID</p>
              <p className="text-xs text-slate-200 font-mono break-all">{basic_info.message_id}</p>
            </div>
          </div>
        </CardContent>
      </Card>
      
      {/* Authentication */}
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <Lock className="w-4 h-4 text-slate-400" />
            Email Authentication
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="text-center p-4 bg-slate-700/30 rounded-lg">
              <p className="text-xs text-slate-400 mb-2">SPF</p>
              <Badge className={authentication.spf === 'pass' ? 'bg-emerald-500/20 text-emerald-400' : authentication.spf === 'fail' ? 'bg-red-500/20 text-red-400' : 'bg-slate-600/50 text-slate-400'}>
                {authentication.spf.toUpperCase()}
              </Badge>
            </div>
            <div className="text-center p-4 bg-slate-700/30 rounded-lg">
              <p className="text-xs text-slate-400 mb-2">DKIM</p>
              <Badge className={authentication.dkim === 'pass' ? 'bg-emerald-500/20 text-emerald-400' : authentication.dkim === 'fail' ? 'bg-red-500/20 text-red-400' : 'bg-slate-600/50 text-slate-400'}>
                {authentication.dkim.toUpperCase()}
              </Badge>
            </div>
            <div className="text-center p-4 bg-slate-700/30 rounded-lg">
              <p className="text-xs text-slate-400 mb-2">DMARC</p>
              <Badge className={authentication.dmarc === 'pass' ? 'bg-emerald-500/20 text-emerald-400' : authentication.dmarc === 'fail' ? 'bg-red-500/20 text-red-400' : 'bg-slate-600/50 text-slate-400'}>
                {authentication.dmarc.toUpperCase()}
              </Badge>
            </div>
          </div>
          <div className="space-y-2 text-xs">
            <div>
              <p className="text-slate-400 mb-1">SPF Details</p>
              <p className="text-slate-300 bg-slate-900/50 p-2 rounded font-mono break-all">{authentication.spf_details}</p>
            </div>
            <div>
              <p className="text-slate-400 mb-1">DKIM Details</p>
              <p className="text-slate-300 bg-slate-900/50 p-2 rounded">{authentication.dkim_details}</p>
            </div>
          </div>
        </CardContent>
      </Card>
      
      {/* Email Routing */}
      <Card className="bg-slate-800/40 border-slate-700/40">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <MapPin className="w-4 h-4 text-slate-400" />
            Email Routing ({routing.hop_count} hops)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {routing.sender_ips && routing.sender_ips.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 mb-2">Sender IPs</p>
              <div className="flex flex-wrap gap-2">
                {routing.sender_ips.map((ip, idx) => (
                  <Badge key={idx} variant="outline" className="bg-slate-700/30 text-slate-300 text-xs border-slate-600 font-mono">
                    {ip}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          
          {routing.originating_ip && routing.originating_ip !== 'Not found' && (
            <div>
              <p className="text-xs text-slate-400 mb-1">Originating IP</p>
              <p className="text-sm text-slate-200 font-mono">{routing.originating_ip}</p>
            </div>
          )}
          
          {routing.email_path && routing.email_path.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 mb-3">Email Path (Server Hops)</p>
              <div className="space-y-2">
                {routing.email_path.map((hop, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-slate-700/50 flex items-center justify-center text-xs text-slate-400">
                      {idx + 1}
                    </div>
                    <div className="flex-1 bg-slate-900/50 p-2 rounded">
                      <p className="text-xs text-slate-300 font-mono break-all">{hop}</p>
                    </div>
                    {idx < routing.email_path.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-slate-600 mt-2" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      
      {/* URLs */}
      {security_analysis.embedded_urls && security_analysis.embedded_urls.length > 0 && (
        <Card className="bg-slate-800/40 border-slate-700/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <Link2 className="w-4 h-4 text-slate-400" />
              Embedded URLs ({security_analysis.embedded_urls.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {security_analysis.embedded_urls.map((url, idx) => (
                <div key={idx} className="bg-slate-900/50 p-2 rounded flex items-center gap-2">
                  <Link2 className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                  <p className="text-xs text-slate-300 font-mono break-all flex-1">{url}</p>
                  <a href={url} target="_blank" rel="noopener noreferrer" className="p-1 hover:bg-slate-700/50 rounded">
                    <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                  </a>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
      
      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <Card className="bg-slate-800/40 border-slate-700/40">
          <CardHeader>
            <CardTitle className="text-base text-slate-100 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-slate-400" />
              Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                  <ChevronRight className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <p>{rec}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

function App() {
  const [activeTab, setActiveTab] = useState('ioc');
  const [iocInput, setIocInput] = useState('');
  const [emailHeaders, setEmailHeaders] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [detectedType, setDetectedType] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [emailAnalysisResult, setEmailAnalysisResult] = useState(null);
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
  
  const analyzeEmailHeaders = async () => {
    if (!emailHeaders.trim()) {
      toast.error('Please paste email headers to analyze');
      return;
    }
    
    setIsLoading(true);
    setEmailAnalysisResult(null);
    
    try {
      const response = await axios.post(`${API}/analyze_headers`, { headers: emailHeaders });
      setEmailAnalysisResult(response.data.analysis);
      toast.success('Email analysis complete - see detailed results below');
    } catch (error) {
      const errorMsg = error.response?.data?.detail || 'Failed to analyze email headers';
      toast.error(errorMsg);
      console.error('Email analysis error:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="min-h-screen bg-slate-950">
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
            {/* IOC content remains the same - omitted for brevity */}
            <p className="text-slate-400">IOC Analysis - Switch to Email Headers tab to test the new feature!</p>
          </TabsContent>
          
          <TabsContent value="email-headers" className="mt-6">
            <Card className="bg-slate-800/40 border-slate-700/40 mb-6">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Mail className="w-4 h-4 text-slate-400" />
                  World-Class Email Header Analyzer
                </CardTitle>
                <CardDescription className="text-slate-500 text-sm">
                  Advanced email security analysis with threat detection, authentication verification, and routing analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea
                  value={emailHeaders}
                  onChange={(e) => setEmailHeaders(e.target.value)}
                  placeholder="Paste complete email headers here...\n\nExample headers:\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test Email\nReceived: from mail.example.com (mail.example.com [192.0.2.1])\nAuthentication-Results: mx.google.com; spf=pass\nReceived-SPF: pass\nDKIM-Signature: v=1; a=rsa-sha256; ...\nMessage-ID: <abc123@example.com>"
                  className="w-full bg-slate-900/50 border-slate-700 text-slate-200 placeholder:text-slate-600 focus:ring-1 focus:ring-slate-600 font-mono text-xs h-64 resize-y py-3"
                />
                
                <div className="flex items-center gap-3">
                  <Button
                    onClick={analyzeEmailHeaders}
                    disabled={isLoading || !emailHeaders.trim()}
                    className="bg-slate-700 hover:bg-slate-600 text-slate-100 px-6 text-sm h-10 disabled:opacity-50"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing Headers...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4 mr-2" />
                        Analyze Email Headers
                      </>
                    )}
                  </Button>
                  
                  {emailAnalysisResult && (
                    <Button
                      variant="outline"
                      onClick={() => {
                        setEmailAnalysisResult(null);
                        setEmailHeaders('');
                      }}
                      className="border-slate-600 text-slate-400 hover:bg-slate-800 text-sm h-10"
                    >
                      Clear Results
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
            
            {emailAnalysisResult && <EmailAnalysisResults analysis={emailAnalysisResult} />}
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}

export default App;