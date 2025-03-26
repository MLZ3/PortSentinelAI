import React, { useState } from 'react';
import { Shield, AlertTriangle, FileText, HelpCircle, Wifi, Download, Loader2 } from 'lucide-react';
import { cn } from './lib/utils';

type ScanMode = 'quick' | 'medium' | 'slow';
type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface Port {
  number: number;
  service: string;
  status: string;
  riskLevel: RiskLevel;
}

interface CVEAlert {
  id: string;
  title: string;
  severity: string;
  description: string;
}

interface ScanConfig {
  targetIp: string;
  mode: ScanMode;
}

function App() {
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    targetIp: '',
    mode: 'quick'
  });
  const [isScanning, setIsScanning] = useState(false);
  const [ports, setPorts] = useState<Port[]>([]);
  const [cveAlerts, setCveAlerts] = useState<{ [port: number]: CVEAlert[] }>({}); // Dictionnaire {port: [CVE]}
  const [error, setError] = useState<string | null>(null);

  const validateIp = (ip: string) => {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    return ip.split('.').every(num => parseInt(num) >= 0 && parseInt(num) <= 255);
  };

  const startScan = async () => {
    if (!validateIp(scanConfig.targetIp)) {
      setError('Please enter a valid IP address');
      return;
    }
    setError(null);
    setIsScanning(true);

    try {
      const response = await fetch('http://127.0.0.1:5000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanConfig)
      });

      if (!response.ok) throw new Error('Scan failed');

      const data = await response.json();
      setPorts(data.ports || []); // S'assurer que ports est une liste
      setCveAlerts(data.cveAlerts || {}); // S'assurer que cveAlerts est un dictionnaire
    } catch (err) {
      setError('Failed to complete scan. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  // Convertir le dictionnaire cveAlerts en une liste plate pour l'affichage
  const cveList: { port: number; cve: CVEAlert }[] = [];
  Object.keys(cveAlerts).forEach(port => {
    if (cveAlerts[parseInt(port)] && Array.isArray(cveAlerts[parseInt(port)])) {
      cveAlerts[parseInt(port)].forEach(cve => {
        cveList.push({ port: parseInt(port), cve });
      });
    }
  });

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Sidebar */}
      <div className="fixed left-0 top-0 h-full w-72 bg-[#1a237e] shadow-xl">
        <div className="p-6 border-b border-indigo-900/20 bg-gradient-to-r from-[#1a237e] to-[#283593]">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-indigo-100" />
            <h1 className="text-xl font-bold text-white tracking-tight">PortSentinel AI</h1>
          </div>
        </div>

        <div className="p-6 space-y-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="block text-sm font-medium text-indigo-100">Target IP Address</label>
              <div className="relative">
                <Wifi className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-indigo-200" />
                <input
                  type="text"
                  value={scanConfig.targetIp}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, targetIp: e.target.value }))}
                  placeholder="192.168.1.1"
                  className="w-full pl-10 pr-4 py-2.5 bg-indigo-900/20 border border-indigo-700/30 rounded-lg text-white placeholder-indigo-300/50 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-200"
                />
              </div>
              {error && <p className="text-sm text-red-300">{error}</p>}
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-indigo-100">Scan Mode</label>
              <select
                value={scanConfig.mode}
                onChange={(e) => setScanConfig(prev => ({ ...prev, mode: e.target.value as ScanMode }))}
                className="w-full pl-3 pr-10 py-2.5 bg-indigo-900/20 border border-indigo-700/30 rounded-lg text-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-200"
              >
                <option value="quick">Quick: SYN Scan</option>
                <option value="medium">Medium: TCP Connect</option>
                <option value="slow">Slow: Full Scan</option>
              </select>
            </div>

            <button
              onClick={startScan}
              disabled={isScanning || !scanConfig.targetIp}
              className={cn(
                "w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium transition-all duration-200",
                isScanning
                  ? "bg-indigo-700 text-indigo-100"
                  : "bg-indigo-500 hover:bg-indigo-600 text-white shadow-lg shadow-indigo-500/25 hover:shadow-indigo-600/25",
                (!scanConfig.targetIp || isScanning) && "opacity-50 cursor-not-allowed"
              )}
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Scanning...
                </>
              ) : (
                'Start Scan'
              )}
            </button>
          </div>

          <div className="space-y-3 pt-4 border-t border-indigo-800/30">
            <a href="#" className="flex items-center gap-2 text-indigo-200 hover:text-white transition-colors duration-200 group">
              <FileText className="h-5 w-5 group-hover:scale-110 transition-transform duration-200" />
              README
            </a>
            <a href="#" className="flex items-center gap-2 text-indigo-200 hover:text-white transition-colors duration-200 group">
              <AlertTriangle className="h-5 w-5 group-hover:scale-110 transition-transform duration-200" />
              LICENSE
            </a>
            <a href="#" className="flex items-center gap-2 text-indigo-200 hover:text-white transition-colors duration-200 group">
              <HelpCircle className="h-5 w-5 group-hover:scale-110 transition-transform duration-200" />
              Help
            </a>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="ml-72 p-8">
        <div className="space-y-8">
          {/* Scanned Ports Section */}
          <section className="bg-white rounded-xl shadow-lg border border-slate-200/50 backdrop-blur-sm">
            <div className="p-6 border-b border-slate-200">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold text-slate-900">Scanned - Detected Ports</h2>
                <div className="flex gap-2">
                  <button className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors duration-200">
                    <Download className="h-4 w-4" />
                    PDF Report
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors duration-200">
                    <Download className="h-4 w-4" />
                    Word Report
                  </button>
                </div>
              </div>
            </div>

            <div className="p-6">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-200">
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Port</th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Service</th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Status</th>
                      <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Risk Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((port, index) => (
                      <tr key={index} className="border-b border-slate-200 hover:bg-slate-50 transition-colors duration-200">
                        <td className="py-3 px-4 text-sm text-slate-900">{port.number}</td>
                        <td className="py-3 px-4 text-sm text-slate-900">{port.service}</td>
                        <td className="py-3 px-4 text-sm text-slate-900">{port.status}</td>
                        <td className="py-3 px-4">
                          <span className={cn(
                            "px-2.5 py-1.5 rounded-full text-xs font-medium transition-colors duration-200",
                            {
                              'bg-red-100 text-red-700 ring-1 ring-red-700/10': port.riskLevel === 'HIGH',
                              'bg-amber-100 text-amber-700 ring-1 ring-amber-700/10': port.riskLevel === 'MEDIUM',
                              'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-700/10': port.riskLevel === 'LOW',
                              'bg-slate-100 text-slate-700 ring-1 ring-slate-700/10': port.riskLevel === 'INFO'
                            }
                          )}>
                            {port.riskLevel}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {ports.length === 0 && (
                  <div className="text-center py-16">
                    <Shield className="mx-auto h-16 w-16 text-indigo-100 bg-indigo-50 p-3 rounded-2xl" />
                    <p className="mt-4 text-slate-500">No ports scanned yet. Enter an IP address and click "Start Scan" to begin.</p>
                  </div>
                )}
              </div>
            </div>
          </section>

          {/* CVE Alerts Section */}
          <section className="bg-white rounded-xl shadow-lg border border-slate-200/50 backdrop-blur-sm">
            <div className="p-6 border-b border-slate-200">
              <h2 className="text-xl font-bold text-slate-900">CVE Alerts</h2>
            </div>
            <div className="p-6">
              {cveList.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-200">
                        <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Port</th>
                        <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">CVE ID</th>
                        <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Title</th>
                        <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Severity</th>
                        <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cveList.map(({ port, cve }, index) => (
                        <tr key={index} className="border-b border-slate-200 hover:bg-slate-50 transition-colors duration-200">
                          <td className="py-3 px-4 text-sm text-slate-900">{port}</td>
                          <td className="py-3 px-4 text-sm text-slate-900">{cve.id}</td>
                          <td className="py-3 px-4 text-sm text-slate-900">{cve.title}</td>
                          <td className="py-3 px-4">
                            <span className={cn(
                              "px-2.5 py-1.5 rounded-full text-xs font-medium transition-colors duration-200",
                              {
                                'bg-red-100 text-red-700 ring-1 ring-red-700/10': cve.severity === 'HIGH',
                                'bg-amber-100 text-amber-700 ring-1 ring-amber-700/10': cve.severity === 'MEDIUM',
                                'bg-emerald-100 text-emerald-700 ring-1 ring-emerald-700/10': cve.severity === 'LOW',
                                'bg-slate-100 text-slate-700 ring-1 ring-slate-700/10': cve.severity === 'INFO'
                              }
                            )}>
                              {cve.severity}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-sm text-slate-900">{cve.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-16">
                  <AlertTriangle className="mx-auto h-16 w-16 text-amber-200 bg-amber-50 p-3 rounded-2xl" />
                  <p className="mt-4 text-slate-500">No CVE alerts to display.</p>
                </div>
              )}
            </div>
          </section>

          {/* Summary Section */}
          <section className="bg-white rounded-xl shadow-lg border border-slate-200/50 backdrop-blur-sm">
            <div className="p-6 border-b border-slate-200">
              <h2 className="text-xl font-bold text-slate-900">Summary</h2>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                <div className="p-4 bg-gradient-to-br from-slate-50 to-indigo-50/50 rounded-xl border border-indigo-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">Total Ports</div>
                  <div className="text-2xl font-bold text-indigo-900 mt-1">{ports.length}</div>
                </div>
                <div className="p-4 bg-gradient-to-br from-slate-50 to-emerald-50/50 rounded-xl border border-emerald-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">Open Ports</div>
                  <div className="text-2xl font-bold text-emerald-700 mt-1">
                    {ports.filter(p => p.status === 'open').length}
                  </div>
                </div>
                <div className="p-4 bg-gradient-to-br from-slate-50 to-blue-50/50 rounded-xl border border-blue-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">Closed Ports</div>
                  <div className="text-2xl font-bold text-blue-700 mt-1">
                    {ports.filter(p => p.status === 'closed').length}
                  </div>
                </div>
                <div className="p-4 bg-gradient-to-br from-slate-50 to-red-50/50 rounded-xl border border-red-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">High Risk</div>
                  <div className="text-2xl font-bold text-red-700 mt-1">
                    {ports.filter(p => p.riskLevel === 'HIGH').length}
                  </div>
                </div>
                <div className="p-4 bg-gradient-to-br from-slate-50 to-amber-50/50 rounded-xl border border-amber-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">Medium Risk</div>
                  <div className="text-2xl font-bold text-amber-700 mt-1">
                    {ports.filter(p => p.riskLevel === 'MEDIUM').length}
                  </div>
                </div>
                <div className="p-4 bg-gradient-to-br from-slate-50 to-emerald-50/50 rounded-xl border border-emerald-100 shadow-sm">
                  <div className="text-sm font-medium text-slate-600">Low Risk</div>
                  <div className="text-2xl font-bold text-emerald-700 mt-1">
                    {ports.filter(p => p.riskLevel === 'LOW').length}
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

export default App;