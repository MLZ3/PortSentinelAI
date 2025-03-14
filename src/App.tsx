import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Settings, HelpCircle, FileText, Scale, PlayCircle, Download, FileDown } from 'lucide-react';

type ScanType = 'quick' | 'medium' | 'full';
type Port = {
  number: number;
  status: 'open' | 'closed';
  service: string;
  risk: 'high' | 'medium' | 'low';
  suggestedAction: string;
};

function App() {
  const [ipAddress, setIpAddress] = useState('');
  const [scanType, setScanType] = useState<ScanType>('quick');
  const [isScanning, setIsScanning] = useState(false);
  const [reportType, setReportType] = useState<'pdf' | 'word'>('pdf');

  // Enhanced placeholder data with suggested actions
  const ports: Port[] = [
    { 
      number: 80, 
      status: 'open', 
      service: 'HTTP', 
      risk: 'medium',
      suggestedAction: 'Consider using HTTPS instead of HTTP'
    },
    { 
      number: 443, 
      status: 'open', 
      service: 'HTTPS', 
      risk: 'low',
      suggestedAction: 'Ensure TLS 1.3 is enabled'
    },
    { 
      number: 22, 
      status: 'open', 
      service: 'SSH', 
      risk: 'high',
      suggestedAction: 'Disable root login and use key-based authentication'
    },
    { 
      number: 3389, 
      status: 'open', 
      service: 'RDP', 
      risk: 'high',
      suggestedAction: 'Limit RDP access to VPN only'
    },
    { 
      number: 21, 
      status: 'open', 
      service: 'FTP', 
      risk: 'medium',
      suggestedAction: 'Replace FTP with SFTP'
    }
  ];

  const startScan = () => {
    if (!ipAddress) return;
    setIsScanning(true);
    // Placeholder for actual scan implementation
    setTimeout(() => setIsScanning(false), 2000);
  };

  const generateReport = () => {
    // Placeholder for report generation
    alert(`Generating ${reportType.toUpperCase()} report...`);
  };

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white">
        <div className="p-4 flex items-center space-x-3">
          <Shield className="w-8 h-8 text-blue-400" />
          <h1 className="text-xl font-bold">PortSentinel AI</h1>
        </div>
        
        <div className="p-4">
          <button
            onClick={startScan}
            disabled={isScanning || !ipAddress}
            className={`w-full py-2 px-4 rounded-lg flex items-center justify-center space-x-2 ${
              isScanning || !ipAddress ? 'bg-blue-400 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600'
            }`}
          >
            <PlayCircle className="w-5 h-5" />
            <span>{isScanning ? 'Scanning...' : 'Start Scan'}</span>
          </button>

          <div className="mt-4">
            <label className="block text-sm font-medium mb-2">IP Address</label>
            <input
              type="text"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="Enter IP address"
              className="w-full px-3 py-2 bg-gray-800 rounded-lg text-white placeholder-gray-400"
            />
          </div>

          <div className="mt-4">
            <label className="block text-sm font-medium mb-2">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value as ScanType)}
              className="w-full px-3 py-2 bg-gray-800 rounded-lg text-white"
            >
              <option value="quick">Quick: SYN scan</option>
              <option value="medium">Medium: TCP Connect</option>
              <option value="full">Slow: Full scan</option>
            </select>
          </div>

          <div className="mt-8 space-y-2">
            <a href="#" className="flex items-center space-x-2 text-gray-300 hover:text-white">
              <FileText className="w-5 h-5" />
              <span>README</span>
            </a>
            <a href="#" className="flex items-center space-x-2 text-gray-300 hover:text-white">
              <Scale className="w-5 h-5" />
              <span>LICENSE</span>
            </a>
            <a href="#" className="flex items-center space-x-2 text-gray-300 hover:text-white">
              <HelpCircle className="w-5 h-5" />
              <span>Help</span>
            </a>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-auto">
        <div className="p-8">
          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4">Scanned - Detected Ports</h2>
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Port</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Suggested Action</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {ports.map((port) => (
                    <tr key={port.number}>
                      <td className="px-6 py-4 whitespace-nowrap">{port.number}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          port.status === 'open' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }`}>
                          {port.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">{port.service}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          port.risk === 'high' ? 'bg-red-100 text-red-800' :
                          port.risk === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-green-100 text-green-800'
                        }`}>
                          {port.risk}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">{port.suggestedAction}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4">CVE Alerts</h2>
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center text-yellow-600">
                <AlertTriangle className="w-6 h-6 mr-2" />
                <p>AI-powered vulnerability analysis will be available once connected to the backend.</p>
              </div>
            </div>
          </div>

          <div className="mb-8">
            <h2 className="text-2xl font-bold mb-4">Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">Total Ports Scanned</div>
                <div className="text-2xl font-bold">50</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">Open Ports</div>
                <div className="text-2xl font-bold text-green-600">5</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">Closed Ports</div>
                <div className="text-2xl font-bold text-red-600">45</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">High Risk Ports</div>
                <div className="text-2xl font-bold text-red-600">2</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">Medium Risk Ports</div>
                <div className="text-2xl font-bold text-yellow-600">3</div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="text-gray-500 text-sm">Low Risk Ports</div>
                <div className="text-2xl font-bold text-green-600">0</div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-bold mb-4">Generate Scan Report</h2>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <input
                  type="radio"
                  id="pdf"
                  value="pdf"
                  checked={reportType === 'pdf'}
                  onChange={(e) => setReportType('pdf')}
                  className="text-blue-500"
                />
                <label htmlFor="pdf" className="text-gray-700">PDF Report</label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="radio"
                  id="word"
                  value="word"
                  checked={reportType === 'word'}
                  onChange={(e) => setReportType('word')}
                  className="text-blue-500"
                />
                <label htmlFor="word" className="text-gray-700">Word Report</label>
              </div>
              <button
                onClick={generateReport}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
              >
                <FileDown className="w-5 h-5" />
                <span>Generate Report</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;