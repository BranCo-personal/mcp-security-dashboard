import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, Search, Trash2 } from 'lucide-react';
import ScanForm from './components/ScanForm';
import ResultsTable from './components/ResultsTable';
import VulnerabilityModal from './components/VulnerabilityModal';

const API_BASE = '/api';

function App() {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);

  // Fetch scans and stats on mount
  useEffect(() => {
    fetchScans();
    fetchStats();
  }, []);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_BASE}/scans`);
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const handleScan = async (target, scanType) => {
    setIsScanning(true);
    setError(null);
    
    try {
      const res = await fetch(`${API_BASE}/quick-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: scanType }),
      });
      
      if (!res.ok) {
        throw new Error('Scan failed');
      }
      
      const result = await res.json();
      
      // Add to scans list
      const newScan = {
        scan_id: Date.now().toString(),
        target,
        scan_type: scanType,
        status: 'completed',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        vulnerabilities: result.vulnerabilities,
        summary: result.summary,
      };
      
      setScans(prev => [newScan, ...prev]);
      setSelectedScan(newScan);
      fetchStats();
      
    } catch (err) {
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await fetch(`${API_BASE}/scan/${scanId}`, { method: 'DELETE' });
      setScans(prev => prev.filter(s => s.scan_id !== scanId));
      if (selectedScan?.scan_id === scanId) {
        setSelectedScan(null);
      }
      fetchStats();
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold text-white">MCP Security Dashboard</h1>
              <p className="text-sm text-gray-400">Scan MCP servers for vulnerabilities</p>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard
              icon={<Search className="w-5 h-5" />}
              label="Total Scans"
              value={stats.total_scans}
              color="blue"
            />
            <StatCard
              icon={<Clock className="w-5 h-5" />}
              label="Today"
              value={stats.scans_today}
              color="green"
            />
            <StatCard
              icon={<AlertTriangle className="w-5 h-5" />}
              label="Critical"
              value={stats.critical_count}
              color="red"
            />
            <StatCard
              icon={<AlertTriangle className="w-5 h-5" />}
              label="High Risk"
              value={stats.high_count}
              color="orange"
            />
          </div>
        )}

        {/* Scan Form */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">New Scan</h2>
          <ScanForm onScan={handleScan} isScanning={isScanning} />
          {error && (
            <div className="mt-4 p-3 bg-red-900/50 border border-red-700 rounded text-red-200">
              {error}
            </div>
          )}
        </div>

        {/* Results */}
        <div className="grid md:grid-cols-2 gap-6">
          {/* Scan History */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Scan History</h2>
            {scans.length === 0 ? (
              <p className="text-gray-500 text-center py-8">
                No scans yet. Run your first scan above!
              </p>
            ) : (
              <div className="space-y-2">
                {scans.map(scan => (
                  <ScanListItem
                    key={scan.scan_id}
                    scan={scan}
                    isSelected={selectedScan?.scan_id === scan.scan_id}
                    onClick={() => setSelectedScan(scan)}
                    onDelete={() => handleDeleteScan(scan.scan_id)}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Selected Scan Results */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Vulnerabilities</h2>
            {selectedScan ? (
              <ResultsTable
                vulnerabilities={selectedScan.vulnerabilities || []}
                onSelectVuln={setSelectedVuln}
              />
            ) : (
              <p className="text-gray-500 text-center py-8">
                Select a scan to view results
              </p>
            )}
          </div>
        </div>
      </main>

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <VulnerabilityModal
          vulnerability={selectedVuln}
          onClose={() => setSelectedVuln(null)}
        />
      )}
    </div>
  );
}

// Stat Card Component
function StatCard({ icon, label, value, color }) {
  const colors = {
    blue: 'bg-blue-900/50 border-blue-700 text-blue-400',
    green: 'bg-green-900/50 border-green-700 text-green-400',
    red: 'bg-red-900/50 border-red-700 text-red-400',
    orange: 'bg-orange-900/50 border-orange-700 text-orange-400',
  };

  return (
    <div className={`rounded-lg border p-4 ${colors[color]}`}>
      <div className="flex items-center gap-2 mb-1">
        {icon}
        <span className="text-sm text-gray-400">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}

// Scan List Item Component
function ScanListItem({ scan, isSelected, onClick, onDelete }) {
  const criticalCount = scan.summary?.critical || 0;
  const highCount = scan.summary?.high || 0;
  const totalVulns = scan.summary?.total || 0;

  return (
    <div
      onClick={onClick}
      className={`p-3 rounded-lg cursor-pointer transition-colors ${
        isSelected
          ? 'bg-blue-900/50 border border-blue-700'
          : 'bg-gray-700/50 hover:bg-gray-700'
      }`}
    >
      <div className="flex justify-between items-start">
        <div className="flex-1 min-w-0">
          <p className="font-medium truncate">{scan.target}</p>
          <p className="text-sm text-gray-400">
            {new Date(scan.started_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {totalVulns > 0 ? (
            <span className={`px-2 py-1 rounded text-xs font-medium ${
              criticalCount > 0
                ? 'bg-red-900 text-red-200'
                : highCount > 0
                ? 'bg-orange-900 text-orange-200'
                : 'bg-yellow-900 text-yellow-200'
            }`}>
              {totalVulns} issues
            </span>
          ) : (
            <span className="px-2 py-1 rounded text-xs font-medium bg-green-900 text-green-200">
              Clean
            </span>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDelete();
            }}
            className="p-1 hover:bg-gray-600 rounded"
          >
            <Trash2 className="w-4 h-4 text-gray-400" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
