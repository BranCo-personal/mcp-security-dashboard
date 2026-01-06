import React from 'react';
import { AlertTriangle, AlertCircle, Info, ChevronRight } from 'lucide-react';

function ResultsTable({ vulnerabilities, onSelectVuln }) {
  if (vulnerabilities.length === 0) {
    return (
      <div className="text-center py-8">
        <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-green-900/50 mb-3">
          <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <p className="text-green-400 font-medium">No vulnerabilities found</p>
        <p className="text-gray-500 text-sm mt-1">This MCP server appears to be secure</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {vulnerabilities.map((vuln, index) => (
        <VulnerabilityRow
          key={vuln.id || index}
          vulnerability={vuln}
          onClick={() => onSelectVuln(vuln)}
        />
      ))}
    </div>
  );
}

function VulnerabilityRow({ vulnerability, onClick }) {
  const { tool_name, vulnerability_type, risk_level, description } = vulnerability;

  const riskConfig = {
    CRITICAL: {
      icon: AlertTriangle,
      bg: 'bg-red-900/30',
      border: 'border-red-800',
      badge: 'bg-red-600',
      iconColor: 'text-red-400',
    },
    HIGH: {
      icon: AlertTriangle,
      bg: 'bg-orange-900/30',
      border: 'border-orange-800',
      badge: 'bg-orange-600',
      iconColor: 'text-orange-400',
    },
    MEDIUM: {
      icon: AlertCircle,
      bg: 'bg-yellow-900/30',
      border: 'border-yellow-800',
      badge: 'bg-yellow-600',
      iconColor: 'text-yellow-400',
    },
    LOW: {
      icon: Info,
      bg: 'bg-blue-900/30',
      border: 'border-blue-800',
      badge: 'bg-blue-600',
      iconColor: 'text-blue-400',
    },
    INFO: {
      icon: Info,
      bg: 'bg-gray-800',
      border: 'border-gray-700',
      badge: 'bg-gray-600',
      iconColor: 'text-gray-400',
    },
  };

  const config = riskConfig[risk_level] || riskConfig.INFO;
  const Icon = config.icon;

  // Format vulnerability type for display
  const formatType = (type) => {
    return type
      ?.replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div
      onClick={onClick}
      className={`${config.bg} border ${config.border} rounded-lg p-3 cursor-pointer hover:opacity-90 transition-opacity`}
    >
      <div className="flex items-start gap-3">
        <Icon className={`w-5 h-5 mt-0.5 ${config.iconColor}`} />
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-sm text-white">{tool_name}</span>
            <span className={`${config.badge} text-white text-xs px-2 py-0.5 rounded`}>
              {risk_level}
            </span>
          </div>
          
          <p className="text-sm text-gray-300 mb-1">
            {formatType(vulnerability_type)}
          </p>
          
          <p className="text-sm text-gray-400 line-clamp-2">
            {description}
          </p>
        </div>
        
        <ChevronRight className="w-5 h-5 text-gray-500" />
      </div>
    </div>
  );
}

export default ResultsTable;
