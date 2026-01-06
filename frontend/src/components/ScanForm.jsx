import React, { useState } from 'react';
import { Search, Loader2 } from 'lucide-react';

function ScanForm({ onScan, isScanning }) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('url');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (target.trim()) {
      onScan(target.trim(), scanType);
    }
  };

  const handleDemo = () => {
    // Use a demo target that will trigger the built-in vulnerable tools
    setTarget('demo://vulnerable-mcp-server');
    setScanType('url');
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="flex flex-col md:flex-row gap-4">
        {/* Scan Type Select */}
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-4 py-2.5 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        >
          <option value="url">HTTP/SSE URL</option>
          <option value="stdio">Stdio Command</option>
          <option value="config">Config File</option>
        </select>

        {/* Target Input */}
        <div className="flex-1 relative">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              scanType === 'url'
                ? 'https://api.example.com/mcp'
                : scanType === 'stdio'
                ? 'npx @modelcontextprotocol/server-example'
                : '~/.config/claude/claude_desktop_config.json'
            }
            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2.5 text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        {/* Scan Button */}
        <button
          type="submit"
          disabled={isScanning || !target.trim()}
          className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium px-6 py-2.5 rounded-lg transition-colors"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Search className="w-5 h-5" />
              Scan
            </>
          )}
        </button>
      </div>

      {/* Demo Button */}
      <div className="mt-3">
        <button
          type="button"
          onClick={handleDemo}
          className="text-sm text-blue-400 hover:text-blue-300 underline"
        >
          Try demo scan with vulnerable MCP server
        </button>
      </div>

      {/* Help Text */}
      <div className="mt-4 text-sm text-gray-400">
        <p>
          <strong>URL:</strong> Scan an MCP server accessible via HTTP/SSE
        </p>
        <p>
          <strong>Stdio:</strong> Scan a local MCP server started via command line
        </p>
        <p>
          <strong>Config:</strong> Scan all servers defined in a config file (Claude Desktop, Cursor, etc.)
        </p>
      </div>
    </form>
  );
}

export default ScanForm;
