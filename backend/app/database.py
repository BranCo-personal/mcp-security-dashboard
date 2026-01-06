"""
Database module for MCP Security Dashboard

Uses SQLite for simple, file-based persistence.
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path


class Database:
    """SQLite database for storing scan results."""
    
    def __init__(self, db_path: str = "mcp_scans.db"):
        self.db_path = db_path
        self.conn = None
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def init_db(self):
        """Initialize database tables."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                error TEXT
            )
        """)
        
        # Create vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                tool_name TEXT,
                vulnerability_type TEXT,
                risk_level TEXT,
                description TEXT,
                evidence TEXT,
                owasp_mapping TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_started 
            ON scans (started_at DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulns_scan 
            ON vulnerabilities (scan_id)
        """)
        
        conn.commit()
    
    def create_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        status: str = "running"
    ):
        """Create a new scan record."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scans (scan_id, target, scan_type, status, started_at)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, target, scan_type, status, datetime.utcnow()))
        
        conn.commit()
    
    def update_scan(
        self,
        scan_id: str,
        status: str,
        results: Optional[list] = None,
        error: Optional[str] = None
    ):
        """Update scan status and store results."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Update scan record
        cursor.execute("""
            UPDATE scans 
            SET status = ?, completed_at = ?, error = ?
            WHERE scan_id = ?
        """, (status, datetime.utcnow(), error, scan_id))
        
        # Store vulnerabilities if any
        if results:
            for vuln in results:
                cursor.execute("""
                    INSERT INTO vulnerabilities 
                    (id, scan_id, tool_name, vulnerability_type, risk_level, 
                     description, evidence, owasp_mapping, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vuln.get("id"),
                    scan_id,
                    vuln.get("tool_name"),
                    vuln.get("vulnerability_type"),
                    vuln.get("risk_level"),
                    vuln.get("description"),
                    vuln.get("evidence"),
                    vuln.get("owasp_mapping"),
                    vuln.get("remediation")
                ))
        
        conn.commit()
    
    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Get scan results by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Get scan record
        cursor.execute("""
            SELECT * FROM scans WHERE scan_id = ?
        """, (scan_id,))
        
        scan_row = cursor.fetchone()
        if not scan_row:
            return None
        
        scan = dict(scan_row)
        
        # Get vulnerabilities
        cursor.execute("""
            SELECT * FROM vulnerabilities WHERE scan_id = ?
        """, (scan_id,))
        
        vulnerabilities = [dict(row) for row in cursor.fetchall()]
        
        # Build summary
        summary = {
            "total": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v["risk_level"] == "CRITICAL"]),
            "high": len([v for v in vulnerabilities if v["risk_level"] == "HIGH"]),
            "medium": len([v for v in vulnerabilities if v["risk_level"] == "MEDIUM"]),
            "low": len([v for v in vulnerabilities if v["risk_level"] == "LOW"]),
        }
        
        return {
            "scan_id": scan["scan_id"],
            "target": scan["target"],
            "scan_type": scan["scan_type"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "completed_at": scan["completed_at"],
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "error": scan["error"]
        }
    
    def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scans."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scans 
            ORDER BY started_at DESC 
            LIMIT ?
        """, (limit,))
        
        scans = []
        for row in cursor.fetchall():
            scan = dict(row)
            
            # Get vulnerability count
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low
                FROM vulnerabilities 
                WHERE scan_id = ?
            """, (scan["scan_id"],))
            
            counts = dict(cursor.fetchone())
            
            scans.append({
                "scan_id": scan["scan_id"],
                "target": scan["target"],
                "scan_type": scan["scan_type"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
                "vulnerabilities": [],  # Don't include full vulns in list
                "summary": {
                    "total": counts["total"] or 0,
                    "critical": counts["critical"] or 0,
                    "high": counts["high"] or 0,
                    "medium": counts["medium"] or 0,
                    "low": counts["low"] or 0,
                },
                "error": scan["error"]
            })
        
        return scans
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its vulnerabilities."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Check if scan exists
        cursor.execute("SELECT scan_id FROM scans WHERE scan_id = ?", (scan_id,))
        if not cursor.fetchone():
            return False
        
        # Delete vulnerabilities first (foreign key)
        cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        
        conn.commit()
        return True
    
    def get_stats(self) -> dict:
        """Get dashboard statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        # Scans today
        today = datetime.utcnow().date()
        cursor.execute("""
            SELECT COUNT(*) FROM scans 
            WHERE DATE(started_at) = ?
        """, (today.isoformat(),))
        scans_today = cursor.fetchone()[0]
        
        # Vulnerability counts
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high
            FROM vulnerabilities
        """)
        vuln_counts = dict(cursor.fetchone())
        
        return {
            "total_scans": total_scans,
            "scans_today": scans_today,
            "total_vulnerabilities": vuln_counts["total"] or 0,
            "critical_count": vuln_counts["critical"] or 0,
            "high_count": vuln_counts["high"] or 0
        }
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
