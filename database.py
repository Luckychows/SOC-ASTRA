#!/usr/bin/env python3
"""
Database Layer for SOC-ASTRA Web Application
SQLite database for incident storage and management
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class IncidentDatabase:
    """Manages incident storage and retrieval"""
    
    def __init__(self, db_path: str = "./data/incidents.db"):
        self.db_path = db_path
        self._ensure_data_directory()
        self._init_database()
    
    def _ensure_data_directory(self):
        """Create data directory if it doesn't exist"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                username TEXT,
                hostname TEXT,
                severity TEXT,
                confidence INTEGER,
                threat_type TEXT,
                mitre_attack TEXT,
                ip_reputation TEXT,
                analysis TEXT,
                recommendation TEXT,
                auto_escalate BOOLEAN,
                ioc_indicators TEXT,
                raw_log TEXT,
                status TEXT DEFAULT 'new',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Create indexes for common queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON incidents(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON incidents(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON incidents(created_at)')
        
        conn.commit()
        conn.close()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def insert_incident(self, incident: Dict) -> int:
        """Insert new incident"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        # Convert IOC indicators to JSON string
        ioc_indicators = incident.get('ioc_indicators', [])
        if isinstance(ioc_indicators, list):
            ioc_indicators = json.dumps(ioc_indicators)
        
        try:
            cursor.execute('''
                INSERT INTO incidents (
                    alert_id, timestamp, event_type, source_ip, dest_ip,
                    username, hostname, severity, confidence, threat_type,
                    mitre_attack, ip_reputation, analysis, recommendation,
                    auto_escalate, ioc_indicators, raw_log, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident.get('alert_id'),
                incident.get('timestamp'),
                incident.get('event_type'),
                incident.get('source_ip'),
                incident.get('dest_ip'),
                incident.get('username'),
                incident.get('hostname'),
                incident.get('severity'),
                incident.get('confidence'),
                incident.get('threat_type'),
                incident.get('mitre_attack'),
                incident.get('ip_reputation'),
                incident.get('analysis'),
                incident.get('recommendation'),
                incident.get('auto_escalate', False),
                ioc_indicators,
                incident.get('raw_log'),
                incident.get('status', 'new'),
                now,
                now
            ))
            
            incident_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return incident_id
            
        except sqlite3.IntegrityError:
            conn.close()
            # Alert ID already exists, return -1
            return -1
        except Exception as e:
            conn.close()
            raise e
    
    def get_incident_by_id(self, incident_id: int) -> Optional[Dict]:
        """Get incident by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_dict(row)
        return None
    
    def get_incident_by_alert_id(self, alert_id: str) -> Optional[Dict]:
        """Get incident by alert ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM incidents WHERE alert_id = ?', (alert_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_dict(row)
        return None
    
    def get_incidents(self, limit: int = 100, offset: int = 0, 
                     severity: Optional[List[str]] = None,
                     status: Optional[str] = None,
                     source_ip: Optional[str] = None) -> List[Dict]:
        """Get incidents with filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM incidents WHERE 1=1'
        params = []
        
        if severity:
            placeholders = ','.join('?' * len(severity))
            query += f' AND severity IN ({placeholders})'
            params.extend(severity)
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        if source_ip:
            query += ' AND source_ip LIKE ?'
            params.append(f'%{source_ip}%')
        
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_dict(row) for row in rows]
    
    def update_incident_status(self, incident_id: int, status: str) -> bool:
        """Update incident status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute('''
            UPDATE incidents 
            SET status = ?, updated_at = ?
            WHERE id = ?
        ''', (status, now, incident_id))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def count_incidents(self, severity: Optional[List[str]] = None,
                       status: Optional[str] = None) -> int:
        """Count incidents with filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT COUNT(*) as count FROM incidents WHERE 1=1'
        params = []
        
        if severity:
            placeholders = ','.join('?' * len(severity))
            query += f' AND severity IN ({placeholders})'
            params.extend(severity)
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        cursor.execute(query, params)
        result = cursor.fetchone()
        conn.close()
        
        return result['count'] if result else 0
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count by severity"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM incidents 
            GROUP BY severity
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for row in rows:
            counts[row['severity']] = row['count']
        
        return counts
    
    def get_top_source_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top source IPs by incident count"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM incidents 
            WHERE source_ip IS NOT NULL AND source_ip != 'N/A'
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [(row['source_ip'], row['count']) for row in rows]
    
    def get_recent_incidents(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent incidents within specified hours"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Calculate cutoff time
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE created_at >= ?
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (cutoff, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_dict(row) for row in rows]
    
    def get_incidents_by_ip(self, ip_address: str, limit: int = 50) -> List[Dict]:
        """Get all incidents related to an IP"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM incidents 
            WHERE source_ip = ? OR dest_ip = ?
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (ip_address, ip_address, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_dict(row) for row in rows]
    
    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert SQLite row to dictionary"""
        incident = dict(row)
        
        # Parse IOC indicators from JSON
        if incident.get('ioc_indicators'):
            try:
                incident['ioc_indicators'] = json.loads(incident['ioc_indicators'])
            except:
                incident['ioc_indicators'] = []
        else:
            incident['ioc_indicators'] = []
        
        # Convert boolean
        incident['auto_escalate'] = bool(incident.get('auto_escalate'))
        
        return incident
    
    def clear_all_incidents(self):
        """Clear all incidents (for testing)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM incidents')
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total count
        cursor.execute('SELECT COUNT(*) as total FROM incidents')
        total = cursor.fetchone()['total']
        
        # Severity counts
        severity_counts = self.get_severity_counts()
        
        # Status counts
        cursor.execute('''
            SELECT status, COUNT(*) as count 
            FROM incidents 
            GROUP BY status
        ''')
        status_rows = cursor.fetchall()
        status_counts = {row['status']: row['count'] for row in status_rows}
        
        # Recent activity (last 24 hours)
        from datetime import timedelta
        cutoff_24h = (datetime.now() - timedelta(hours=24)).isoformat()
        cursor.execute('SELECT COUNT(*) as count FROM incidents WHERE created_at >= ?', (cutoff_24h,))
        incidents_24h = cursor.fetchone()['count']
        
        conn.close()
        
        return {
            'total_incidents': total,
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'incidents_last_24h': incidents_24h,
            'top_source_ips': self.get_top_source_ips(5)
        }


def initialize_database(db_path: str = "./data/incidents.db"):
    """Initialize database (for CLI usage)"""
    print(f"Initializing database at {db_path}...")
    db = IncidentDatabase(db_path)
    print("✅ Database initialized successfully")
    
    # Print stats
    stats = db.get_statistics()
    print(f"\n📊 Database Statistics:")
    print(f"   Total Incidents: {stats['total_incidents']}")
    print(f"   Incidents (24h): {stats['incidents_last_24h']}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--init':
        db_path = sys.argv[2] if len(sys.argv) > 2 else "./data/incidents.db"
        initialize_database(db_path)
    else:
        print("Usage: python database.py --init [db_path]")




