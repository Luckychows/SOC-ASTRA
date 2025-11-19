#!/usr/bin/env python3
"""
Log Processing Engine for SOC-ASTRA
Handles async log ingestion, queuing, and AI analysis
"""

import queue
import threading
import time
import os
from datetime import datetime
from typing import Dict, Optional
from database import IncidentDatabase


class LogQueue:
    """Thread-safe queue for log processing"""
    
    def __init__(self, maxsize: int = 1000):
        self.queue = queue.Queue(maxsize=maxsize)
        self.total_received = 0
        self.total_processed = 0
        self.lock = threading.Lock()
    
    def add_log(self, log: Dict) -> bool:
        """Add log to queue"""
        try:
            self.queue.put(log, block=False)
            with self.lock:
                self.total_received += 1
            return True
        except queue.Full:
            return False
    
    def get_log(self, timeout: float = 1.0) -> Optional[Dict]:
        """Get log from queue"""
        try:
            return self.queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def mark_done(self):
        """Mark task as done"""
        self.queue.task_done()
        with self.lock:
            self.total_processed += 1
    
    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self.lock:
            return {
                'queue_size': self.queue.qsize(),
                'total_received': self.total_received,
                'total_processed': self.total_processed,
                'pending': self.total_received - self.total_processed
            }


class AnalysisWorker(threading.Thread):
    """Worker thread for processing logs"""
    
    def __init__(self, worker_id: int, log_queue: LogQueue, 
                 ai_copilot, rag_manager, database: IncidentDatabase):
        super().__init__()
        self.worker_id = worker_id
        self.log_queue = log_queue
        self.ai_copilot = ai_copilot
        self.rag_manager = rag_manager
        self.database = database
        self.running = True
        self.daemon = True
        self.processed_count = 0
        self.error_count = 0
    
    def run(self):
        """Main worker loop"""
        print(f"✅ Worker {self.worker_id} started")
        
        while self.running:
            log = self.log_queue.get_log(timeout=1.0)
            
            if log is None:
                continue
            
            try:
                self._process_log(log)
                self.processed_count += 1
            except Exception as e:
                print(f"❌ Worker {self.worker_id} error: {e}")
                self.error_count += 1
            finally:
                self.log_queue.mark_done()
    
    def _process_log(self, log: Dict):
        """Process a single log"""
        # Normalize log format
        normalized_log = self._normalize_log(log)
        
        # Generate alert ID if not present
        if 'alert_id' not in normalized_log:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            normalized_log['alert_id'] = f"SOC-{timestamp}-{self.processed_count:04d}"
        
        # Check if already processed
        existing = self.database.get_incident_by_alert_id(normalized_log['alert_id'])
        if existing:
            print(f"⏭️  Skipping duplicate: {normalized_log['alert_id']}")
            return
        
        # Analyze with AI
        analysis = self._analyze_with_ai(normalized_log)
        
        # Merge analysis with log
        incident = {**normalized_log, **analysis}
        incident['status'] = 'new'
        incident['created_at'] = datetime.now().isoformat()
        
        # Store in database
        incident_id = self.database.insert_incident(incident)
        
        if incident_id > 0:
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(analysis.get('severity', 'MEDIUM'), '⚪')
            
            print(f"{severity_icon} Worker {self.worker_id}: Processed {normalized_log.get('event_type', 'Unknown')} "
                  f"[{analysis.get('severity')}] - ID: {incident_id}")
    
    def _normalize_log(self, log: Dict) -> Dict:
        """Normalize incoming log to standard format"""
        # Handle different log formats
        normalized = {
            'timestamp': log.get('timestamp', datetime.now().isoformat()),
            'event_type': log.get('event_type', log.get('eventType', 'Unknown Event')),
            'source_ip': log.get('source_ip', log.get('sourceIP', log.get('src_ip', 'N/A'))),
            'dest_ip': log.get('dest_ip', log.get('destIP', log.get('dst_ip', 'N/A'))),
            'username': log.get('username', log.get('user', 'N/A')),
            'hostname': log.get('hostname', log.get('host', 'N/A')),
            'event_id': str(log.get('event_id', log.get('eventID', 'N/A'))),
            'raw_log': log.get('raw_log', log.get('message', str(log)))
        }
        
        # Preserve alert_id if present
        if 'alert_id' in log:
            normalized['alert_id'] = log['alert_id']
        
        # Preserve any additional fields
        for key, value in log.items():
            if key not in normalized:
                normalized[key] = value
        
        return normalized
    
    def _analyze_with_ai(self, log: Dict) -> Dict:
        """Analyze log with AI"""
        try:
            # Use AI copilot for analysis
            analysis = self.ai_copilot.analyze_with_ai(log)
            
            # Ensure all required fields are present
            default_analysis = {
                'severity': 'MEDIUM',
                'confidence': 50,
                'threat_type': 'Unknown',
                'mitre_attack': 'N/A',
                'ip_reputation': 'Unknown',
                'analysis': 'Analysis unavailable',
                'recommendation': 'Manual review required',
                'auto_escalate': False,
                'ioc_indicators': []
            }
            
            # Merge with defaults
            return {**default_analysis, **analysis}
            
        except Exception as e:
            print(f"⚠️  Analysis error: {e}")
            return {
                'severity': 'MEDIUM',
                'confidence': 0,
                'threat_type': 'Analysis Failed',
                'mitre_attack': 'N/A',
                'ip_reputation': 'Unknown',
                'analysis': f'AI analysis failed: {str(e)}',
                'recommendation': 'Manual review required',
                'auto_escalate': True,
                'ioc_indicators': [log.get('source_ip', 'Unknown')]
            }
    
    def stop(self):
        """Stop worker"""
        self.running = False
        print(f"🛑 Worker {self.worker_id} stopping...")


class LogProcessor:
    """Main log processing coordinator"""
    
    def __init__(self, ai_copilot, rag_manager, database: IncidentDatabase, 
                 num_workers: int = 2):
        self.log_queue = LogQueue(maxsize=1000)
        self.ai_copilot = ai_copilot
        self.rag_manager = rag_manager
        self.database = database
        self.num_workers = num_workers
        self.workers = []
        self.running = False
        
        # Batch update tracking for RAG
        self.batch_logs = []
        self.batch_size = int(os.getenv("RAG_BATCH_SIZE", "100"))
    
    def start(self):
        """Start processing workers"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = AnalysisWorker(
                worker_id=i+1,
                log_queue=self.log_queue,
                ai_copilot=self.ai_copilot,
                rag_manager=self.rag_manager,
                database=self.database
            )
            worker.start()
            self.workers.append(worker)
        
        print(f"✅ Started {self.num_workers} analysis workers")
    
    def stop(self):
        """Stop all workers"""
        if not self.running:
            return
        
        print("\n🛑 Stopping log processor...")
        self.running = False
        
        # Stop all workers
        for worker in self.workers:
            worker.stop()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        print("✅ Log processor stopped")
    
    def ingest_log(self, log: Dict) -> bool:
        """Ingest a single log"""
        success = self.log_queue.add_log(log)
        
        if success:
            # Add to batch for RAG updates
            self.batch_logs.append(log)
            
            # Batch update RAG if threshold reached
            if len(self.batch_logs) >= self.batch_size:
                self._batch_update_rag()
        
        return success
    
    def _batch_update_rag(self):
        """Batch update RAG vector store"""
        if not self.rag_manager or not self.batch_logs:
            return
        
        try:
            print(f"\n🔄 Batch updating RAG with {len(self.batch_logs)} logs...")
            
            # Insert into vector store
            self.rag_manager.insert_events(self.batch_logs, batch_size=50)
            
            # Update IP profiles
            self.rag_manager.build_ip_profiles(self.batch_logs)
            
            print(f"✅ RAG updated successfully")
            
            # Clear batch
            self.batch_logs = []
            
        except Exception as e:
            print(f"⚠️  RAG batch update failed: {e}")
    
    def get_stats(self) -> Dict:
        """Get processing statistics"""
        queue_stats = self.log_queue.get_stats()
        
        worker_stats = []
        for worker in self.workers:
            worker_stats.append({
                'worker_id': worker.worker_id,
                'processed': worker.processed_count,
                'errors': worker.error_count,
                'running': worker.is_alive()
            })
        
        return {
            'queue': queue_stats,
            'workers': worker_stats,
            'batch_pending': len(self.batch_logs),
            'running': self.running
        }
    
    def wait_for_completion(self, timeout: Optional[float] = None):
        """Wait for all logs to be processed"""
        start_time = time.time()
        
        while True:
            stats = self.log_queue.get_stats()
            if stats['pending'] == 0:
                break
            
            if timeout and (time.time() - start_time) > timeout:
                break
            
            time.sleep(0.5)


def test_processor():
    """Test the log processor"""
    from dotenv import load_dotenv
    load_dotenv()
    
    # Initialize components
    db = IncidentDatabase()
    
    # Mock AI copilot
    class MockAICopilot:
        def analyze_with_ai(self, log):
            return {
                'severity': 'HIGH',
                'confidence': 85,
                'threat_type': 'Test Alert',
                'mitre_attack': 'T1110 - Brute Force',
                'ip_reputation': 'Suspicious',
                'analysis': 'This is a test analysis',
                'recommendation': 'Review and investigate',
                'auto_escalate': False,
                'ioc_indicators': [log.get('source_ip')]
            }
    
    copilot = MockAICopilot()
    
    # Create processor
    processor = LogProcessor(copilot, None, db, num_workers=2)
    processor.start()
    
    # Test logs
    test_logs = [
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'Failed Login',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'username': 'admin',
            'raw_log': 'Test log 1'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'Port Scan',
            'source_ip': '203.0.113.50',
            'dest_ip': '10.0.0.10',
            'username': 'N/A',
            'raw_log': 'Test log 2'
        }
    ]
    
    # Ingest test logs
    for log in test_logs:
        processor.ingest_log(log)
    
    # Wait for processing
    print("\nWaiting for processing...")
    processor.wait_for_completion(timeout=10)
    
    # Print stats
    stats = processor.get_stats()
    print(f"\n📊 Processing Stats:")
    print(f"   Received: {stats['queue']['total_received']}")
    print(f"   Processed: {stats['queue']['total_processed']}")
    print(f"   Pending: {stats['queue']['pending']}")
    
    # Stop processor
    processor.stop()
    
    # Check database
    incidents = db.get_incidents(limit=10)
    print(f"\n📁 Incidents in database: {len(incidents)}")
    for incident in incidents:
        print(f"   - {incident['alert_id']}: {incident['event_type']} [{incident['severity']}]")


if __name__ == "__main__":
    print("Testing Log Processor...\n")
    test_processor()




