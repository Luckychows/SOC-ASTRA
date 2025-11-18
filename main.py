
#!/usr/bin/env python3
"""
AI-SOC Copilot v3.0: Complete Multi-Model Security Analysis System
Supports: Claude, GPT-4, Gemini, Ollama
Datasets: MORDOR, UNSW-NB15, CICIDS2017, Splunk/ELK
"""

import json
import os
import sys
import time
import requests
import zipfile
import io
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd
from pathlib import Path

class AISOCCopilot:
    """Main SOC Analysis System"""
    
    def _init_(self):
        self.model_provider = None
        self.client = None
        self.api_key = None
        self.alerts = []
        self.stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "dismissed": 0}
    
    def display_banner(self):
        """Display welcome banner"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🛡  AI-SOC COPILOT v3.0                             ║
║              Intelligent Security Operations Center              ║
║                                                                  ║
║              Multi-Model | Multi-Dataset | Production Ready      ║
║              Developers: Luckychowdary		          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """)
    
    def select_ai_model(self):
        """Interactive AI model selection"""
        print("\n" + "="*70)
        print("🤖 SELECT AI MODEL FOR ANALYSIS")
        print("="*70 + "\n")
        
        # Check for available API keys
        claude_key = os.getenv("ANTHROPIC_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")
        gemini_key = os.getenv("GOOGLE_API_KEY")
        
        models = []
        
        # Model 1: Claude
        models.append({
            "num": "1",
            "name": "Anthropic Claude Sonnet 4",
            "provider": "claude",
            "key": claude_key,
            "available": bool(claude_key)
        })
        
        # Model 2: OpenAI
        models.append({
            "num": "2",
            "name": "OpenAI GPT-4o",
            "provider": "openai",
            "key": openai_key,
            "available": bool(openai_key)
        })
        
        # Model 3: Gemini
        models.append({
            "num": "3",
            "name": "Google Gemini Pro",
            "provider": "gemini",
            "key": gemini_key,
            "available": bool(gemini_key)
        })
        
        # Model 4: Ollama
        models.append({
            "num": "4",
            "name": "Ollama (Local LLaMA 3)",
            "provider": "ollama",
            "key": None,
            "available": True
        })
        
        # Display models
        for model in models:
            status = "✅ AVAILABLE" if model["available"] else "⚠  REQUIRES SETUP"
            print(f"{model['num']}. {model['name']}")
            print(f"   Provider: {model['provider'].upper()}")
            print(f"   Status: {status}")
            if model["key"]:
                print(f"   API Key: {model['key'][:15]}...{model['key'][-5:]}")
            print()
        
        print("5. Enter API Key Manually\n")
        
        # Get selection
        while True:
            choice = input("Select AI Model (1-5): ").strip()
            
            if choice == "5":
                return self._manual_api_key_entry()
            
            if choice in ["1", "2", "3", "4"]:
                selected = models[int(choice) - 1]
                
                if not selected["available"] and choice != "4":
                    print(f"❌ No API key found for {selected['name']}")
                    retry = input("Enter API key manually? (y/n): ").strip().lower()
                    if retry == "y":
                        return self._manual_api_key_entry()
                    continue
                
                self.model_provider = selected["provider"]
                self.api_key = selected["key"]
                
                print(f"\n✅ Selected: {selected['name']}\n")
                return self._initialize_client()
            
            print("❌ Invalid selection. Try again.")
    
    def _manual_api_key_entry(self):
        """Manual API key entry"""
        print("\n" + "="*70)
        print("🔑 MANUAL API KEY ENTRY")
        print("="*70 + "\n")
        
        print("Select Provider:")
        print("1. Anthropic Claude")
        print("2. OpenAI GPT-4")
        print("3. Google Gemini")
        print()
        
        choice = input("Select provider (1-3): ").strip()
        
        providers = {
            "1": "claude",
            "2": "openai",
            "3": "gemini"
        }
        
        if choice not in providers:
            print("❌ Invalid selection")
            return False
        
        self.model_provider = providers[choice]
        api_key = input(f"\nEnter your {self.model_provider.upper()} API Key: ").strip()
        
        if not api_key:
            print("❌ No API key provided")
            return False
        
        self.api_key = api_key
        
        # Save to environment
        env_vars = {
            "claude": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GOOGLE_API_KEY"
        }
        os.environ[env_vars[self.model_provider]] = api_key
        
        print(f"\n✅ API Key saved for {self.model_provider.upper()}")
        return self._initialize_client()
    
    def _initialize_client(self):
        """Initialize AI client"""
        try:
            if self.model_provider == "claude":
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                print("✅ Claude client initialized")
                return True
            
            elif self.model_provider == "openai":
                import openai
                openai.api_key = self.api_key
                self.client = openai
                print("✅ OpenAI client initialized")
                return True
            
            elif self.model_provider == "gemini":
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel('gemini-pro')
                print("✅ Gemini client initialized")
                return True
            
            elif self.model_provider == "ollama":
                response = requests.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    self.client = requests
                    print("✅ Ollama client initialized")
                    return True
                else:
                    print("❌ Ollama not running. Start with: ollama serve")
                    return False
        
        except ImportError as e:
            print(f"❌ Missing library. Install with: pip3 install {self.model_provider}")
            return False
        except Exception as e:
            print(f"❌ Initialization error: {e}")
            return False
    
    def select_dataset(self):
        """Dataset selection"""
        print("\n" + "="*70)
        print("📊 SELECT DATASET FOR ANALYSIS")
        print("="*70 + "\n")
        
        datasets = [
            {
                "num": "1",
                "name": "MORDOR - Real Attack Simulations",
                "type": "mordor",
                "description": "Real adversary simulation logs (Empire, Covenant, Mimikatz)"
            },
            {
                "num": "2",
                "name": "UNSW-NB15 - Network Traffic",
                "type": "unsw",
                "description": "Network traffic with labeled attack categories"
            },
            {
                "num": "3",
                "name": "CICIDS2017 - IDS/IPS Logs",
                "type": "cicids",
                "description": "Modern attack scenarios (DDoS, Brute Force, Web attacks)"
            },
            {
                "num": "4",
                "name": "Splunk/ELK Sample Logs",
                "type": "splunk",
                "description": "Real SIEM logs from Splunk/Elastic repositories"
            },
            {
                "num": "5",
                "name": "Upload Custom Dataset",
                "type": "custom",
                "description": "Upload your own SIEM logs (CSV/JSON)"
            }
        ]
        
        for ds in datasets:
            print(f"{ds['num']}. {ds['name']}")
            print(f"   Description: {ds['description']}")
            print()
        
        while True:
            choice = input("Select Dataset (1-5): ").strip()
            
            if choice in ["1", "2", "3", "4", "5"]:
                selected = datasets[int(choice) - 1]
                print(f"\n✅ Selected: {selected['name']}")
                
                if selected['type'] == 'mordor':
                    return self._load_mordor_dataset()
                elif selected['type'] == 'unsw':
                    return self._load_synthetic_unsw()
                elif selected['type'] == 'cicids':
                    return self._load_synthetic_cicids()
                elif selected['type'] == 'splunk':
                    return self._load_synthetic_splunk()
                elif selected['type'] == 'custom':
                    return self._load_custom_dataset()
            
            print("❌ Invalid selection. Try again.")
    
    def _load_mordor_dataset(self):
        """Load MORDOR dataset"""
        print("\n📥 MORDOR Dataset Options:\n")
        
        scenarios = [
            {
                "num": "1",
                "name": "DCSync Credential Dumping",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/small/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
                "mitre": "T1003.006"
            },
            {
                "num": "2",
                "name": "Password Spraying",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/small/windows/credential_access/host/empire_spray_passwords.zip",
                "mitre": "T1110.003"
            },
            {
                "num": "3",
                "name": "PSExec Lateral Movement",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/small/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
                "mitre": "T1021.002"
            }
        ]
        
        for sc in scenarios:
            print(f"{sc['num']}. {sc['name']} (MITRE: {sc['mitre']})")
        
        choice = input("\nSelect MORDOR scenario (1-3): ").strip()
        
        if choice not in ["1", "2", "3"]:
            print("❌ Invalid choice, using option 1")
            choice = "1"
        
        selected = scenarios[int(choice) - 1]
        print(f"\n📥 Downloading: {selected['name']}...")
        
        try:
            response = requests.get(selected['url'], timeout=60)
            response.raise_for_status()
            
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                json_files = [f for f in zip_file.namelist() if f.endswith('.json')]
                
                if not json_files:
                    print("❌ No JSON files found")
                    return []
                
                print(f"✅ Extracted: {json_files[0]}")
                
                with zip_file.open(json_files[0]) as json_file:
                    logs = []
                    for line in json_file:
                        try:
                            log = json.loads(line.decode('utf-8'))
                            parsed = self._parse_mordor_log(log)
                            if parsed:
                                logs.append(parsed)
                        except:
                            continue
                    
                    print(f"✅ Loaded {len(logs)} events from MORDOR dataset")
                    return logs
        
        except Exception as e:
            print(f"❌ Download failed: {e}")
            return []
    
    def _parse_mordor_log(self, raw_log: Dict) -> Optional[Dict]:
        """Parse MORDOR log"""
        try:
            event_data = raw_log.get('Event', {}).get('EventData', {})
            system_data = raw_log.get('Event', {}).get('System', {})
            
            event_id = system_data.get('EventID', {})
            if isinstance(event_id, dict):
                event_id = event_id.get('#text', 'Unknown')
            
            return {
                "timestamp": system_data.get('TimeCreated', {}).get('#attributes', {}).get('SystemTime', datetime.now().isoformat()),
                "event_id": str(event_id),
                "hostname": system_data.get('Computer', {}).get('#text', 'Unknown'),
                "source_ip": event_data.get('IpAddress', event_data.get('WorkstationName', 'N/A')),
                "dest_ip": event_data.get('TargetServerName', 'N/A'),
                "username": event_data.get('SubjectUserName', event_data.get('TargetUserName', 'SYSTEM')),
                "event_type": self._get_event_type(event_id),
                "raw_log": str(event_data)[:500],
                "dataset_type": "MORDOR"
            }
        except Exception as e:
            return None
    
    def _get_event_type(self, event_id):
        """Map Event ID to type"""
        event_map = {
            '4625': 'Failed Login',
            '4624': 'Successful Login',
            '4720': 'User Account Created',
            '5140': 'Network Share Access',
            '1102': 'Audit Log Cleared',
            '7045': 'Service Installation',
            '4688': 'Process Creation',
            '4663': 'Object Access'
        }
        return event_map.get(str(event_id), f'Event {event_id}')
    
    def _load_synthetic_unsw(self):
        """Generate synthetic UNSW-style data"""
        import random
        
        attack_types = ['Fuzzers', 'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Reconnaissance']
        
        logs = []
        for i in range(50):
            is_attack = random.random() > 0.3
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "dest_ip": f"192.168.1.{random.randint(1,254)}",
                "source_port": random.randint(1024, 65535),
                "dest_port": random.choice([22, 80, 443, 3389, 445]),
                "protocol": random.choice(['tcp', 'udp', 'icmp']),
                "attack_category": random.choice(attack_types) if is_attack else "Normal",
                "event_type": f"Network Traffic - {'Attack' if is_attack else 'Normal'}",
                "raw_log": "Synthetic UNSW-NB15 style data",
                "dataset_type": "UNSW-NB15 (Synthetic)"
            })
        
        print(f"✅ Generated {len(logs)} synthetic UNSW-style records")
        return logs
    
    def _load_synthetic_cicids(self):
        """Generate synthetic CICIDS data"""
        import random
        
        attack_types = ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Web Attack', 'Brute Force']
        
        logs = []
        for i in range(50):
            attack = random.choice(attack_types)
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "dest_ip": f"192.168.1.{random.randint(1,254)}",
                "attack_category": attack,
                "event_type": f"IDS Alert - {attack}",
                "raw_log": "Synthetic CICIDS2017 style data",
                "dataset_type": "CICIDS2017 (Synthetic)"
            })
        
        print(f"✅ Generated {len(logs)} synthetic CICIDS-style records")
        return logs
    
    def _load_synthetic_splunk(self):
        """Generate synthetic Splunk data"""
        import random
        
        event_types = ['login_failed', 'login_success', 'file_access', 'process_creation']
        
        logs = []
        for i in range(50):
            event = random.choice(event_types)
            logs.append({
                "timestamp": datetime.now().isoformat(),
                "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "username": random.choice(['admin', 'user', 'service_account']),
                "event_type": event.replace('_', ' ').title(),
                "raw_log": f"Splunk-style log: {event}",
                "dataset_type": "Splunk (Synthetic)"
            })
        
        print(f"✅ Generated {len(logs)} synthetic Splunk-style records")
        return logs
    
    def _load_custom_dataset(self):
        """Load custom dataset"""
        print("\n📂 CUSTOM DATASET UPLOAD\n")
        file_path = input("Enter file path (CSV or JSON): ").strip()
        
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return []
        
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
                logs = df.to_dict('records')
                print(f"✅ Loaded {len(logs)} records from CSV")
                return logs
            elif file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    logs = json.load(f)
                print(f"✅ Loaded {len(logs)} records from JSON")
                return logs
        except Exception as e:
            print(f"❌ Error: {e}")
            return []
    
    def analyze_with_ai(self, log: Dict) -> Dict:
        """Analyze with AI"""
        prompt = f"""You are a Tier-1 SOC analyst. Analyze this security event and respond with ONLY valid JSON (no markdown):

Event Data:
{json.dumps(log, indent=2)}

Respond with EXACTLY this JSON:
{{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 85,
  "threat_type": "brief category",
  "mitre_attack": "T#### - Technique Name",
  "ip_reputation": "Malicious|Suspicious|Clean|Internal",
  "analysis": "2-3 sentence analysis",
  "recommendation": "Specific action",
  "auto_escalate": true,
  "ioc_indicators": ["indicator1"]
}}"""

        try:
            if self.model_provider == "gemini":
                response = self.client.generate_content(prompt)
                response_text = response.text.strip()
            elif self.model_provider == "claude":
                message = self.client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}]
                )
                response_text = message.content[0].text.strip()
            elif self.model_provider == "openai":
                response = self.client.ChatCompletion.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1000
                )
                response_text = response.choices[0].message.content.strip()
            else:
                return self._fallback_analysis(log)
            
            response_text = response_text.replace("json", "").replace("", "").strip()
            analysis = json.loads(response_text)
            return analysis
        
        except Exception as e:
            print(f"⚠  AI Error: {e}")
            return self._fallback_analysis(log)
    
    def _fallback_analysis(self, log: Dict) -> Dict:
        """Fallback analysis"""
        return {
            "severity": "MEDIUM",
            "confidence": 50,
            "threat_type": "Requires Manual Review",
            "mitre_attack": "T1078 - Valid Accounts",
            "ip_reputation": "Unknown",
            "analysis": "AI analysis unavailable. Manual review required.",
            "recommendation": "Escalate to human analyst",
            "auto_escalate": True,
            "ioc_indicators": [log.get('source_ip', 'Unknown')]
        }
    
    def process_alerts(self, logs: List[Dict], max_alerts: int = None):
        """Process alerts"""
        if max_alerts:
            logs = logs[:max_alerts]
        
        print(f"\n{'='*70}")
        print(f"🛡  AI-SOC COPILOT - AUTOMATED ANALYSIS")
        print(f"{'='*70}\n")
        print(f"📊 Processing {len(logs)} security events...")
        print(f"🤖 AI Model: {self.model_provider.upper()}")
        print(f"📁 Dataset: {logs[0].get('dataset_type', 'Unknown') if logs else 'None'}\n")
        
        for idx, log in enumerate(logs, 1):
            event_type = log.get('event_type', 'Unknown Event')
            print(f"[{idx}/{len(logs)}] Analyzing: {event_type}")
            
            analysis = self.analyze_with_ai(log)
            
            alert = {
                "alert_id": f"SOC-{datetime.now().strftime('%Y%m%d')}-{idx:04d}",
                **log,
                **analysis,
                "status": "Escalated" if analysis['auto_escalate'] else "Reviewed",
                "analyst": f"AI-SOC Copilot ({self.model_provider.upper()})",
                "processed_at": datetime.now().isoformat()
            }
            
            self.alerts.append(alert)
            self.stats[analysis['severity']] += 1
            
            print(f"   └─ Severity: {analysis['severity']} ({analysis['confidence']}% confidence)")
            print(f"   └─ MITRE: {analysis['mitre_attack']}")
            print(f"   └─ Action: {'🚨 ESCALATED' if analysis['auto_escalate'] else '✓ Reviewed'}\n")
            
            time.sleep(1.5)
        
        return self.alerts
    
    def generate_report(self) -> str:
        """Generate report"""
        if not self.alerts:
            return "No alerts to report"
        
        report = f"""
{'='*70}
🛡  AI-SOC COPILOT - SECURITY ANALYSIS REPORT
{'='*70}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
AI Model: {self.model_provider.upper()}
Dataset: {self.alerts[0].get('dataset_type', 'Unknown')}

📊 EXECUTIVE SUMMARY
{'='*70}
Total Alerts: {len(self.alerts)}
├─ 🔴 CRITICAL: {self.stats['CRITICAL']}
├─ 🟠 HIGH: {self.stats['HIGH']}
├─ 🟡 MEDIUM: {self.stats['MEDIUM']}
└─ 🔵 LOW: {self.stats['LOW']}

🚨 TOP INCIDENTS
{'='*70}
"""
        
        critical_alerts = [a for a in self.alerts if a['severity'] in ['CRITICAL', 'HIGH']][:5]
        
        for idx, alert in enumerate(critical_alerts, 1):
            report += f"""
[{idx}] {alert['severity']} - {alert['event_type']}
    Alert ID: {alert['alert_id']}
    Timestamp: {alert['timestamp']}
    MITRE: {alert['mitre_attack']}
    Analysis: {alert['analysis']}
    Recommendation: {alert['recommendation']}
    {'─'*70}
"""
        
        report += f"""
{'='*70}
Report by AI-SOC Copilot v3.0
Luckychowdary
{'='*70}
"""
        return report
    
    def export_results(self):
        """Export results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # JSON export
        json_file = output_dir / f"soc_analysis_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({"alerts": self.alerts, "stats": self.stats}, f, indent=2)
        print(f"✅ JSON: {json_file}")
        
        # CSV export
        csv_file = output_dir / f"soc_analysis_{timestamp}.csv"
        df = pd.DataFrame(self.alerts)
        df.to_csv(csv_file, index=False)
        print(f"✅ CSV: {csv_file}")
        
        # Report export
        report_file = output_dir / f"soc_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write(self.generate_report())
        print(f"✅ Report: {report_file}")


def main():
    """Main execution"""
    # Load environment variables
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except:
        pass
    
    copilot = AISOCCopilot()
    
    copilot.display_banner()
    
    if not copilot.select_ai_model():
        print("❌ Failed to initialize AI model")
        return
    
    logs = copilot.select_dataset()
    
    if not logs:
        print("❌ No logs to process")
        return
    
    print(f"\n📊 Dataset contains {len(logs)} events")
    max_alerts = input(f"How many to analyze? (max {len(logs)}) [20]: ").strip()
    
    try:
        max_alerts = int(max_alerts) if max_alerts else 20
        max_alerts = min(max_alerts, len(logs))
    except:
        max_alerts = min(20, len(logs))
    
    try:
        copilot.process_alerts(logs, max_alerts)
        
        report = copilot.generate_report()
        print(report)
        
        print("\n📁 Exporting results...")
        copilot.export_results()
        
        print("\n✅ Analysis Complete!")
        print("📂 Check ./output/ folder for results")
    
    except KeyboardInterrupt:
        print("\n\n⚠  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if _name_ == "_main_":
    main()
