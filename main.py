
#!/usr/bin/env python3
"""
AI-SOC Copilot v3.0: RAG-Enhanced Security Analysis System
Powered by: OpenAI GPT-4o + LangChain + Milvus
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

# RAG Module
from rag_module import RAGManager

class AISOCCopilot:
    """Main SOC Analysis System"""
    
    def __init__(self):
        self.model_provider = "openai"  # Fixed to OpenAI only
        self.client = None
        self.api_key = None
        self.alerts = []
        self.stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "dismissed": 0}
        self.rag_manager = None
        self.use_rag = False
        self.current_dataset_type = None
    
    def display_banner(self):
        """Display welcome banner"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🛡  AI-SOC COPILOT v3.0                             ║
║              Intelligent Security Operations Center              ║
║                                                                  ║
║         OpenAI + LangChain + RAG | Production Ready              ║
║              Developer: Luckychowdary                            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """)
    
    def select_ai_model(self):
        """Initialize OpenAI model"""
        print("\n" + "="*70)
        print("🤖 AI MODEL CONFIGURATION")
        print("="*70 + "\n")
        
        # Check for OpenAI API key
        openai_key = os.getenv("OPENAI_API_KEY")
        
        if not openai_key:
            print("⚠️  No OpenAI API key found in environment")
            openai_key = input("\nEnter your OpenAI API Key: ").strip()
            
            if not openai_key:
                print("❌ No API key provided")
                return False
            
            # Save to environment for this session
            os.environ["OPENAI_API_KEY"] = openai_key
        
        self.api_key = openai_key
        self.model_provider = "openai"
        
        # Display configuration
        print(f"\n✅ OpenAI Configuration:")
        print(f"   API Key: {openai_key[:15]}...{openai_key[-5:]}")
        print(f"   Model: {os.getenv('OPENAI_MODEL', 'gpt-4o')}")
        print(f"   Embedding: {os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-large')}\n")
        
        return self._initialize_client()
    
    
    def _initialize_client(self):
        """Initialize LangChain OpenAI client"""
        try:
            from langchain_openai import ChatOpenAI
            self.client = ChatOpenAI(
                model=os.getenv("OPENAI_MODEL", "gpt-4o"),
                temperature=0,
                openai_api_key=self.api_key
            )
            print("✅ LangChain OpenAI client initialized")
            return True
        except ImportError:
            print("❌ Missing LangChain library. Install with: pip install langchain-openai")
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
                
                # Store dataset type for collection naming
                self.current_dataset_type = selected['type']
                
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
    
    def initialize_rag(self, dataset_type: str) -> bool:
        """Initialize RAG with Milvus using dataset-specific collection"""
        print("\n" + "="*70)
        print("🧠 RAG (Retrieval-Augmented Generation) Setup")
        print("="*70 + "\n")
        
        use_rag = input("Enable RAG for enhanced context-aware analysis? (y/n): ").strip().lower()
        
        if use_rag != 'y':
            print("⏭️  Skipping RAG setup - using standard analysis\n")
            return False
        
        milvus_host = os.getenv("MILVUS_HOST", "localhost")
        milvus_port = os.getenv("MILVUS_PORT", "19530")
        
        # Create dataset-specific collection name
        collection_name = f"soc_{dataset_type}_events"
        
        print(f"📦 Using collection: {collection_name}")
        print(f"   (Each dataset has its own isolated knowledge base)")
        
        try:
            self.rag_manager = RAGManager(
                milvus_host=milvus_host,
                milvus_port=milvus_port,
                collection_name=collection_name
            )
            
            if not self.rag_manager.connect():
                print("⚠️  Failed to connect to Milvus. Make sure Docker containers are running.")
                print("   Run: python setup_docker.py")
                return False
            
            if not self.rag_manager.initialize_vector_store():
                return False
            
            self.use_rag = True
            print(f"✅ RAG enabled for {dataset_type.upper()} dataset\n")
            return True
            
        except Exception as e:
            print(f"❌ RAG initialization failed: {e}")
            print("   Continuing with standard analysis\n")
            return False
    
    def analyze_with_ai(self, log: Dict) -> Dict:
        """Analyze with AI using LangChain (with optional RAG context)"""
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import PydanticOutputParser
        from pydantic import BaseModel, Field
        from typing import List
        
        # Define output schema
        class SecurityAnalysis(BaseModel):
            severity: str = Field(description="Severity level: CRITICAL, HIGH, MEDIUM, or LOW")
            confidence: int = Field(description="Confidence score 0-100")
            threat_type: str = Field(description="Brief threat category")
            mitre_attack: str = Field(description="MITRE ATT&CK technique (e.g., T1110 - Brute Force)")
            ip_reputation: str = Field(description="IP reputation: Malicious, Suspicious, Clean, or Internal")
            analysis: str = Field(description="2-3 sentence analysis")
            recommendation: str = Field(description="Specific action to take")
            auto_escalate: bool = Field(description="Whether to auto-escalate this alert")
            ioc_indicators: List[str] = Field(description="List of IOC indicators")
        
        # Get RAG context with IP profiling if enabled
        rag_context = ""
        if self.use_rag and self.rag_manager:
            try:
                query = self.rag_manager.prepare_event_text(log)
                source_ip = log.get('source_ip')
                dest_ip = log.get('dest_ip')
                
                # Get context including IP behavioral profiles
                rag_context = self.rag_manager.get_augmented_context(
                    query, 
                    top_k=3,
                    include_ip_profile=True,
                    source_ip=source_ip,
                    dest_ip=dest_ip
                )
            except Exception as e:
                print(f"⚠️  RAG context retrieval failed: {e}")
                rag_context = ""
        
        # Create output parser
        parser = PydanticOutputParser(pydantic_object=SecurityAnalysis)
        
        # Create prompt template
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", "You are a Tier-1 SOC analyst specialized in threat detection and analysis."),
            ("user", """Analyze this security event and provide a structured assessment.

{rag_context}

CURRENT EVENT TO ANALYZE:
{event_data}

{format_instructions}""")
        ])
        
        # Build the chain
        chain = prompt_template | self.client | parser
        
        try:
            # Invoke the chain
            result = chain.invoke({
                "rag_context": rag_context if rag_context else "No historical context available.",
                "event_data": json.dumps(log, indent=2),
                "format_instructions": parser.get_format_instructions()
            })
            
            # Convert Pydantic model to dict
            return result.dict()
        
        except Exception as e:
            print(f"⚠  LangChain Error: {e}")
            # Try simple fallback without structured output
            try:
                from langchain_core.messages import HumanMessage
                
                simple_prompt = f"""You are a SOC analyst. Analyze this security event and respond with ONLY valid JSON:

{rag_context if rag_context else ""}

EVENT: {json.dumps(log, indent=2)}

Respond with this exact JSON structure:
{{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 85, "threat_type": "brief category", "mitre_attack": "T#### - Technique", "ip_reputation": "Malicious|Suspicious|Clean|Internal", "analysis": "brief analysis", "recommendation": "action", "auto_escalate": true, "ioc_indicators": ["indicator1"]}}"""
                
                response = self.client.invoke([HumanMessage(content=simple_prompt)])
                response_text = response.content.strip()
                
                # Clean and parse
                response_text = response_text.replace("```json", "").replace("```", "").strip()
                return json.loads(response_text)
                
            except Exception as e2:
                print(f"⚠  Fallback also failed: {e2}")
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
    
    # Initialize OpenAI
    if not copilot.select_ai_model():
        print("❌ Failed to initialize AI model")
        return
    
    # Select dataset
    logs = copilot.select_dataset()
    
    if not logs:
        print("❌ No logs to process")
        return
    
    print(f"\n📊 Dataset contains {len(logs)} events")
    print(f"📁 Dataset type: {copilot.current_dataset_type.upper()}")
    
    # Initialize RAG with dataset-specific collection
    rag_initialized = copilot.initialize_rag(copilot.current_dataset_type)
    
    # If RAG is enabled, check if we need to ingest data
    if rag_initialized and copilot.use_rag and copilot.rag_manager:
        # Check if collection is already populated
        stats = copilot.rag_manager.get_collection_stats()
        existing_count = stats.get('num_entities', 0)
        
        if existing_count > 0:
            print("\n" + "="*70)
            print(f"📚 Existing Knowledge Base Found")
            print("="*70)
            print(f"\n   Collection already contains {existing_count} vectors")
            print(f"   Dataset: {copilot.current_dataset_type.upper()}")
            
            reingest = input(f"\n   Re-ingest dataset? This will REPLACE existing data (y/n): ").strip().lower()
            
            if reingest == 'y':
                print(f"\n   Dropping existing collection...")
                copilot.rag_manager.drop_collection()
                copilot.rag_manager.initialize_vector_store()
                should_ingest = True
            else:
                print(f"\n   ✓ Using existing knowledge base")
                should_ingest = False
        else:
            should_ingest = True
        
        # Ingest data if needed
        if should_ingest:
            print("\n" + "="*70)
            print(f"📥 Building Knowledge Base for {copilot.current_dataset_type.upper()}")
            print("="*70)
            
            print(f"\n🧠 Ingesting ENTIRE dataset ({len(logs)} events) into Milvus...")
            print("   This builds IP-based patterns and behavioral profiles")
            print("   Processing in batches for optimal performance...\n")
            
            try:
                # Ingest ALL events for comprehensive learning
                copilot.rag_manager.insert_events(logs, batch_size=100)
                
                # Show stats
                stats = copilot.rag_manager.get_collection_stats()
                print(f"\n📈 Knowledge Base Stats:")
                print(f"   Collection: {stats.get('collection_name', 'N/A')}")
                print(f"   Total Vectors: {stats.get('num_entities', 0)}")
                print(f"   Source Events: {len(logs)}")
                print(f"   Status: {stats.get('status', 'unknown')}")
                
                # Build IP profile index
                print(f"\n🔍 Building IP behavior profiles...")
                copilot.rag_manager.build_ip_profiles(logs)
                
            except Exception as e:
                print(f"⚠️  Knowledge base indexing failed: {e}")
                print("   Continuing with standard analysis...")
        else:
            # Still build IP profiles from current data
            try:
                print(f"\n🔍 Building IP behavior profiles from current dataset...")
                copilot.rag_manager.build_ip_profiles(logs)
            except Exception as e:
                print(f"⚠️  IP profiling failed: {e}")
    
    # Process alerts
    max_alerts = input(f"\nHow many events to analyze? (max {len(logs)}) [20]: ").strip()
    
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
        
        # Cleanup
        if copilot.rag_manager:
            copilot.rag_manager.disconnect()
    
    except KeyboardInterrupt:
        print("\n\n⚠  Interrupted by user")
        if copilot.rag_manager:
            copilot.rag_manager.disconnect()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        if copilot.rag_manager:
            copilot.rag_manager.disconnect()


if __name__ == "__main__":
    main()
