#!/usr/bin/env python3
"""
AI-SOC Agent: Single-File Security Analysis System
Complete setup, ingestion, and analysis workflow
"""

import json
import os
import sys
import requests
import zipfile
import io
from datetime import datetime
from typing import List, Dict, Optional
from dotenv import load_dotenv

# Load environment
load_dotenv()

# LangChain imports
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.vectorstores import Milvus

# LangChain imports - new versions only
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

# Pydantic imports
from pydantic import BaseModel, Field
from typing import List

# Milvus imports
from pymilvus import connections, utility, Collection


class SecurityAnalysis(BaseModel):
    """Structured security analysis output"""
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    confidence: int = Field(description="Confidence score 0-100")
    threat_type: str = Field(description="Type of threat detected")
    mitre_attack: str = Field(description="MITRE ATT&CK technique")
    ip_reputation: str = Field(description="Malicious, Suspicious, Clean, or Internal")
    analysis: str = Field(description="Detailed analysis of the incident")
    recommendation: str = Field(description="Recommended actions")
    auto_escalate: bool = Field(description="Should this be auto-escalated")
    ioc_indicators: List[str] = Field(description="IOC indicators found")


class SOCAgent:
    """Complete SOC Analysis Agent"""
    
    def __init__(self):
        self.llm = None
        self.embeddings = None
        self.vector_store = None
        self.collection_name = None
        self.ip_profiles = {}
        
    def display_banner(self):
        """Display banner"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🛡️  AI-SOC AGENT                                    ║
║              Powered by GPT-5 + LangChain + RAG                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """)
    
    def setup_openai(self):
        """Initialize OpenAI"""
        print("\n" + "="*70)
        print("🔐 OpenAI Configuration")
        print("="*70 + "\n")
        
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            api_key = input("Enter your OpenAI API Key: ").strip()
            if not api_key:
                print("❌ API key required")
                return False
        
        try:
            self.llm = ChatOpenAI(
                model=os.getenv("OPENAI_MODEL", "gpt-4o"),
                temperature=0,
                openai_api_key=api_key
            )
            
            self.embeddings = OpenAIEmbeddings(
                model="text-embedding-3-large",
                openai_api_key=api_key
            )
            
            print(f"✅ OpenAI initialized (Model: {os.getenv('OPENAI_MODEL', 'gpt-4o')})\n")
            return True
            
        except Exception as e:
            print(f"❌ OpenAI setup failed: {e}")
            return False
    
    def connect_milvus(self):
        """Connect to Milvus"""
        print("="*70)
        print("🗄️  Connecting to Milvus Vector Database")
        print("="*70 + "\n")
        
        host = os.getenv("MILVUS_HOST", "localhost")
        port = os.getenv("MILVUS_PORT", "19530")
        
        try:
            connections.connect(alias="default", host=host, port=port)
            print(f"✅ Connected to Milvus at {host}:{port}\n")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            print("   Make sure Docker is running: python setup_docker.py\n")
            return False
    
    def select_dataset(self):
        """Select and download dataset"""
        print("="*70)
        print("📊 SELECT DATASET TO INGEST")
        print("="*70 + "\n")
        
        datasets = [
            {
                "name": "MORDOR - Mimikatz Credential Dumping",
                "type": "mordor_mimikatz",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip",
                "mitre": "T1003.001",
                "description": "Mimikatz credential extraction attacks"
            },
            {
                "name": "MORDOR - Empire Invoke Mimikatz",
                "type": "mordor_empire",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys.zip",
                "mitre": "T1003",
                "description": "PowerShell Empire credential attacks"
            },
            {
                "name": "MORDOR - Remote Service Creation",
                "type": "mordor_service",
                "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_invoke_psremoting.zip",
                "mitre": "T1021.006",
                "description": "Remote service lateral movement"
            },
            {
                "name": "Synthetic - Brute Force & Failed Logins",
                "type": "synthetic_bruteforce",
                "url": None,
                "mitre": "T1110",
                "description": "Generated brute force attack patterns"
            }
        ]
        
        for idx, ds in enumerate(datasets, 1):
            print(f"{idx}. {ds['name']}")
            print(f"   MITRE: {ds['mitre']}")
            print(f"   Description: {ds['description']}")
            print()
        
        choice = input(f"Select dataset (1-{len(datasets)}): ").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(datasets):
                selected = datasets[idx]
                print(f"\n✅ Selected: {selected['name']}\n")
                
                self.collection_name = f"soc_{selected['type']}"
                
                # Download and parse
                if selected['url']:
                    events = self.download_mordor(selected['url'], selected['name'])
                else:
                    events = self.generate_synthetic_dataset(selected['type'])
                
                return events, selected['type']
            else:
                print("❌ Invalid selection")
                return None, None
        except ValueError:
            print("❌ Invalid input")
            return None, None
    
    def download_mordor(self, url: str, name: str) -> List[Dict]:
        """Download and parse MORDOR dataset"""
        print(f"📥 Downloading {name}...")
        
        try:
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                json_files = [f for f in zip_file.namelist() if f.endswith('.json')]
                
                if not json_files:
                    print("❌ No JSON files found")
                    return []
                
                with zip_file.open(json_files[0]) as json_file:
                    events = []
                    for line in json_file:
                        try:
                            raw_log = json.loads(line.decode('utf-8'))
                            parsed = self.parse_mordor_event(raw_log)
                            if parsed:
                                events.append(parsed)
                        except:
                            continue
                    
                    print(f"✅ Loaded {len(events)} events\n")
                    return events
        
        except Exception as e:
            print(f"❌ Download failed: {e}")
            return []
    
    def parse_mordor_event(self, raw_log: Dict) -> Optional[Dict]:
        """Parse MORDOR event"""
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
                "event_type": self.get_event_type(event_id),
                "raw_log": str(event_data)[:500]
            }
        except:
            return None
    
    def get_event_type(self, event_id):
        """Map Event ID to type"""
        event_map = {
            '4625': 'Failed Login', '4624': 'Successful Login',
            '4720': 'User Account Created', '5140': 'Network Share Access',
            '1102': 'Audit Log Cleared', '7045': 'Service Installation',
            '4688': 'Process Creation', '4663': 'Object Access',
            '4672': 'Special Privileges Assigned', '4698': 'Scheduled Task Created',
            '10': 'Process Access (Mimikatz)', '1': 'Process Creation (Sysmon)'
        }
        return event_map.get(str(event_id), f'Event {event_id}')
    
    def generate_synthetic_dataset(self, dataset_type: str) -> List[Dict]:
        """Generate synthetic security dataset"""
        import random
        
        print("🎲 Generating synthetic security dataset...")
        
        events = []
        
        # Suspicious IPs with history
        attacker_ips = [
            "203.0.113.50", "198.51.100.25", "192.0.2.100",
            "185.220.101.40", "45.142.120.50"
        ]
        
        internal_ips = [
            "10.0.0.5", "10.0.0.10", "10.0.0.15",
            "192.168.1.100", "192.168.1.150"
        ]
        
        usernames = ["admin", "administrator", "root", "user", "service_account", "john.doe", "jane.smith"]
        
        # Generate 200 events with realistic patterns
        for i in range(200):
            # Simulate brute force attack pattern
            if i < 80:  # First 80 events: brute force from external IP
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": "4625",
                    "event_type": "Failed Login",
                    "source_ip": random.choice(attacker_ips),
                    "dest_ip": random.choice(internal_ips),
                    "username": random.choice(["admin", "administrator", "root"]),
                    "hostname": f"DC-{random.randint(1,3)}",
                    "raw_log": f"Failed login attempt {i+1} from suspicious IP"
                }
            
            # Successful compromise
            elif i < 85:
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": "4624",
                    "event_type": "Successful Login",
                    "source_ip": attacker_ips[0],
                    "dest_ip": internal_ips[0],
                    "username": "admin",
                    "hostname": "DC-1",
                    "raw_log": "Successful login after brute force"
                }
            
            # Lateral movement
            elif i < 100:
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": random.choice(["4672", "5140", "4688"]),
                    "event_type": random.choice(["Special Privileges", "Share Access", "Process Creation"]),
                    "source_ip": internal_ips[0],
                    "dest_ip": random.choice(internal_ips[1:]),
                    "username": "admin",
                    "hostname": f"SRV-{random.randint(1,5)}",
                    "raw_log": "Lateral movement activity detected"
                }
            
            # Credential dumping
            elif i < 120:
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": "10",
                    "event_type": "Process Access (Mimikatz)",
                    "source_ip": internal_ips[0],
                    "dest_ip": internal_ips[0],
                    "username": "admin",
                    "hostname": "DC-1",
                    "raw_log": "LSASS.exe memory access detected - possible credential dumping"
                }
            
            # Normal traffic mixed in
            else:
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "event_id": random.choice(["4624", "4688", "4663"]),
                    "event_type": random.choice(["Successful Login", "Process Creation", "Object Access"]),
                    "source_ip": random.choice(internal_ips),
                    "dest_ip": random.choice(internal_ips),
                    "username": random.choice(usernames),
                    "hostname": f"WS-{random.randint(1,10)}",
                    "raw_log": "Normal user activity"
                }
            
            events.append(event)
        
        print(f"✅ Generated {len(events)} synthetic events")
        print(f"   Pattern: Brute force → Compromise → Lateral Movement → Credential Dumping\n")
        
        return events
    
    def check_existing_collection(self, collection_name: str) -> bool:
        """Check if collection exists and has data"""
        if utility.has_collection(collection_name):
            col = Collection(collection_name)
            col.load()
            count = col.num_entities
            
            if count > 0:
                print("="*70)
                print(f"📚 Existing Knowledge Base Found")
                print("="*70 + "\n")
                print(f"   Collection: {collection_name}")
                print(f"   Vectors: {count}")
                
                choice = input(f"\n   Use existing knowledge base? (y/n): ").strip().lower()
                
                if choice == 'y':
                    self.vector_store = Milvus(
                        embedding_function=self.embeddings,
                        collection_name=collection_name,
                        connection_args={"host": "localhost", "port": "19530"}
                    )
                    print(f"   ✓ Using existing collection\n")
                    return True
                else:
                    print(f"   Dropping old collection...\n")
                    utility.drop_collection(collection_name)
        
        return False
    
    def ingest_dataset(self, events: List[Dict], dataset_type: str):
        """Ingest dataset into Milvus with smart sampling"""
        print("="*70)
        print(f"📥 INGESTING DATASET: {dataset_type.upper()}")
        print("="*70 + "\n")
        
        # Check for existing collection
        if self.check_existing_collection(self.collection_name):
            return True
        
        # Smart sampling for large datasets
        max_events = 500  # Reasonable limit
        if len(events) > max_events:
            print(f"⚠️  Dataset has {len(events)} events (very large!)")
            print(f"   Sampling {max_events} representative events to save time & cost\n")
            
            # Sample strategically: mix of beginning, middle, end
            sample_size = max_events // 3
            sampled = (
                events[:sample_size] +  # Beginning
                events[len(events)//2 - sample_size//2:len(events)//2 + sample_size//2] +  # Middle
                events[-sample_size:]  # End
            )
            events = sampled[:max_events]
        
        print(f"🧠 Processing {len(events)} events...")
        print(f"   Chunking, embedding, and storing in Milvus...")
        print(f"   Collection: {self.collection_name}\n")
        
        # Prepare documents
        documents = []
        for idx, event in enumerate(events):
            text = self.prepare_event_text(event)
            
            metadata = {
                "event_id": str(event.get("event_id", f"EVT-{idx}")),
                "timestamp": event.get("timestamp", ""),
                "event_type": event.get("event_type", "Unknown"),
                "source_ip": event.get("source_ip", "N/A"),
                "dest_ip": event.get("dest_ip", "N/A"),
                "username": event.get("username", "N/A"),
                "hostname": event.get("hostname", "N/A")
            }
            
            documents.append(Document(page_content=text, metadata=metadata))
        
        # Split into chunks
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=512,
            chunk_overlap=50,
            length_function=len
        )
        
        split_docs = text_splitter.split_documents(documents)
        print(f"   Created {len(split_docs)} chunks from {len(documents)} events")
        
        # Insert into Milvus
        try:
            batch_size = 100
            for i in range(0, len(split_docs), batch_size):
                batch = split_docs[i:i + batch_size]
                
                if self.vector_store is None:
                    self.vector_store = Milvus.from_documents(
                        batch,
                        embedding=self.embeddings,
                        collection_name=self.collection_name,
                        connection_args={"host": "localhost", "port": "19530"}
                    )
                else:
                    self.vector_store.add_documents(batch)
                
                print(f"   ✓ Batch {i//batch_size + 1}: {len(batch)} chunks")
            
            # Build IP profiles
            print(f"\n🔍 Building IP behavior profiles...")
            self.build_ip_profiles(events)
            
            print(f"\n✅ Dataset ingestion complete!")
            print(f"   Total vectors: {len(split_docs)}")
            print(f"   IP profiles: {len(self.ip_profiles)}\n")
            
            return True
            
        except Exception as e:
            print(f"❌ Ingestion failed: {e}")
            return False
    
    def prepare_event_text(self, event: Dict) -> str:
        """Convert event to text"""
        parts = [
            f"Event Type: {event.get('event_type', 'Unknown')}",
            f"Timestamp: {event.get('timestamp', '')}",
            f"Source IP: {event.get('source_ip', 'N/A')}",
            f"Destination IP: {event.get('dest_ip', 'N/A')}",
            f"Username: {event.get('username', 'N/A')}",
            f"Hostname: {event.get('hostname', 'N/A')}",
            f"Event ID: {event.get('event_id', 'N/A')}",
            f"Details: {event.get('raw_log', '')}"
        ]
        return "\n".join(parts)
    
    def build_ip_profiles(self, events: List[Dict]):
        """Build IP behavior profiles"""
        from collections import defaultdict
        
        ip_events = defaultdict(list)
        
        for event in events:
            source_ip = event.get('source_ip', 'N/A')
            if source_ip and source_ip != 'N/A':
                ip_events[source_ip].append(event)
        
        for ip, ip_event_list in ip_events.items():
            profile = {
                'ip': ip,
                'total_events': len(ip_event_list),
                'event_types': {},
                'usernames': set(),
                'first_seen': None,
                'last_seen': None
            }
            
            for event in ip_event_list:
                event_type = event.get('event_type', 'Unknown')
                profile['event_types'][event_type] = profile['event_types'].get(event_type, 0) + 1
                
                username = event.get('username', 'N/A')
                if username != 'N/A':
                    profile['usernames'].add(username)
                
                timestamp = event.get('timestamp', '')
                if timestamp:
                    if not profile['first_seen'] or timestamp < profile['first_seen']:
                        profile['first_seen'] = timestamp
                    if not profile['last_seen'] or timestamp > profile['last_seen']:
                        profile['last_seen'] = timestamp
            
            profile['usernames'] = list(profile['usernames'])
            self.ip_profiles[ip] = profile
        
        print(f"   ✓ Profiled {len(self.ip_profiles)} unique IPs")
    
    def get_ip_context(self, ip: str) -> str:
        """Get IP behavioral context"""
        if ip not in self.ip_profiles:
            return ""
        
        profile = self.ip_profiles[ip]
        
        context = f"\nIP PROFILE: {ip}\n"
        context += f"Total Events: {profile['total_events']}\n"
        context += f"First Seen: {profile['first_seen']}\n"
        context += f"Last Seen: {profile['last_seen']}\n"
        context += f"Event Types:\n"
        
        for event_type, count in sorted(profile['event_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
            context += f"  - {event_type}: {count}x\n"
        
        if profile['usernames']:
            context += f"Usernames: {', '.join(profile['usernames'][:5])}\n"
        
        return context
    
    def analyze_incident(self, incident: Dict) -> Dict:
        """Analyze security incident with RAG"""
        print("\n" + "="*70)
        print("🔍 ANALYZING INCIDENT")
        print("="*70 + "\n")
        
        # Prepare query
        query = self.prepare_event_text(incident)
        
        # Get similar events
        print("   📚 Retrieving similar historical events...")
        similar_events = self.vector_store.similarity_search_with_score(query, k=5)
        
        # Build context
        context = "HISTORICAL CONTEXT:\n\n"
        
        # Add IP profiles
        source_ip = incident.get('source_ip')
        if source_ip:
            ip_ctx = self.get_ip_context(source_ip)
            if ip_ctx:
                context += ip_ctx + "\n"
        
        # Add similar events
        context += "\nSIMILAR PAST INCIDENTS:\n"
        for idx, (doc, score) in enumerate(similar_events, 1):
            similarity = (1 - score) * 100
            context += f"\n[{idx}] Similarity: {similarity:.1f}%\n"
            context += f"{doc.page_content[:300]}...\n"
            context += f"Metadata: {doc.metadata}\n"
        
        # Create analysis prompt
        parser = PydanticOutputParser(pydantic_object=SecurityAnalysis)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert SOC analyst with deep knowledge of:
- MITRE ATT&CK framework
- Threat intelligence and IOC analysis
- Incident response procedures
- Risk assessment and triage

Analyze incidents with precision and provide actionable recommendations."""),
            ("user", """Using the historical context below, analyze this security incident:

{context}

CURRENT INCIDENT:
{incident}

{format_instructions}""")
        ])
        
        # Build chain
        chain = prompt | self.llm | parser
        
        print("   🤖 Analyzing with GPT-5...")
        
        try:
            result = chain.invoke({
                "context": context,
                "incident": query,
                "format_instructions": parser.get_format_instructions()
            })
            
            return result.dict()
            
        except Exception as e:
            print(f"   ⚠️  Analysis error: {e}")
            return {
                "severity": "MEDIUM",
                "confidence": 50,
                "threat_type": "Requires Manual Review",
                "mitre_attack": "Unknown",
                "ip_reputation": "Unknown",
                "analysis": f"Automated analysis failed: {e}",
                "recommendation": "Manual investigation required",
                "auto_escalate": True,
                "ioc_indicators": []
            }
    
    def display_analysis(self, analysis: Dict, incident: Dict):
        """Display analysis results"""
        print("\n" + "="*70)
        print("📊 ANALYSIS RESULTS")
        print("="*70 + "\n")
        
        # Severity with color
        severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵"
        }
        
        icon = severity_icons.get(analysis['severity'], "⚪")
        
        print(f"{icon} Severity: {analysis['severity']}")
        print(f"📈 Confidence: {analysis['confidence']}%")
        print(f"⚔️  Threat Type: {analysis['threat_type']}")
        print(f"🎯 MITRE ATT&CK: {analysis['mitre_attack']}")
        print(f"🌐 IP Reputation: {analysis['ip_reputation']}")
        
        print(f"\n📝 Analysis:")
        print(f"   {analysis['analysis']}")
        
        print(f"\n💡 Recommendation:")
        print(f"   {analysis['recommendation']}")
        
        if analysis['ioc_indicators']:
            print(f"\n🚨 IOC Indicators:")
            for ioc in analysis['ioc_indicators']:
                print(f"   - {ioc}")
        
        if analysis['auto_escalate']:
            print(f"\n⚠️  AUTO-ESCALATE: YES")
        else:
            print(f"\n✓ AUTO-ESCALATE: NO")
        
        print()
    
    def incident_analysis_loop(self):
        """Loop for analyzing incidents"""
        print("="*70)
        print("🎯 INCIDENT ANALYSIS MODE")
        print("="*70 + "\n")
        print("Enter incident details (or 'quit' to exit)\n")
        
        while True:
            print("-" * 70)
            
            # Get incident details
            print("\nEnter incident information:")
            event_type = input("  Event Type (e.g., Failed Login): ").strip()
            
            if event_type.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Exiting analysis mode\n")
                break
            
            source_ip = input("  Source IP: ").strip()
            dest_ip = input("  Destination IP (optional): ").strip()
            username = input("  Username (optional): ").strip()
            details = input("  Additional Details (optional): ").strip()
            
            # Build incident
            incident = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type or "Unknown Event",
                "source_ip": source_ip or "N/A",
                "dest_ip": dest_ip or "N/A",
                "username": username or "N/A",
                "raw_log": details or "No additional details"
            }
            
            # Analyze
            analysis = self.analyze_incident(incident)
            
            # Display
            self.display_analysis(analysis, incident)
            
            # Save option
            save = input("Save this analysis? (y/n): ").strip().lower()
            if save == 'y':
                self.save_analysis(incident, analysis)
    
    def save_analysis(self, incident: Dict, analysis: Dict):
        """Save analysis to file"""
        os.makedirs("output", exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"output/incident_analysis_{timestamp}.json"
        
        data = {
            "incident": incident,
            "analysis": analysis,
            "analyzed_at": datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"   ✅ Saved to: {filename}\n")
    
    def run(self):
        """Main execution"""
        self.display_banner()
        
        # Step 1: Setup OpenAI
        if not self.setup_openai():
            return
        
        # Step 2: Connect to Milvus
        if not self.connect_milvus():
            return
        
        # Step 3: Select dataset
        events, dataset_type = self.select_dataset()
        if not events:
            return
        
        # Step 4: Ingest dataset
        if not self.ingest_dataset(events, dataset_type):
            return
        
        print("="*70)
        print("✅ SETUP COMPLETE - Ready for Incident Analysis")
        print("="*70 + "\n")
        
        # Step 5: Analyze incidents
        self.incident_analysis_loop()
        
        # Cleanup
        connections.disconnect(alias="default")
        print("✅ Session complete\n")


def main():
    """Entry point"""
    try:
        agent = SOCAgent()
        agent.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()



