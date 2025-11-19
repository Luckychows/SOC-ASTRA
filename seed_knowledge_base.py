#!/usr/bin/env python3
"""
Synthetic Security Event Generator for Knowledge Base Pre-Seeding
Generates realistic security events based on provided IPs
"""

import os
import sys
import yaml
import random
from datetime import datetime, timedelta
from typing import List, Dict
from pathlib import Path

# Import event templates
from event_templates import (
    BruteForceTemplate,
    LateralMovementTemplate,
    CredentialDumpingTemplate,
    ReconnaissanceTemplate,
    ExfiltrationTemplate,
    NormalActivityTemplate,
    MalwareTemplate
)


class SyntheticEventGenerator:
    """Generate realistic synthetic security events"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.internal_ips = config.get('internal_ips', [])
        self.external_ips = config.get('external_ips', [])
        self.suspicious_ips = config.get('suspicious_internal_ips', [])
        self.event_config = config.get('event_generation', {})
        self.events = []
    
    def generate_all_events(self) -> List[Dict]:
        """Generate events for all IPs"""
        print("\n" + "="*70)
        print("🧬 SYNTHETIC EVENT GENERATION")
        print("="*70 + "\n")
        
        print(f"📊 Configuration:")
        print(f"   Internal IPs: {len(self.internal_ips)}")
        print(f"   External IPs: {len(self.external_ips)}")
        print(f"   Suspicious IPs: {len(self.suspicious_ips)}")
        
        events_per_ip = self.event_config.get('events_per_ip', '50-200')
        if '-' in str(events_per_ip):
            min_events, max_events = map(int, events_per_ip.split('-'))
        else:
            min_events = max_events = int(events_per_ip)
        
        print(f"   Events per IP: {min_events}-{max_events}")
        print(f"   Time span: {self.event_config.get('time_span_days', 30)} days\n")
        
        # Generate attack scenarios from external IPs
        for ext_ip in self.external_ips:
            print(f"🎯 Generating attack scenarios for {ext_ip} (External)...")
            events = self._generate_attack_scenario(ext_ip, min_events, max_events)
            self.events.extend(events)
            print(f"   ✓ Generated {len(events)} events\n")
        
        # Generate suspicious activity from suspicious internal IPs
        for sus_ip in self.suspicious_ips:
            print(f"⚠️  Generating suspicious activity for {sus_ip} (Compromised)...")
            events = self._generate_compromised_host_activity(sus_ip, min_events, max_events)
            self.events.extend(events)
            print(f"   ✓ Generated {len(events)} events\n")
        
        # Generate normal activity from internal IPs
        for int_ip in self.internal_ips:
            print(f"✅ Generating normal activity for {int_ip} (Internal)...")
            events = self._generate_normal_activity(int_ip, min_events//2, max_events//2)
            self.events.extend(events)
            print(f"   ✓ Generated {len(events)} events\n")
        
        # Sort by timestamp
        self.events.sort(key=lambda x: x.get('timestamp', ''))
        
        print(f"✅ Total events generated: {len(self.events)}")
        self._print_statistics()
        
        return self.events
    
    def _generate_attack_scenario(self, attacker_ip: str, min_events: int, max_events: int) -> List[Dict]:
        """Generate complete attack scenario from external attacker"""
        events = []
        num_events = random.randint(min_events, max_events)
        
        scenarios = self.event_config.get('attack_scenarios', [
            'brute_force', 'lateral_movement', 'reconnaissance'
        ])
        
        # Pick random internal targets
        targets = random.sample(self.internal_ips, min(3, len(self.internal_ips))) if self.internal_ips else ["10.0.0.1"]
        
        # Phase 1: Reconnaissance (10-20% of events)
        recon_count = int(num_events * 0.15)
        if 'reconnaissance' in scenarios:
            for _ in range(recon_count):
                target = random.choice(targets)
                events.append(ReconnaissanceTemplate.port_scan(attacker_ip, target))
        
        # Phase 2: Brute Force (40-60% of events)
        brute_force_count = int(num_events * 0.5)
        if 'brute_force' in scenarios:
            target = targets[0]  # Focus on one target
            for _ in range(brute_force_count - 1):
                events.append(BruteForceTemplate.failed_login(attacker_ip, target))
            # One successful login
            events.append(BruteForceTemplate.successful_login_after_brute_force(attacker_ip, target))
        
        # Phase 3: Post-compromise activity (remaining events)
        remaining = num_events - recon_count - brute_force_count
        if remaining > 0:
            if 'lateral_movement' in scenarios:
                for _ in range(remaining // 2):
                    target = random.choice(targets)
                    events.append(LateralMovementTemplate.network_share_access(attacker_ip, target))
            
            if 'data_exfiltration' in scenarios:
                for _ in range(remaining // 2):
                    events.append(ExfiltrationTemplate.large_data_transfer(attacker_ip, attacker_ip))
        
        return events
    
    def _generate_compromised_host_activity(self, compromised_ip: str, min_events: int, max_events: int) -> List[Dict]:
        """Generate activity from compromised internal host"""
        events = []
        num_events = random.randint(min_events, max_events)
        
        # Credential dumping
        cred_dump_count = int(num_events * 0.2)
        for _ in range(cred_dump_count):
            events.append(CredentialDumpingTemplate.lsass_access(compromised_ip))
        
        # Lateral movement to other internal hosts
        lateral_count = int(num_events * 0.3)
        if self.internal_ips:
            targets = [ip for ip in self.internal_ips if ip != compromised_ip]
            for _ in range(lateral_count):
                if targets:
                    target = random.choice(targets)
                    event_type = random.choice([
                        LateralMovementTemplate.psexec_execution,
                        LateralMovementTemplate.rdp_connection,
                        LateralMovementTemplate.network_share_access
                    ])
                    events.append(event_type(compromised_ip, target))
        
        # Malware/suspicious processes
        malware_count = int(num_events * 0.2)
        for _ in range(malware_count):
            events.append(MalwareTemplate.suspicious_process(compromised_ip))
        
        # Exfiltration
        exfil_count = int(num_events * 0.15)
        external_target = random.choice(self.external_ips) if self.external_ips else "185.220.101.40"
        for _ in range(exfil_count):
            events.append(ExfiltrationTemplate.large_data_transfer(compromised_ip, external_target))
        
        # Normal activity to blend in
        normal_count = num_events - cred_dump_count - lateral_count - malware_count - exfil_count
        for _ in range(normal_count):
            events.append(NormalActivityTemplate.process_creation(compromised_ip))
        
        return events
    
    def _generate_normal_activity(self, internal_ip: str, min_events: int, max_events: int) -> List[Dict]:
        """Generate normal baseline activity from internal host"""
        events = []
        num_events = random.randint(min_events, max_events)
        
        for _ in range(num_events):
            event_type = random.choice([
                NormalActivityTemplate.normal_login,
                NormalActivityTemplate.file_access,
                NormalActivityTemplate.process_creation
            ])
            
            if event_type == NormalActivityTemplate.normal_login:
                target = random.choice(self.internal_ips) if self.internal_ips else internal_ip
                events.append(event_type(internal_ip, target))
            else:
                events.append(event_type(internal_ip))
        
        return events
    
    def _print_statistics(self):
        """Print generation statistics"""
        print("\n📈 Event Statistics:")
        
        # Count by severity
        severity_counts = {}
        for event in self.events:
            severity = event.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"   {severity}: {count}")
        
        # Count unique MITRE techniques
        mitre_techniques = set()
        for event in self.events:
            mitre = event.get('mitre_attack', '')
            if mitre and mitre != 'N/A':
                mitre_techniques.add(mitre)
        
        print(f"\n🎯 Unique MITRE ATT&CK Techniques: {len(mitre_techniques)}")


def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file"""
    if not os.path.exists(config_path):
        print(f"❌ Configuration file not found: {config_path}")
        print(f"   Creating example configuration...")
        create_example_config()
        return None
    
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def create_example_config():
    """Create example configuration file"""
    example_config = """# Seed IPs Configuration for SOC-ASTRA Knowledge Base

internal_ips:
  - 10.0.1.10      # Domain Controller
  - 10.0.1.20      # File Server
  - 10.0.1.30      # Web Server
  - 192.168.1.50   # Workstation
  - 192.168.1.51   # Admin Workstation

external_ips:
  - 203.0.113.50   # Known attacker IP
  - 198.51.100.25  # Suspicious IP
  - 185.220.101.40 # Tor exit node
  - 45.142.120.50  # Botnet C2

suspicious_internal_ips:
  - 10.0.1.99      # Potentially compromised host

event_generation:
  events_per_ip: 50-200     # Random range per IP
  time_span_days: 30        # Spread events over 30 days
  attack_scenarios:
    - brute_force
    - lateral_movement
    - data_exfiltration
    - privilege_escalation
    - reconnaissance
    - malware_execution
"""
    
    with open('seed_ips.example.yaml', 'w') as f:
        f.write(example_config)
    
    print(f"✅ Created seed_ips.example.yaml")
    print(f"   Copy it to seed_ips.yaml and customize with your IPs")


def ingest_to_milvus(events: List[Dict]):
    """Ingest generated events into Milvus"""
    from rag_module import RAGManager
    
    print("\n" + "="*70)
    print("📥 INGESTING INTO MILVUS")
    print("="*70 + "\n")
    
    # Initialize RAG Manager
    rag_manager = RAGManager(
        milvus_host=os.getenv("MILVUS_HOST", "localhost"),
        milvus_port=os.getenv("MILVUS_PORT", "19530"),
        collection_name=os.getenv("KNOWLEDGE_BASE_COLLECTION", "soc_knowledge_base")
    )
    
    # Connect
    if not rag_manager.connect():
        print("❌ Failed to connect to Milvus")
        print("   Make sure Docker containers are running: python setup_docker.py")
        return False
    
    # Initialize vector store
    if not rag_manager.initialize_vector_store():
        print("❌ Failed to initialize vector store")
        return False
    
    # Insert events
    print(f"📤 Inserting {len(events)} events...")
    inserted = rag_manager.insert_events(events, batch_size=100)
    
    if inserted > 0:
        print(f"\n🔍 Building IP behavior profiles...")
        rag_manager.build_ip_profiles(events)
        
        # Show stats
        stats = rag_manager.get_collection_stats()
        print(f"\n✅ Knowledge Base Ready!")
        print(f"   Collection: {stats.get('collection_name', 'N/A')}")
        print(f"   Total Vectors: {stats.get('num_entities', 0)}")
        print(f"   Status: {stats.get('status', 'unknown')}")
        
        rag_manager.disconnect()
        return True
    else:
        print("❌ No events were inserted")
        rag_manager.disconnect()
        return False


def main():
    """Main execution"""
    # Load environment
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except:
        pass
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║           🧬 SYNTHETIC EVENT GENERATOR                           ║
║           SOC-ASTRA Knowledge Base Pre-Seeding                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Load configuration
    config_path = os.getenv("SEED_CONFIG_PATH", "seed_ips.yaml")
    config = load_config(config_path)
    
    if not config:
        print("\n⚠️  Please create seed_ips.yaml and run again")
        return
    
    # Generate events
    generator = SyntheticEventGenerator(config)
    events = generator.generate_all_events()
    
    if not events:
        print("❌ No events generated")
        return
    
    # Ingest into Milvus
    ingest_choice = input("\n📥 Ingest events into Milvus now? (y/n): ").strip().lower()
    
    if ingest_choice == 'y':
        success = ingest_to_milvus(events)
        if success:
            print("\n✅ Knowledge base seeding complete!")
            print("   You can now start the web server: python web_app.py")
    else:
        print("\n💾 Events generated but not ingested")
        print("   Run this script again to ingest")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()




