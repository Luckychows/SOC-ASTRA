#!/usr/bin/env python3
"""
Generate comprehensive synthetic security logs
Creates realistic attack scenarios for SOC analysis
"""

import json
import random
from datetime import datetime, timedelta

def generate_comprehensive_logs(output_file="security_logs.json", num_events=1000):
    """Generate comprehensive security log dataset"""
    
    print(f"🎲 Generating {num_events} security events...\n")
    
    # Define actors
    attacker_ips = {
        "203.0.113.50": {"name": "APT29", "reputation": "Known threat actor"},
        "198.51.100.25": {"name": "Botnet C2", "reputation": "Command & Control"},
        "192.0.2.100": {"name": "Scanner", "reputation": "Port scanning activity"},
        "185.220.101.40": {"name": "Tor Exit Node", "reputation": "Anonymous proxy"},
        "45.142.120.50": {"name": "Ransomware Group", "reputation": "Malware distribution"}
    }
    
    internal_assets = {
        "10.0.0.5": {"name": "DC-01", "type": "Domain Controller", "criticality": "Critical"},
        "10.0.0.10": {"name": "FILE-SRV-01", "type": "File Server", "criticality": "High"},
        "10.0.0.15": {"name": "DB-SRV-01", "type": "Database Server", "criticality": "Critical"},
        "192.168.1.100": {"name": "WEB-SRV-01", "type": "Web Server", "criticality": "High"},
        "192.168.1.150": {"name": "MAIL-SRV-01", "type": "Mail Server", "criticality": "Medium"}
    }
    
    workstations = [f"10.10.{random.randint(1,10)}.{random.randint(10,250)}" for _ in range(20)]
    
    usernames = ["admin", "administrator", "john.doe", "jane.smith", "bob.wilson", 
                 "alice.brown", "service_account", "backup_admin", "it_support"]
    
    events = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Scenario 1: Reconnaissance Phase (20%)
    print("📡 Phase 1: Reconnaissance...")
    for i in range(int(num_events * 0.20)):
        attacker_ip = random.choice(list(attacker_ips.keys()))
        target_ip = random.choice(list(internal_assets.keys()))
        
        events.append({
            "id": f"EVT-{i+1:06d}",
            "timestamp": (base_time + timedelta(minutes=i*5)).isoformat(),
            "severity": "MEDIUM",
            "event_type": "Port Scan Detected",
            "event_id": "5156",
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "dest_port": random.choice([22, 80, 443, 3389, 445, 135, 139]),
            "protocol": "TCP",
            "username": "N/A",
            "hostname": internal_assets[target_ip]["name"],
            "action": "blocked",
            "raw_log": f"Multiple connection attempts from {attacker_ip} to {target_ip} on various ports",
            "mitre": "T1046 - Network Service Scanning",
            "tags": ["reconnaissance", "port_scan", "external_threat"]
        })
    
    # Scenario 2: Initial Access - Brute Force (15%)
    print("🔐 Phase 2: Brute Force Attacks...")
    attacker_ip = list(attacker_ips.keys())[0]
    target_dc = "10.0.0.5"
    
    for i in range(int(num_events * 0.15)):
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=2, minutes=i*2)).isoformat(),
            "severity": "HIGH",
            "event_type": "Failed Login Attempt",
            "event_id": "4625",
            "source_ip": attacker_ip,
            "dest_ip": target_dc,
            "username": random.choice(["admin", "administrator", "root"]),
            "hostname": "DC-01",
            "logon_type": "3",
            "failure_reason": "Bad password",
            "action": "failed",
            "raw_log": f"Failed login attempt from {attacker_ip} to DC-01",
            "mitre": "T1110.001 - Password Guessing",
            "tags": ["brute_force", "failed_login", "credential_access"]
        })
    
    # Scenario 3: Successful Compromise (1%)
    print("💥 Phase 3: Successful Compromise...")
    events.append({
        "id": f"EVT-{len(events)+1:06d}",
        "timestamp": (base_time + timedelta(hours=3)).isoformat(),
        "severity": "CRITICAL",
        "event_type": "Successful Login",
        "event_id": "4624",
        "source_ip": attacker_ip,
        "dest_ip": target_dc,
        "username": "admin",
        "hostname": "DC-01",
        "logon_type": "3",
        "action": "allowed",
        "raw_log": f"Successful remote login from {attacker_ip} after {int(num_events * 0.15)} failed attempts",
        "mitre": "T1078 - Valid Accounts",
        "tags": ["successful_login", "compromised_account", "critical_alert"]
    })
    
    # Scenario 4: Privilege Escalation (5%)
    print("⬆️  Phase 4: Privilege Escalation...")
    for i in range(int(num_events * 0.05)):
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=3, minutes=15+i*3)).isoformat(),
            "severity": "HIGH",
            "event_type": "Special Privileges Assigned",
            "event_id": "4672",
            "source_ip": target_dc,
            "dest_ip": target_dc,
            "username": "admin",
            "hostname": "DC-01",
            "privileges": "SeDebugPrivilege, SeBackupPrivilege",
            "action": "granted",
            "raw_log": "Special privileges assigned to compromised admin account",
            "mitre": "T1078.002 - Domain Accounts",
            "tags": ["privilege_escalation", "suspicious_privileges"]
        })
    
    # Scenario 5: Credential Dumping (3%)
    print("🔑 Phase 5: Credential Dumping...")
    for i in range(int(num_events * 0.03)):
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=3, minutes=45+i*5)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "Suspicious Process Access",
            "event_id": "10",
            "source_ip": target_dc,
            "dest_ip": target_dc,
            "username": "admin",
            "hostname": "DC-01",
            "process": "mimikatz.exe",
            "target_process": "lsass.exe",
            "access_rights": "PROCESS_VM_READ",
            "action": "detected",
            "raw_log": "Suspicious access to LSASS process memory - potential credential dumping",
            "mitre": "T1003.001 - LSASS Memory",
            "tags": ["credential_dumping", "mimikatz", "critical_alert"]
        })
    
    # Scenario 6: Lateral Movement (10%)
    print("↔️  Phase 6: Lateral Movement...")
    compromised_hosts = [target_dc] + random.sample(list(internal_assets.keys()), 2)
    
    for i in range(int(num_events * 0.10)):
        source = random.choice(compromised_hosts)
        target = random.choice([h for h in internal_assets.keys() if h != source])
        
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=4, minutes=i*5)).isoformat(),
            "severity": "HIGH",
            "event_type": "Remote Service Created",
            "event_id": "7045",
            "source_ip": source,
            "dest_ip": target,
            "username": "admin",
            "hostname": internal_assets[target]["name"],
            "service_name": f"WindowsUpdate{random.randint(1,99)}",
            "service_path": "\\\\127.0.0.1\\ADMIN$\\system32\\svchost.exe",
            "action": "created",
            "raw_log": f"Remote service created on {internal_assets[target]['name']} from {internal_assets[source]['name']}",
            "mitre": "T1021.002 - SMB/Windows Admin Shares",
            "tags": ["lateral_movement", "remote_service", "psexec"]
        })
    
    # Scenario 7: Data Exfiltration (5%)
    print("📤 Phase 7: Data Exfiltration...")
    for i in range(int(num_events * 0.05)):
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=5, minutes=i*10)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "Large Data Transfer",
            "event_id": "5156",
            "source_ip": "10.0.0.10",
            "dest_ip": attacker_ip,
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(1000000000, 5000000000),
            "username": "admin",
            "hostname": "FILE-SRV-01",
            "action": "allowed",
            "raw_log": f"Large data transfer ({random.randint(1,5)}GB) to external IP",
            "mitre": "T1041 - Exfiltration Over C2 Channel",
            "tags": ["exfiltration", "data_theft", "critical_alert"]
        })
    
    # Scenario 8: Normal Activity (41%)
    print("✅ Phase 8: Normal Operations...")
    for i in range(int(num_events * 0.41)):
        user = random.choice(usernames)
        ws_ip = random.choice(workstations)
        
        event_types = [
            {
                "type": "Successful Login",
                "id": "4624",
                "severity": "LOW",
                "mitre": "N/A",
                "tags": ["normal_activity", "user_login"]
            },
            {
                "type": "File Access",
                "id": "4663",
                "severity": "LOW",
                "mitre": "N/A",
                "tags": ["normal_activity", "file_access"]
            },
            {
                "type": "Process Creation",
                "id": "4688",
                "severity": "LOW",
                "mitre": "N/A",
                "tags": ["normal_activity", "process_creation"]
            }
        ]
        
        event_type = random.choice(event_types)
        
        events.append({
            "id": f"EVT-{len(events)+1:06d}",
            "timestamp": (base_time + timedelta(hours=random.randint(0,168), minutes=random.randint(0,59))).isoformat(),
            "severity": event_type["severity"],
            "event_type": event_type["type"],
            "event_id": event_type["id"],
            "source_ip": ws_ip,
            "dest_ip": random.choice(list(internal_assets.keys())),
            "username": user,
            "hostname": f"WS-{random.randint(1,50):02d}",
            "action": "success",
            "raw_log": f"Normal user activity by {user}",
            "mitre": event_type["mitre"],
            "tags": event_type["tags"]
        })
    
    # Sort by timestamp
    events.sort(key=lambda x: x['timestamp'])
    
    # Save to file
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2)
    
    print(f"\n✅ Generated {len(events)} events")
    print(f"📁 Saved to: {output_file}")
    print(f"\n📊 Event Distribution:")
    print(f"   Reconnaissance: {int(num_events * 0.20)} events")
    print(f"   Brute Force: {int(num_events * 0.15)} events")
    print(f"   Compromise: 1 event")
    print(f"   Privilege Escalation: {int(num_events * 0.05)} events")
    print(f"   Credential Dumping: {int(num_events * 0.03)} events")
    print(f"   Lateral Movement: {int(num_events * 0.10)} events")
    print(f"   Data Exfiltration: {int(num_events * 0.05)} events")
    print(f"   Normal Activity: {int(num_events * 0.41)} events")
    
    return output_file

if __name__ == "__main__":
    import sys
    
    num_events = 1000
    if len(sys.argv) > 1:
        try:
            num_events = int(sys.argv[1])
        except:
            pass
    
    print("\n" + "="*70)
    print("🛡️  SOC Security Log Generator")
    print("="*70 + "\n")
    
    generate_comprehensive_logs(num_events=num_events)
    
    print("\n✅ Ready to use with soc_agent.py")
    print("="*70 + "\n")







