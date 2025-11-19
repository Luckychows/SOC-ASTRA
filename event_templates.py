#!/usr/bin/env python3
"""
Event Templates for Synthetic Security Event Generation
Provides realistic templates for various security scenarios
"""

import random
from datetime import datetime, timedelta
from typing import Dict, List


class EventTemplate:
    """Base class for event templates"""
    
    @staticmethod
    def random_timestamp(days_back: int = 30) -> str:
        """Generate random timestamp within last N days"""
        now = datetime.now()
        random_days = random.uniform(0, days_back)
        random_hours = random.uniform(0, 24)
        random_minutes = random.uniform(0, 60)
        
        timestamp = now - timedelta(
            days=random_days,
            hours=random_hours,
            minutes=random_minutes
        )
        return timestamp.isoformat()
    
    @staticmethod
    def random_username() -> str:
        """Generate random username"""
        users = [
            "admin", "administrator", "root", "user", "service_account",
            "john.doe", "jane.smith", "bob.wilson", "alice.johnson",
            "system", "backup_admin", "dev_user", "test_user"
        ]
        return random.choice(users)
    
    @staticmethod
    def random_hostname(host_type: str = "workstation") -> str:
        """Generate random hostname"""
        if host_type == "dc":
            return f"DC-{random.randint(1, 3)}"
        elif host_type == "server":
            return f"SRV-{random.randint(1, 10)}"
        else:
            return f"WS-{random.randint(1, 50)}"


class BruteForceTemplate(EventTemplate):
    """Brute force attack templates"""
    
    @staticmethod
    def failed_login(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate failed login event"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4625",
            "event_type": "Failed Login",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": random.choice(["admin", "administrator", "root"]),
            "hostname": EventTemplate.random_hostname("dc"),
            "raw_log": f"Failed login attempt from {source_ip}",
            "dataset_type": "Synthetic",
            "severity": "MEDIUM",
            "mitre_attack": "T1110.001 - Brute Force: Password Guessing"
        }
    
    @staticmethod
    def successful_login_after_brute_force(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate successful login after brute force"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4624",
            "event_type": "Successful Login",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": "admin",
            "hostname": EventTemplate.random_hostname("dc"),
            "raw_log": f"Successful login from {source_ip} after multiple failed attempts",
            "dataset_type": "Synthetic",
            "severity": "HIGH",
            "mitre_attack": "T1078 - Valid Accounts"
        }


class LateralMovementTemplate(EventTemplate):
    """Lateral movement templates"""
    
    @staticmethod
    def psexec_execution(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate PSExec lateral movement"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "7045",
            "event_type": "Service Installation",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": "admin",
            "hostname": EventTemplate.random_hostname("server"),
            "raw_log": f"PSEXESVC service installed on {target_ip}",
            "dataset_type": "Synthetic",
            "severity": "HIGH",
            "mitre_attack": "T1021.002 - Remote Services: SMB/Windows Admin Shares"
        }
    
    @staticmethod
    def rdp_connection(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate RDP connection event"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4624",
            "event_type": "Remote Desktop Login",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname("server"),
            "raw_log": f"RDP session from {source_ip} to {target_ip}",
            "dataset_type": "Synthetic",
            "severity": "MEDIUM",
            "mitre_attack": "T1021.001 - Remote Services: Remote Desktop Protocol"
        }
    
    @staticmethod
    def network_share_access(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate network share access"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "5140",
            "event_type": "Network Share Access",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname("server"),
            "raw_log": f"Share access from {source_ip}: \\\\{target_ip}\\C$",
            "dataset_type": "Synthetic",
            "severity": "MEDIUM",
            "mitre_attack": "T1021.002 - Remote Services: SMB/Windows Admin Shares"
        }


class CredentialDumpingTemplate(EventTemplate):
    """Credential dumping templates"""
    
    @staticmethod
    def lsass_access(source_ip: str, timestamp: str = None) -> Dict:
        """Generate LSASS memory access (Mimikatz)"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "10",
            "event_type": "Process Access - LSASS",
            "source_ip": source_ip,
            "dest_ip": source_ip,
            "username": "admin",
            "hostname": EventTemplate.random_hostname("dc"),
            "raw_log": "LSASS.exe memory access detected - possible credential dumping",
            "dataset_type": "Synthetic",
            "severity": "CRITICAL",
            "mitre_attack": "T1003.001 - OS Credential Dumping: LSASS Memory"
        }
    
    @staticmethod
    def sam_dump(source_ip: str, timestamp: str = None) -> Dict:
        """Generate SAM database dump"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4663",
            "event_type": "Registry Access - SAM",
            "source_ip": source_ip,
            "dest_ip": source_ip,
            "username": "admin",
            "hostname": EventTemplate.random_hostname("dc"),
            "raw_log": "SAM registry hive accessed",
            "dataset_type": "Synthetic",
            "severity": "CRITICAL",
            "mitre_attack": "T1003.002 - OS Credential Dumping: Security Account Manager"
        }


class ReconnaissanceTemplate(EventTemplate):
    """Reconnaissance templates"""
    
    @staticmethod
    def port_scan(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate port scan event"""
        ports = [22, 80, 443, 445, 3389, 1433, 3306, 8080]
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "5156",
            "event_type": "Port Scan",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": "N/A",
            "hostname": EventTemplate.random_hostname("server"),
            "source_port": random.randint(1024, 65535),
            "dest_port": random.choice(ports),
            "raw_log": f"Port scan detected from {source_ip} to {target_ip}",
            "dataset_type": "Synthetic",
            "severity": "MEDIUM",
            "mitre_attack": "T1046 - Network Service Discovery"
        }
    
    @staticmethod
    def dns_enumeration(source_ip: str, timestamp: str = None) -> Dict:
        """Generate DNS enumeration"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "3008",
            "event_type": "DNS Query",
            "source_ip": source_ip,
            "dest_ip": "8.8.8.8",
            "username": "N/A",
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"DNS zone transfer attempt from {source_ip}",
            "dataset_type": "Synthetic",
            "severity": "LOW",
            "mitre_attack": "T1590.002 - Gather Victim Network Information: DNS"
        }


class ExfiltrationTemplate(EventTemplate):
    """Data exfiltration templates"""
    
    @staticmethod
    def large_data_transfer(source_ip: str, external_ip: str, timestamp: str = None) -> Dict:
        """Generate large data transfer"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "5156",
            "event_type": "Large Data Transfer",
            "source_ip": source_ip,
            "dest_ip": external_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"Large outbound data transfer: {random.randint(100, 1000)}MB to {external_ip}",
            "dataset_type": "Synthetic",
            "severity": "HIGH",
            "mitre_attack": "T1041 - Exfiltration Over C2 Channel"
        }
    
    @staticmethod
    def dns_tunneling(source_ip: str, timestamp: str = None) -> Dict:
        """Generate DNS tunneling"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "3008",
            "event_type": "DNS Tunneling",
            "source_ip": source_ip,
            "dest_ip": "8.8.8.8",
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"Suspicious DNS query pattern detected from {source_ip}",
            "dataset_type": "Synthetic",
            "severity": "HIGH",
            "mitre_attack": "T1048.003 - Exfiltration Over Alternative Protocol: DNS"
        }


class NormalActivityTemplate(EventTemplate):
    """Normal baseline activity templates"""
    
    @staticmethod
    def normal_login(source_ip: str, target_ip: str, timestamp: str = None) -> Dict:
        """Generate normal login"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4624",
            "event_type": "Successful Login",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"Normal user login from {source_ip}",
            "dataset_type": "Synthetic",
            "severity": "LOW",
            "mitre_attack": "N/A"
        }
    
    @staticmethod
    def file_access(source_ip: str, timestamp: str = None) -> Dict:
        """Generate file access"""
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4663",
            "event_type": "File Access",
            "source_ip": source_ip,
            "dest_ip": source_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"User accessed file: Documents\\report.docx",
            "dataset_type": "Synthetic",
            "severity": "LOW",
            "mitre_attack": "N/A"
        }
    
    @staticmethod
    def process_creation(source_ip: str, timestamp: str = None) -> Dict:
        """Generate normal process creation"""
        processes = ["chrome.exe", "outlook.exe", "excel.exe", "word.exe"]
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4688",
            "event_type": "Process Creation",
            "source_ip": source_ip,
            "dest_ip": source_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"Process created: {random.choice(processes)}",
            "dataset_type": "Synthetic",
            "severity": "LOW",
            "mitre_attack": "N/A"
        }


class MalwareTemplate(EventTemplate):
    """Malware execution templates"""
    
    @staticmethod
    def suspicious_process(source_ip: str, timestamp: str = None) -> Dict:
        """Generate suspicious process execution"""
        processes = ["powershell.exe -enc", "cmd.exe /c", "wscript.exe", "regsvr32.exe"]
        return {
            "timestamp": timestamp or EventTemplate.random_timestamp(),
            "event_id": "4688",
            "event_type": "Suspicious Process Creation",
            "source_ip": source_ip,
            "dest_ip": source_ip,
            "username": EventTemplate.random_username(),
            "hostname": EventTemplate.random_hostname(),
            "raw_log": f"Suspicious process: {random.choice(processes)}",
            "dataset_type": "Synthetic",
            "severity": "HIGH",
            "mitre_attack": "T1059 - Command and Scripting Interpreter"
        }




