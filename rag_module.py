"""
RAG Module for AI-SOC Copilot using LangChain and Milvus
OpenAI-only implementation with vector storage and retrieval
"""

import os
import json
from typing import List, Dict, Optional
from datetime import datetime

from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import Milvus
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from pymilvus import connections, utility


class RAGManager:
    """Manages RAG operations with Milvus vector database using LangChain"""
    
    def __init__(self, 
                 milvus_host: str = "localhost",
                 milvus_port: str = "19530",
                 collection_name: str = "soc_security_events",
                 embedding_model: str = "text-embedding-3-large",
                 llm_model: str = "gpt-4o"):
        """Initialize RAG Manager with LangChain"""
        self.milvus_host = milvus_host
        self.milvus_port = milvus_port
        self.collection_name = collection_name
        self.connection_args = {
            "host": milvus_host,
            "port": milvus_port
        }
        
        # Initialize OpenAI components via LangChain
        self.embeddings = OpenAIEmbeddings(
            model=embedding_model,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        self.llm = ChatOpenAI(
            model=llm_model,
            temperature=0,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Text splitter for chunking
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=int(os.getenv("CHUNK_SIZE", 512)),
            chunk_overlap=int(os.getenv("CHUNK_OVERLAP", 50)),
            length_function=len,
        )
        
        self.vector_store = None
        self.ip_profiles = {}  # Store IP behavior profiles
        
    def connect(self) -> bool:
        """Connect to Milvus"""
        try:
            connections.connect(
                alias="default",
                host=self.milvus_host,
                port=self.milvus_port
            )
            print(f"✅ Connected to Milvus at {self.milvus_host}:{self.milvus_port}")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to Milvus: {e}")
            return False
    
    def initialize_vector_store(self) -> bool:
        """Initialize or load vector store"""
        try:
            # Check if collection exists
            if utility.has_collection(self.collection_name):
                print(f"ℹ️  Loading existing collection '{self.collection_name}'")
                self.vector_store = Milvus(
                    embedding_function=self.embeddings,
                    collection_name=self.collection_name,
                    connection_args=self.connection_args
                )
            else:
                print(f"ℹ️  Collection '{self.collection_name}' will be created on first insert")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to initialize vector store: {e}")
            return False
    
    def prepare_event_text(self, event: Dict) -> str:
        """Prepare event data as structured text"""
        text_parts = [
            f"Event Type: {event.get('event_type', 'Unknown')}",
            f"Timestamp: {event.get('timestamp', '')}",
            f"Source IP: {event.get('source_ip', 'N/A')}",
            f"Destination IP: {event.get('dest_ip', 'N/A')}",
            f"Username: {event.get('username', 'N/A')}",
            f"Hostname: {event.get('hostname', 'N/A')}",
            f"Event ID: {event.get('event_id', 'N/A')}",
        ]
        
        # Add severity if present
        if event.get('severity'):
            text_parts.append(f"Severity: {event['severity']}")
        
        # Add MITRE if present
        if event.get('mitre_attack'):
            text_parts.append(f"MITRE ATT&CK: {event['mitre_attack']}")
        
        # Add raw log
        if event.get('raw_log'):
            text_parts.append(f"Raw Log: {event['raw_log'][:500]}")
        
        return "\n".join(text_parts)
    
    def insert_events(self, events: List[Dict], batch_size: int = 50) -> int:
        """Insert security events into Milvus using LangChain"""
        if not events:
            return 0
        
        print(f"\n📥 Processing {len(events)} events for vector storage...")
        
        # Prepare documents
        documents = []
        for idx, event in enumerate(events):
            # Create text representation
            text = self.prepare_event_text(event)
            
            # Create metadata
            metadata = {
                "alert_id": event.get("alert_id", f"EVT-{idx}"),
                "timestamp": event.get("timestamp", datetime.now().isoformat()),
                "event_type": event.get("event_type", "Unknown"),
                "source_ip": event.get("source_ip", "N/A"),
                "dest_ip": event.get("dest_ip", "N/A"),
                "dataset_type": event.get("dataset_type", "Unknown"),
                "event_id": str(event.get("event_id", "N/A"))
            }
            
            # Create LangChain Document
            doc = Document(page_content=text, metadata=metadata)
            documents.append(doc)
        
        # Split documents into chunks
        print(f"📄 Splitting documents into chunks...")
        split_docs = self.text_splitter.split_documents(documents)
        print(f"   Created {len(split_docs)} chunks from {len(documents)} events")
        
        # Insert into Milvus in batches
        total_inserted = 0
        try:
            for i in range(0, len(split_docs), batch_size):
                batch = split_docs[i:i + batch_size]
                
                if self.vector_store is None:
                    # Create vector store on first batch
                    # Note: Milvus auto-generates IDs by default in newer versions
                    self.vector_store = Milvus.from_documents(
                        batch,
                        embedding=self.embeddings,
                        collection_name=self.collection_name,
                        connection_args=self.connection_args
                    )
                else:
                    # Add to existing vector store
                    self.vector_store.add_documents(batch)
                
                total_inserted += len(batch)
                print(f"   ✓ Inserted batch {i//batch_size + 1} ({len(batch)} chunks)")
            
            print(f"\n✅ Successfully inserted {total_inserted} document chunks into Milvus")
            return total_inserted
            
        except Exception as e:
            print(f"❌ Insertion failed: {e}")
            import traceback
            traceback.print_exc()
            return total_inserted
    
    def search_similar_events(self, query: str, top_k: int = 5) -> List[Dict]:
        """Search for similar security events using vector similarity"""
        if not self.vector_store:
            print("❌ Vector store not initialized")
            return []
        
        try:
            # Perform similarity search
            results = self.vector_store.similarity_search_with_score(
                query,
                k=top_k
            )
            
            # Format results
            similar_events = []
            for doc, score in results:
                similar_events.append({
                    "score": float(score),
                    "similarity_percentage": (1 - score) * 100,  # Convert distance to similarity
                    "content": doc.page_content,
                    "metadata": doc.metadata
                })
            
            return similar_events
            
        except Exception as e:
            print(f"❌ Search failed: {e}")
            return []
    
    def build_ip_profiles(self, events: List[Dict]):
        """Build comprehensive IP behavior profiles for better triage"""
        from collections import defaultdict
        
        print("   Analyzing IP patterns and behaviors...")
        
        # Group events by IP
        ip_events = defaultdict(list)
        
        for event in events:
            source_ip = event.get('source_ip', 'N/A')
            dest_ip = event.get('dest_ip', 'N/A')
            
            if source_ip and source_ip != 'N/A':
                ip_events[source_ip].append(event)
            if dest_ip and dest_ip != 'N/A':
                ip_events[dest_ip].append(event)
        
        # Build profiles
        for ip, ip_event_list in ip_events.items():
            profile = {
                'ip': ip,
                'total_events': len(ip_event_list),
                'event_types': {},
                'severity_distribution': {},
                'mitre_techniques': set(),
                'first_seen': None,
                'last_seen': None,
                'is_internal': ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'),
                'ports_accessed': set(),
                'usernames': set()
            }
            
            for event in ip_event_list:
                # Event types
                event_type = event.get('event_type', 'Unknown')
                profile['event_types'][event_type] = profile['event_types'].get(event_type, 0) + 1
                
                # Severity
                severity = event.get('severity', 'MEDIUM')
                profile['severity_distribution'][severity] = profile['severity_distribution'].get(severity, 0) + 1
                
                # MITRE techniques
                mitre = event.get('mitre_attack', '')
                if mitre:
                    profile['mitre_techniques'].add(mitre)
                
                # Timestamps
                timestamp = event.get('timestamp', '')
                if timestamp:
                    if not profile['first_seen'] or timestamp < profile['first_seen']:
                        profile['first_seen'] = timestamp
                    if not profile['last_seen'] or timestamp > profile['last_seen']:
                        profile['last_seen'] = timestamp
                
                # Ports
                if 'dest_port' in event:
                    profile['ports_accessed'].add(event['dest_port'])
                if 'source_port' in event:
                    profile['ports_accessed'].add(event['source_port'])
                
                # Usernames
                if 'username' in event and event['username'] != 'N/A':
                    profile['usernames'].add(event['username'])
            
            # Convert sets to lists for JSON serialization
            profile['mitre_techniques'] = list(profile['mitre_techniques'])
            profile['ports_accessed'] = list(profile['ports_accessed'])
            profile['usernames'] = list(profile['usernames'])
            
            # Calculate risk score
            profile['risk_score'] = self._calculate_ip_risk_score(profile)
            
            self.ip_profiles[ip] = profile
        
        print(f"   ✓ Built profiles for {len(self.ip_profiles)} unique IPs")
        
        # Show some stats
        high_risk_ips = [ip for ip, prof in self.ip_profiles.items() if prof['risk_score'] > 70]
        print(f"   ✓ Identified {len(high_risk_ips)} high-risk IPs")
    
    def _calculate_ip_risk_score(self, profile: Dict) -> int:
        """Calculate risk score for an IP based on its behavior profile"""
        score = 0
        
        # Base score from event count
        if profile['total_events'] > 100:
            score += 20
        elif profile['total_events'] > 50:
            score += 10
        elif profile['total_events'] > 20:
            score += 5
        
        # Severity distribution
        critical_count = profile['severity_distribution'].get('CRITICAL', 0)
        high_count = profile['severity_distribution'].get('HIGH', 0)
        
        score += critical_count * 10
        score += high_count * 5
        
        # MITRE techniques variety (more techniques = more sophisticated)
        score += min(len(profile['mitre_techniques']) * 5, 30)
        
        # External IPs are higher risk
        if not profile['is_internal']:
            score += 15
        
        # Multiple usernames from same IP (potential compromise)
        if len(profile['usernames']) > 3:
            score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def get_ip_context(self, ip_address: str) -> str:
        """Get comprehensive context about a specific IP"""
        if ip_address not in self.ip_profiles:
            return f"No historical data for IP {ip_address}"
        
        profile = self.ip_profiles[ip_address]
        
        context = f"""
IP PROFILE: {ip_address}
{'='*70}
Risk Score: {profile['risk_score']}/100
Total Events: {profile['total_events']}
Type: {'Internal' if profile['is_internal'] else 'External'}
First Seen: {profile['first_seen']}
Last Seen: {profile['last_seen']}

Event Types:
"""
        for event_type, count in sorted(profile['event_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
            context += f"  - {event_type}: {count} occurrences\n"
        
        context += f"\nSeverity Distribution:\n"
        for severity, count in profile['severity_distribution'].items():
            context += f"  - {severity}: {count} events\n"
        
        if profile['mitre_techniques']:
            context += f"\nMITRE ATT&CK Techniques:\n"
            for technique in profile['mitre_techniques'][:5]:
                context += f"  - {technique}\n"
        
        if profile['usernames']:
            context += f"\nAssociated Usernames: {', '.join(list(profile['usernames'])[:5])}\n"
        
        if profile['ports_accessed']:
            context += f"\nPorts Accessed: {', '.join(map(str, list(profile['ports_accessed'])[:10]))}\n"
        
        return context
    
    def get_augmented_context(self, query: str, top_k: int = 5, include_ip_profile: bool = True, source_ip: str = None, dest_ip: str = None) -> str:
        """Get augmented context for RAG-enhanced analysis with IP profiling"""
        context = ""
        
        # Add IP-specific context if available
        if include_ip_profile and self.ip_profiles:
            ip_context = ""
            
            if source_ip and source_ip in self.ip_profiles:
                ip_context += "\n" + self.get_ip_context(source_ip) + "\n"
            
            if dest_ip and dest_ip in self.ip_profiles and dest_ip != source_ip:
                ip_context += "\n" + self.get_ip_context(dest_ip) + "\n"
            
            if ip_context:
                context += ip_context + "\n" + "=" * 70 + "\n\n"
        
        # Add similar events context
        similar_events = self.search_similar_events(query, top_k)
        
        if similar_events:
            context += "SIMILAR HISTORICAL EVENTS:\n"
            context += "=" * 70 + "\n\n"
            
            for idx, event in enumerate(similar_events, 1):
                similarity = event['similarity_percentage']
                metadata = event['metadata']
                content = event['content']
                
                context += f"[Historical Event {idx}] Similarity: {similarity:.1f}%\n"
                context += f"Alert ID: {metadata.get('alert_id', 'N/A')}\n"
                context += f"Event Type: {metadata.get('event_type', 'Unknown')}\n"
                context += f"Source IP: {metadata.get('source_ip', 'N/A')}\n"
                context += f"Timestamp: {metadata.get('timestamp', 'N/A')}\n"
                context += f"Details:\n{content[:250]}...\n"
                context += "-" * 70 + "\n\n"
        
        if not context:
            context = "No historical context available for this event."
        
        return context
    
    def analyze_with_rag(self, event: Dict) -> str:
        """Analyze an event with RAG-augmented context"""
        # Prepare query
        query = self.prepare_event_text(event)
        
        # Get similar events
        context = self.get_augmented_context(query, top_k=3)
        
        # Create analysis prompt
        prompt = f"""You are an expert SOC analyst. Analyze the following security event using the historical context provided.

{context}

CURRENT EVENT TO ANALYZE:
{query}

Based on the historical similar events and the current event, provide a comprehensive security analysis including:
1. Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
2. Threat classification
3. MITRE ATT&CK technique
4. Recommended actions
5. Confidence level (0-100%)

Respond in a structured format."""

        try:
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            print(f"❌ RAG analysis failed: {e}")
            return "Analysis failed - please review manually"
    
    def get_collection_stats(self) -> Dict:
        """Get collection statistics"""
        try:
            if self.vector_store:
                # Get collection info
                col = self.vector_store.col
                num_entities = col.num_entities
                
                return {
                    "collection_name": self.collection_name,
                    "num_entities": num_entities,
                    "status": "active"
                }
            else:
                return {
                    "collection_name": self.collection_name,
                    "status": "not_initialized"
                }
        except Exception as e:
            print(f"❌ Failed to get stats: {e}")
            return {}
    
    def drop_collection(self):
        """Drop the current collection"""
        try:
            if utility.has_collection(self.collection_name):
                utility.drop_collection(self.collection_name)
                self.vector_store = None
                self.ip_profiles = {}
                print(f"   ✓ Dropped collection: {self.collection_name}")
                return True
        except Exception as e:
            print(f"   ⚠️ Failed to drop collection: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Milvus"""
        try:
            connections.disconnect(alias="default")
            print("✅ Disconnected from Milvus")
        except Exception as e:
            pass


