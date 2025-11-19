#!/usr/bin/env python3
"""
SOC-ASTRA Web Application
Real-time incident triage dashboard with AI analysis
"""

import os
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Import components
from database import IncidentDatabase
from log_processor import LogProcessor
from rag_module import RAGManager

# Load environment
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Global components
db = None
log_processor = None
ai_copilot = None
rag_manager = None


def display_banner():
    """Display startup banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🛡️  SOC-ASTRA WEB APPLICATION                       ║
║              Real-Time Incident Triage Dashboard                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)


def initialize_components():
    """Initialize all components"""
    global db, log_processor, ai_copilot, rag_manager
    
    print("\n" + "="*70)
    print("🚀 INITIALIZING COMPONENTS")
    print("="*70 + "\n")
    
    # 1. Initialize Database
    print("1️⃣  Initializing database...")
    db_path = os.getenv("DATABASE_PATH", "./data/incidents.db")
    db = IncidentDatabase(db_path)
    print(f"   ✅ Database ready: {db_path}\n")
    
    # 2. Initialize AI Copilot
    print("2️⃣  Initializing AI Copilot...")
    from main import AISOCCopilot
    
    ai_copilot = AISOCCopilot()
    
    # Setup OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        print("   ❌ OPENAI_API_KEY not found in environment")
        print("   Please set it in .env file")
        return False
    
    os.environ["OPENAI_API_KEY"] = openai_key
    ai_copilot.api_key = openai_key
    
    if not ai_copilot._initialize_client():
        print("   ❌ Failed to initialize AI client")
        return False
    
    print(f"   ✅ AI Copilot ready (Model: {os.getenv('OPENAI_MODEL', 'gpt-4o')})\n")
    
    # 3. Initialize RAG (if enabled)
    enable_rag = os.getenv("ENABLE_RAG", "true").lower() == "true"
    
    if enable_rag:
        print("3️⃣  Initializing RAG (Knowledge Base)...")
        
        milvus_host = os.getenv("MILVUS_HOST", "localhost")
        milvus_port = os.getenv("MILVUS_PORT", "19530")
        collection_name = os.getenv("KNOWLEDGE_BASE_COLLECTION", "soc_knowledge_base")
        
        try:
            rag_manager = RAGManager(
                milvus_host=milvus_host,
                milvus_port=milvus_port,
                collection_name=collection_name
            )
            
            if not rag_manager.connect():
                print("   ⚠️  Milvus connection failed - RAG disabled")
                print("   Make sure Docker is running: python setup_docker.py")
                rag_manager = None
            else:
                if not rag_manager.initialize_vector_store():
                    print("   ⚠️  Vector store init failed - RAG disabled")
                    rag_manager = None
                else:
                    # Check if knowledge base exists
                    stats = rag_manager.get_collection_stats()
                    existing_count = stats.get('num_entities', 0)
                    
                    if existing_count == 0:
                        print(f"   📚 Empty knowledge base found - will regenerate")
                        
                        # Auto-generate synthetic data if seed config exists
                        seed_config = os.getenv("SEED_CONFIG_PATH", "seed_ips.yaml")
                        if os.path.exists(seed_config):
                            print(f"   🧬 Generating synthetic events from {seed_config}...")
                            
                            from seed_knowledge_base import load_config, SyntheticEventGenerator
                            
                            config = load_config(seed_config)
                            if config:
                                generator = SyntheticEventGenerator(config)
                                events = generator.generate_all_events()
                                
                                if events:
                                    print(f"\n   📥 Ingesting {len(events)} events into Milvus...")
                                    rag_manager.insert_events(events, batch_size=100)
                                    rag_manager.build_ip_profiles(events)
                                    
                                    stats = rag_manager.get_collection_stats()
                                    print(f"   ✅ Knowledge base ready!")
                                    print(f"      Vectors: {stats.get('num_entities', 0)}")
                        else:
                            print(f"   ⚠️  No seed_ips.yaml found - starting with empty KB")
                    else:
                        print(f"   ✅ Using existing knowledge base")
                        print(f"      Vectors: {existing_count}")
                    
                    # Pass RAG to AI Copilot
                    ai_copilot.rag_manager = rag_manager
                    ai_copilot.use_rag = True
                    
                    print()
        
        except Exception as e:
            print(f"   ⚠️  RAG initialization failed: {e}")
            print(f"   Continuing without RAG...")
            rag_manager = None
            print()
    else:
        print("3️⃣  RAG disabled (ENABLE_RAG=false)\n")
    
    # 4. Initialize Log Processor
    print("4️⃣  Initializing log processor...")
    num_workers = int(os.getenv("ANALYSIS_WORKERS", "2"))
    
    log_processor = LogProcessor(
        ai_copilot=ai_copilot,
        rag_manager=rag_manager,
        database=db,
        num_workers=num_workers
    )
    
    log_processor.start()
    print(f"   ✅ Log processor ready ({num_workers} workers)\n")
    
    print("="*70)
    print("✅ ALL COMPONENTS INITIALIZED")
    print("="*70 + "\n")
    
    return True


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')


@app.route('/api/ingest', methods=['POST'])
def ingest_log():
    """Ingest a new log (no auth required)"""
    try:
        log = request.get_json()
        
        if not log:
            return jsonify({'error': 'No log data provided'}), 400
        
        # Add to processing queue
        success = log_processor.ingest_log(log)
        
        if success:
            return jsonify({
                'status': 'accepted',
                'message': 'Log queued for analysis'
            }), 202
        else:
            return jsonify({
                'status': 'rejected',
                'message': 'Queue is full, try again later'
            }), 503
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Get incidents with filters"""
    try:
        # Parse query parameters
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Filters
        severity_param = request.args.get('severity')
        severity = severity_param.split(',') if severity_param else None
        
        status = request.args.get('status')
        source_ip = request.args.get('source_ip')
        
        # Get incidents
        incidents = db.get_incidents(
            limit=limit,
            offset=offset,
            severity=severity,
            status=status,
            source_ip=source_ip
        )
        
        # Get total count
        total = db.count_incidents(severity=severity, status=status)
        
        return jsonify({
            'incidents': incidents,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/incident/<int:incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Get single incident details"""
    try:
        incident = db.get_incident_by_id(incident_id)
        
        if incident:
            # Get related incidents (same IP)
            source_ip = incident.get('source_ip')
            if source_ip and source_ip != 'N/A':
                related = db.get_incidents_by_ip(source_ip, limit=10)
                # Exclude current incident
                related = [r for r in related if r['id'] != incident_id]
                incident['related_incidents'] = related[:5]
            
            return jsonify(incident)
        else:
            return jsonify({'error': 'Incident not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/incident/<int:incident_id>/action', methods=['POST'])
def incident_action(incident_id):
    """Perform action on incident"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        if action not in ['reviewed', 'dismissed', 'escalated']:
            return jsonify({'error': 'Invalid action'}), 400
        
        success = db.update_incident_status(incident_id, action)
        
        if success:
            return jsonify({
                'status': 'success',
                'incident_id': incident_id,
                'action': action
            })
        else:
            return jsonify({'error': 'Incident not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        # Database stats
        db_stats = db.get_statistics()
        
        # Processor stats
        processor_stats = log_processor.get_stats()
        
        return jsonify({
            'database': db_stats,
            'processor': processor_stats,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        processor_stats = log_processor.get_stats()
        
        health = {
            'status': 'healthy',
            'database': 'connected',
            'ai_copilot': 'ready' if ai_copilot else 'unavailable',
            'rag': 'enabled' if rag_manager else 'disabled',
            'workers': len([w for w in processor_stats['workers'] if w['running']]),
            'queue_size': processor_stats['queue']['queue_size'],
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(health)
    
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


def cleanup():
    """Cleanup on shutdown"""
    global log_processor, rag_manager
    
    print("\n\n🛑 Shutting down...")
    
    if log_processor:
        log_processor.stop()
    
    if rag_manager:
        rag_manager.disconnect()
    
    print("✅ Cleanup complete\n")


def main():
    """Main execution"""
    display_banner()
    
    # Initialize components
    if not initialize_components():
        print("❌ Initialization failed")
        return
    
    # Get configuration
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    print(f"🌐 Starting web server...")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Dashboard: http://localhost:{port}")
    print(f"   API: http://localhost:{port}/api/ingest")
    print(f"\n   Press Ctrl+C to stop\n")
    print("="*70 + "\n")
    
    try:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    finally:
        cleanup()


if __name__ == "__main__":
    main()


