# SOC-ASTRA - Real-Time AI-Powered Security Incident Triage Platform

## 🛡️ Overview

SOC-ASTRA is an intelligent Security Operations Center (SOC) platform that uses **AI-powered analysis** to automatically triage security incidents in real-time. It combines **OpenAI GPT-4**, **LangChain**, and **Milvus vector database** to provide context-aware threat analysis with historical incident correlation.

### Key Features

- **🚀 Real-Time Processing**: Instant AI analysis of security logs as they arrive
- **🧠 Context-Aware Intelligence**: Uses RAG (Retrieval-Augmented Generation) to correlate with historical incidents
- **📊 IP Behavioral Profiling**: Tracks and learns from IP address behavior patterns
- **🎯 MITRE ATT&CK Mapping**: Automatically maps threats to MITRE ATT&CK framework
- **📈 Confidence Scoring**: AI provides confidence levels for each analysis
- **🌐 Web Dashboard**: Modern, real-time dashboard for incident monitoring
- **🔄 Auto-Seeding**: Pre-generates synthetic security events for immediate intelligence

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXTERNAL LOG SOURCES                         │
│  (SIEM, Firewalls, IDS/IPS, Applications, Custom Systems)       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ HTTP POST /api/ingest
                             │ (JSON Logs)
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                    FLASK WEB SERVER                             │
│  - Receives logs via REST API                                   │
│  - Serves web dashboard                                         │
│  - Manages API endpoints                                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                    LOG PROCESSING QUEUE                         │
│  - Thread-safe queue (max 1000 logs)                            │
│  - Multiple worker threads (configurable)                       │
│  - Async processing                                             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                ↓                         ↓
┌───────────────────────────┐  ┌──────────────────────────────┐
│   AI ANALYSIS WORKERS    │  │   RAG CONTEXT RETRIEVAL      │
│  (LangChain + OpenAI)    │  │   (Milvus Vector Search)     │
│                           │  │                              │
│  - Analyzes each log     │  │  - Searches similar events   │
│  - Generates severity    │  │  - Retrieves IP profiles    │
│  - Maps MITRE techniques │  │  - Builds context            │
│  - Provides IOCs         │  │                              │
└───────────┬───────────────┘  └──────────────┬───────────────┘
            │                                  │
            └──────────────┬───────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│                    SQLITE DATABASE                              │
│  - Stores all analyzed incidents                                │
│  - Tracks status (new/reviewed/dismissed/escalated)             │
│  - Maintains full analysis history                              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────────┐
│                    WEB DASHBOARD                                │
│  - Real-time incident feed (auto-refresh every 5s)              │
│  - Severity filtering                                           │
│  - IP search                                                    │
│  - Detailed incident views                                      │
│  - Action management                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Log Ingestion**: External systems POST JSON logs to `/api/ingest`
2. **Queue Processing**: Logs added to thread-safe queue
3. **AI Analysis**: Worker threads pull logs and analyze with:
   - OpenAI GPT-4 via LangChain
   - RAG context from Milvus (similar past incidents)
   - IP behavioral profiles
4. **Storage**: Results stored in SQLite database
5. **Display**: Dashboard auto-refreshes showing new incidents
6. **Knowledge Growth**: Real logs also added to Milvus for future context

---

## 📦 Components Explained

### 1. **Web Application (`web_app.py`)**

The main Flask server that:
- Receives logs via HTTP POST
- Manages the analysis queue
- Serves the web dashboard
- Provides REST API endpoints
- Auto-generates synthetic events on first startup

**Key Features:**
- No authentication (designed for trusted internal networks)
- CORS enabled for development
- Graceful shutdown handling
- Health check endpoint

### 2. **Log Processor (`log_processor.py`)**

Handles async log processing:
- **LogQueue**: Thread-safe queue (max 1000 logs)
- **AnalysisWorker**: Multiple worker threads that:
  - Pull logs from queue
  - Normalize log formats
  - Call AI analysis
  - Store results in database
  - Update IP profiles incrementally

**Configuration:**
- `ANALYSIS_WORKERS`: Number of parallel workers (default: 2)
- `RAG_BATCH_SIZE`: How often to update vector store (default: 100)

### 3. **Database Layer (`database.py`)**

SQLite database for incident storage:
- **Schema**: Stores all incident data, AI analysis, status
- **Indexes**: Optimized for severity, status, IP, timestamp queries
- **Operations**: CRUD, filtering, statistics, status updates

**Tables:**
- `incidents`: All security incidents with full analysis

### 4. **RAG Module (`rag_module.py`)**

Retrieval-Augmented Generation for context-aware analysis:
- **Vector Store**: Milvus integration via LangChain
- **Embeddings**: OpenAI text-embedding-3-large
- **IP Profiling**: Builds behavioral profiles for each IP
- **Similarity Search**: Finds related past incidents

**How RAG Works:**
1. Incoming log is converted to text
2. Searches Milvus for similar past incidents (top 5)
3. Retrieves IP behavioral profile if available
4. Combines context with current log
5. Sends enriched context to AI for analysis

### 5. **AI Analysis (`main.py` - AISOCCopilot)**

Uses LangChain for all AI operations:
- **ChatOpenAI**: LangChain wrapper for OpenAI GPT-4
- **ChatPromptTemplate**: Structured prompts
- **PydanticOutputParser**: Structured JSON output
- **SecurityAnalysis**: Pydantic model for analysis results

**Analysis Output:**
- Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Confidence score (0-100%)
- Threat type
- MITRE ATT&CK technique
- IP reputation
- Detailed analysis
- Recommendations
- Auto-escalate decision
- IOC indicators

### 6. **Synthetic Event Generator (`seed_knowledge_base.py`)**

Pre-seeds knowledge base with realistic events:
- **Event Templates**: 7 attack scenario types
- **IP-Based Generation**: Creates events for provided IPs
- **Attack Chains**: Simulates complete attack lifecycles
- **MITRE Mapping**: All events mapped to MITRE techniques

**Scenarios Generated:**
- Brute force attacks
- Lateral movement
- Credential dumping
- Port scanning
- Data exfiltration
- Malware execution
- Normal baseline activity

### 7. **Web Dashboard**

Modern, responsive web interface:
- **Real-Time Feed**: Auto-refreshes every 5 seconds
- **Statistics Panel**: Live metrics and counts
- **Filtering**: By severity, status, IP address
- **Incident Cards**: Color-coded by severity
- **Detail Modal**: Full AI analysis view
- **Actions**: Review, dismiss, escalate incidents

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Docker Desktop** (for Milvus)
- **OpenAI API Key** (get from https://platform.openai.com)

### Installation

1. **Clone or navigate to the project:**
```bash
cd C:\Users\sumod\SOC-ASTRA
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment:**
Create a `.env` file in the project root:
```env
# Required
OPENAI_API_KEY=sk-your-actual-api-key-here
OPENAI_MODEL=gpt-4o

# Web Server
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=False

# Knowledge Base
ENABLE_RAG=true
SEED_CONFIG_PATH=./seed_ips.yaml
KNOWLEDGE_BASE_COLLECTION=soc_knowledge_base

# Milvus
MILVUS_HOST=localhost
MILVUS_PORT=19530

# Analysis
ANALYSIS_WORKERS=2
RAG_BATCH_SIZE=100

# Database
DATABASE_PATH=./data/incidents.db
```

4. **Customize IPs (Optional):**
Edit `seed_ips.yaml` with your network's IP addresses:
```yaml
internal_ips:
  - 10.0.1.10      # Your Domain Controller
  - 10.0.1.20      # Your File Server
  # Add more...

external_ips:
  - 203.0.113.50   # Known attacker IP
  # Add more...

suspicious_internal_ips:
  - 10.0.1.99      # Potentially compromised host
```

---

## ▶️ How to Start

### Quick Start (Recommended)

**Single command to do everything:**
```bash
python launcher.py
```

This will automatically:
1. ✅ Check environment configuration
2. ✅ Start Docker containers (Milvus, etcd, minio, attu)
3. ✅ Wait for Milvus to be ready
4. ✅ Clean up old collections
5. ✅ Auto-generate synthetic events from `seed_ips.yaml`
6. ✅ Ingest events into Milvus
7. ✅ Build IP behavioral profiles
8. ✅ Start the web application

**Dashboard will be available at:** http://localhost:5000

### Manual Start (Step by Step)

If you prefer manual control:

1. **Start Docker:**
```bash
python launcher.py --menu
# Select option 2: Setup Docker Only
```

2. **Start Web Application:**
```bash
python launcher.py --menu
# Select option 4: Run Web Application
```

Or directly:
```bash
python web_app.py
```

### Using the Launcher Menu

For full control:
```bash
python launcher.py --menu
```

**Menu Options:**
1. 🚀 **Quick Start** - Setup + Run everything
2. 🐳 **Setup Docker Only** - Start containers
3. 🧹 **Cleanup Milvus Collections** - Remove old data
4. ▶️ **Run Web Application** - Start dashboard
5. 📊 **Show System Status** - Check everything
6. ⏸️ **Stop Docker** - Stop containers
7. 🔄 **Restart Docker** - Restart containers
8. 🗑️ **Reset Docker** - Remove all data (fresh start)
9. 🔧 **Check Environment Config** - Verify .env
0. ❌ **Exit**

---

## ⏹️ How to Stop

### Stop Web Application Only

**Press `Ctrl+C`** in the terminal where `web_app.py` is running.

**Note:** Docker containers will keep running in the background. This is intentional - you can restart the web app quickly without waiting for containers to initialize.

### Stop Everything (Web App + Docker)

**Option 1: Using Launcher**
```bash
python launcher.py --menu
# Select option 6: Stop Docker
```

**Option 2: Direct Command**
```bash
docker compose stop
# or
docker-compose stop
```

### Complete Reset (Remove All Data)

**Warning:** This deletes all Milvus data and incidents!

```bash
python launcher.py --menu
# Select option 8: Reset Docker (Remove Volumes)
# Type "yes" to confirm
```

This runs: `docker compose down -v` which removes:
- All containers
- All volumes (Milvus data, etcd data, minio data)
- All network configurations

---

## 🔄 How Everything Works Together

### Startup Sequence

1. **Launcher starts** (`launcher.py`)
   - Checks prerequisites
   - Starts Docker containers
   - Waits for Milvus readiness

2. **Web app initializes** (`web_app.py`)
   - Connects to SQLite database (creates if needed)
   - Connects to Milvus
   - Initializes RAG Manager
   - Checks for existing knowledge base

3. **Auto-Seeding (First Run Only)**
   - If no knowledge base exists:
     - Loads `seed_ips.yaml`
     - Generates 500-1500 synthetic security events
     - Creates attack chains (recon → exploit → lateral movement → exfil)
     - Ingests into Milvus vector database
     - Builds IP behavioral profiles
   - If knowledge base exists:
     - Loads existing collection
     - Uses existing IP profiles

4. **Worker Threads Start**
   - 2 analysis workers (configurable)
   - Each worker waits for logs in queue

5. **Web Server Starts**
   - Flask server on port 5000
   - Dashboard available at http://localhost:5000
   - API endpoint ready at http://localhost:5000/api/ingest

### Real-Time Processing Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. External System Sends Log                                │
│    POST http://localhost:5000/api/ingest                    │
│    {                                                         │
│      "timestamp": "2025-11-19T10:30:00Z",                   │
│      "event_type": "Failed Login",                          │
│      "source_ip": "203.0.113.50",                           │
│      "dest_ip": "10.0.1.10",                                │
│      "username": "admin",                                   │
│      "raw_log": "Failed login attempt"                      │
│    }                                                         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Flask Receives Log                                       │
│    - Validates JSON                                         │
│    - Adds to LogQueue                                       │
│    - Returns 202 Accepted immediately                       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Worker Thread Picks Up Log                               │
│    - Pulls from queue                                       │
│    - Normalizes log format                                  │
│    - Generates alert_id if missing                          │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. RAG Context Retrieval (if enabled)                       │
│    - Converts log to text                                   │
│    - Searches Milvus for similar incidents (top 5)         │
│    - Retrieves IP behavioral profile                        │
│    - Builds enriched context                                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. AI Analysis (LangChain)                                  │
│    - Creates prompt with:                                   │
│      * Historical context (RAG)                             │
│      * IP behavioral profile                                │
│      * Current log data                                     │
│    - Sends to OpenAI GPT-4 via LangChain                    │
│    - Receives structured analysis                           │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. Result Processing                                        │
│    - Merges log + analysis                                  │
│    - Sets status to "new"                                   │
│    - Stores in SQLite database                              │
│    - Adds to batch for RAG update (every 100 logs)         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. Dashboard Display                                        │
│    - JavaScript polls /api/incidents every 5 seconds        │
│    - New incidents appear automatically                     │
│    - Color-coded by severity                                │
│    - Shows AI analysis summary                              │
└─────────────────────────────────────────────────────────────┘
```

### RAG (Retrieval-Augmented Generation) Explained

**What is RAG?**
RAG enhances AI analysis by providing historical context. Instead of analyzing each log in isolation, the system:

1. **Searches** for similar past incidents in Milvus
2. **Retrieves** relevant context (what happened before, how it was handled)
3. **Enriches** the current analysis with this knowledge
4. **Generates** more accurate, context-aware assessments

**Example:**

**Without RAG:**
```
Log: Failed login from 203.0.113.50
Analysis: "Single failed login. Could be typo or attack. Monitor for more attempts."
Severity: MEDIUM
Confidence: 60%
```

**With RAG:**
```
Log: Failed login from 203.0.113.50

RAG Context Retrieved:
- IP Profile: 203.0.113.50 has 89 previous failed login attempts
- Similar Incident: Same IP brute-forced admin account last week
- Historical Pattern: This IP is known attacker, always targets DC-1

Analysis: "This IP has a documented history of brute force attacks targeting 
administrative accounts. 89 previous failed attempts show sustained credential 
attack pattern. High confidence this is an active attack in progress."
Severity: CRITICAL
Confidence: 94%
```

### IP Behavioral Profiling

The system builds profiles for each IP address:

**Profile Contains:**
- Total event count
- Event type distribution
- Severity distribution
- MITRE techniques used
- First seen / Last seen timestamps
- Internal vs External classification
- Ports accessed
- Usernames targeted
- **Risk Score** (0-100)

**How It's Used:**
- New logs from known IPs get enriched with their history
- High-risk IPs get flagged immediately
- Attack patterns are identified across multiple events
- Context helps AI make better decisions

---

## 📡 API Reference

### POST /api/ingest

**Ingest a new security log**

**Request:**
```bash
curl -X POST http://localhost:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-11-19T10:30:00Z",
    "event_type": "Failed Login",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "username": "admin",
    "hostname": "DC-1",
    "raw_log": "Failed login attempt"
  }'
```

**Response:**
```json
{
  "status": "accepted",
  "message": "Log queued for analysis"
}
```

**Status Codes:**
- `202 Accepted`: Log queued successfully
- `400 Bad Request`: Invalid JSON
- `503 Service Unavailable`: Queue full

### GET /api/incidents

**Get incidents with filters**

**Query Parameters:**
- `limit`: Max incidents (default: 100)
- `offset`: Pagination offset (default: 0)
- `severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `status`: Filter by status (new, reviewed, dismissed, escalated)
- `source_ip`: Filter by source IP

**Example:**
```bash
curl "http://localhost:5000/api/incidents?severity=CRITICAL&limit=10"
```

**Response:**
```json
{
  "incidents": [...],
  "total": 150,
  "limit": 10,
  "offset": 0
}
```

### GET /api/incident/<id>

**Get single incident details**

**Example:**
```bash
curl http://localhost:5000/api/incident/1
```

**Response:**
```json
{
  "id": 1,
  "alert_id": "SOC-20251119-0001",
  "severity": "HIGH",
  "confidence": 92,
  "threat_type": "Brute Force Attack",
  "mitre_attack": "T1110.001 - Password Guessing",
  "analysis": "...",
  "recommendation": "...",
  "ioc_indicators": ["203.0.113.50"],
  ...
}
```

### POST /api/incident/<id>/action

**Update incident status**

**Request:**
```bash
curl -X POST http://localhost:5000/api/incident/1/action \
  -H "Content-Type: application/json" \
  -d '{"action": "reviewed"}'
```

**Actions:**
- `reviewed`: Mark as reviewed
- `dismissed`: Mark as false positive
- `escalated`: Flag for senior analyst

### GET /api/stats

**Get system statistics**

**Response:**
```json
{
  "database": {
    "total_incidents": 150,
    "incidents_last_24h": 45,
    "severity_counts": {
      "CRITICAL": 5,
      "HIGH": 15,
      "MEDIUM": 20,
      "LOW": 5
    }
  },
  "processor": {
    "queue": {
      "queue_size": 2,
      "total_received": 150,
      "total_processed": 148
    },
    "workers": [...]
  }
}
```

### GET /api/health

**Health check endpoint**

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "ai_copilot": "ready",
  "rag": "enabled",
  "workers": 2,
  "queue_size": 0
}
```

---

## 🧪 Testing

### Test Log Ingestion

**Run the test script:**
```bash
python test_ingest.py
```

**Test Modes:**
1. **Real-Time Stream** (60 seconds, continuous)
2. **Custom Real-Time Stream** (your duration/interval)
3. **Batch Test** (10 sample logs)
4. **Burst Test** (20 logs rapidly)

**What It Does:**
- Sends realistic security events
- Simulates various attack scenarios
- Shows real-time progress
- Displays success rate

**Watch the Dashboard:**
Open http://localhost:5000 in your browser to see incidents appear in real-time!

---

## 🔧 Configuration

### Environment Variables (.env)

**Required:**
```env
OPENAI_API_KEY=sk-your-key-here
```

**Web Server:**
```env
FLASK_HOST=0.0.0.0          # Bind address
FLASK_PORT=5000            # Port number
FLASK_DEBUG=False          # Debug mode
```

**Knowledge Base:**
```env
ENABLE_RAG=true                           # Use RAG for analysis
SEED_CONFIG_PATH=./seed_ips.yaml         # IP configuration
KNOWLEDGE_BASE_COLLECTION=soc_knowledge_base  # Milvus collection name
```

**Milvus:**
```env
MILVUS_HOST=localhost
MILVUS_PORT=19530
```

**Analysis:**
```env
ANALYSIS_WORKERS=2        # Number of worker threads
RAG_BATCH_SIZE=100        # Batch size for RAG updates
```

**Database:**
```env
DATABASE_PATH=./data/incidents.db
```

### Performance Tuning

**High Volume (>100 logs/min):**
```env
ANALYSIS_WORKERS=4        # More workers
RAG_BATCH_SIZE=200       # Larger batches
```

**Low Resources:**
```env
ANALYSIS_WORKERS=1       # Fewer workers
OPENAI_MODEL=gpt-3.5-turbo  # Faster model
```

**Speed Over Accuracy:**
```env
ENABLE_RAG=false         # Disable RAG (2x faster, less context)
```

---

## 📊 Dashboard Usage

### Main Features

**Statistics Panel:**
- Total incidents (last 24 hours)
- Count by severity (Critical/High/Medium/Low)
- Live queue size

**Filter Bar:**
- **Severity**: All, Critical, High, Medium, Low
- **Status**: New, Reviewed, Dismissed, Escalated
- **IP Search**: Filter by source IP address

**Incident Feed:**
- Auto-refreshes every 5 seconds
- Color-coded by severity:
  - 🔴 **Critical** - Immediate action required
  - 🟠 **High** - Urgent investigation needed
  - 🟡 **Medium** - Review when possible
  - 🔵 **Low** - Monitor

**Incident Cards Show:**
- Alert ID and timestamp
- Source/Destination IPs
- Username and hostname
- MITRE ATT&CK technique
- AI confidence score
- Analysis summary
- Quick actions

**Click Any Incident:**
- Full AI analysis
- Complete recommendations
- All IOC indicators
- Raw log data
- Related incidents (same IP)

**Actions:**
- 👁️ **View Details**: See full analysis
- ✅ **Mark Reviewed**: Flag as reviewed
- ❌ **Dismiss**: Mark as false positive
- 🚨 **Escalate**: Flag for senior analyst

---

## 🔍 Troubleshooting

### Common Issues

**1. "Failed to connect to Milvus"**

**Solution:**
```bash
# Check if Docker is running
docker ps

# Start Docker
python launcher.py --menu
# Select option 2: Setup Docker Only

# Or restart
docker compose restart
```

**2. "OPENAI_API_KEY not found"**

**Solution:**
- Create `.env` file in project root
- Add: `OPENAI_API_KEY=sk-your-key-here`
- Restart web app

**3. "No incidents appearing"**

**Check:**
```bash
# Check if logs are being received
curl http://localhost:5000/api/stats

# Check queue size (should be 0 after processing)
# Check worker status
```

**4. "Slow processing"**

**Solutions:**
- Increase workers: `ANALYSIS_WORKERS=4`
- Use faster model: `OPENAI_MODEL=gpt-3.5-turbo`
- Disable RAG: `ENABLE_RAG=false`

**5. "Dashboard not refreshing"**

**Check:**
- Ensure "Auto-refresh" checkbox is enabled
- Check browser console (F12) for errors
- Verify server: `curl http://localhost:5000/api/health`

**6. "Milvus node mismatch error"**

**Solution:**
```bash
python launcher.py --menu
# Select option 8: Reset Docker
# Type "yes" to confirm
# Then option 1: Quick Start
```

**7. "Pydantic import errors"**

**Solution:**
```bash
# Reinstall with latest versions
pip install --upgrade -r requirements.txt
```

---

## 📁 Project Structure

```
SOC-ASTRA/
├── launcher.py              # Unified launcher (setup, cleanup, run)
├── web_app.py               # Main Flask application
├── database.py              # SQLite operations
├── log_processor.py         # Queue & worker threads
├── rag_module.py            # RAG implementation
├── main.py                  # AI copilot (LangChain integration)
├── soc_agent.py            # Original CLI tool
├── seed_knowledge_base.py  # Synthetic event generator
├── event_templates.py      # Event type templates
├── test_ingest.py          # Testing script
├── seed_ips.yaml           # IP configuration
├── docker-compose.yml       # Docker services
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (create this)
├── templates/
│   └── dashboard.html      # Dashboard UI
├── static/
│   ├── css/
│   │   └── styles.css      # Styling
│   └── js/
│       └── dashboard.js    # Frontend logic
└── data/
    └── incidents.db        # SQLite database (auto-created)
```

---

## 🔐 Security Considerations

### Network Security

- **Internal Use Only**: Designed for trusted internal networks
- **No Authentication**: By design (add if deploying publicly)
- **Bind Address**: Default `0.0.0.0` (all interfaces) - restrict for production

### Adding Authentication (Optional)

If deploying on public network, add to `web_app.py`:

```python
API_KEY = os.getenv("API_KEY", "your-secret-key")

@app.before_request
def authenticate():
    if request.path.startswith('/api/'):
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != f'Bearer {API_KEY}':
            return jsonify({'error': 'Unauthorized'}), 401
```

Then send logs with:
```bash
curl -X POST http://localhost:5000/api/ingest \
  -H "Authorization: Bearer your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{...}'
```

### Data Storage

- **SQLite**: All incidents stored locally
- **Milvus**: Vector data stored in Docker volumes
- **Backup**: Regularly backup `./data/incidents.db`

---

## 🎓 Understanding the AI Analysis

### How AI Analyzes Logs

1. **Input Processing**
   - Log normalized to standard format
   - Text representation created
   - Metadata extracted

2. **Context Enrichment (RAG)**
   - Similar past incidents retrieved
   - IP behavioral profile loaded
   - Historical patterns identified

3. **AI Prompt Construction**
   ```
   System: You are a Tier-1 SOC analyst...
   
   User: 
   HISTORICAL CONTEXT:
   [Similar incidents from RAG]
   [IP behavioral profile]
   
   CURRENT EVENT:
   [Current log data]
   
   Analyze and provide structured assessment.
   ```

4. **Structured Output**
   - Pydantic model ensures consistent format
   - All fields validated
   - JSON response guaranteed

5. **Post-Processing**
   - Confidence scores normalized
   - Severity thresholds applied
   - Auto-escalate logic evaluated

### MITRE ATT&CK Mapping

The AI automatically maps threats to MITRE ATT&CK framework:

**Examples:**
- `T1110.001` - Brute Force: Password Guessing
- `T1021.002` - Remote Services: SMB/Windows Admin Shares
- `T1003.001` - OS Credential Dumping: LSASS Memory
- `T1041` - Exfiltration Over C2 Channel

This helps:
- Standardize threat classification
- Enable threat hunting
- Track attack patterns
- Generate compliance reports

---

## 📈 Performance Metrics

### Expected Throughput

- **Analysis Rate**: 5-10 logs/second (with 2 workers)
- **API Response**: <100ms (log acceptance)
- **AI Analysis**: 2-5 seconds per log
- **Dashboard Refresh**: Every 5 seconds

### Scaling

**Horizontal Scaling:**
- Run multiple web app instances
- Use load balancer
- Share SQLite database (or migrate to PostgreSQL)

**Vertical Scaling:**
- Increase `ANALYSIS_WORKERS`
- Use faster OpenAI model
- Increase server resources

---

## 🚀 Integration Examples

### Splunk Integration

**Configure Splunk HTTP Event Collector:**
```
output {
  http {
    url => "http://your-soc-astra:5000/api/ingest"
    http_method => "post"
    format => "json"
  }
}
```

### ELK Stack Integration

**Logstash Configuration:**
```ruby
output {
  http {
    url => "http://your-soc-astra:5000/api/ingest"
    http_method => "post"
    format => "json"
  }
}
```

### Python Script

```python
import requests
from datetime import datetime

log = {
    "timestamp": datetime.now().isoformat(),
    "event_type": "Failed Login",
    "source_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "username": "admin",
    "raw_log": "Failed login attempt"
}

response = requests.post(
    'http://localhost:5000/api/ingest',
    json=log
)
print(response.json())
```

### PowerShell

```powershell
$log = @{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    event_type = "Failed Login"
    source_ip = "192.168.1.100"
    dest_ip = "10.0.0.5"
    username = "admin"
    raw_log = "Failed login attempt"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5000/api/ingest" `
    -Method Post `
    -ContentType "application/json" `
    -Body $log
```

---

## 📚 Advanced Usage

### Custom Event Templates

Edit `event_templates.py` to add new event types:

```python
class CustomTemplate(EventTemplate):
    @staticmethod
    def my_custom_event(source_ip, target_ip):
        return {
            "timestamp": EventTemplate.random_timestamp(),
            "event_type": "My Custom Event",
            "source_ip": source_ip,
            "dest_ip": target_ip,
            # ... your fields
        }
```

### Custom Analysis Prompts

Edit `main.py` in `AISOCCopilot.analyze_with_ai()` to customize prompts:

```python
prompt_template = ChatPromptTemplate.from_messages([
    ("system", "Your custom system prompt..."),
    ("user", "Your custom user prompt...")
])
```

### Database Queries

Direct database access:

```python
from database import IncidentDatabase

db = IncidentDatabase()
incidents = db.get_incidents(severity=['CRITICAL', 'HIGH'])
stats = db.get_statistics()
```

---

## 🆘 Support & Troubleshooting

### Check System Status

```bash
# Health check
curl http://localhost:5000/api/health

# Statistics
curl http://localhost:5000/api/stats

# Docker status
docker compose ps

# Milvus logs
docker compose logs milvus
```

### Reset Everything

**Complete fresh start:**
```bash
python launcher.py --menu
# Option 8: Reset Docker
# Option 1: Quick Start
```

### View Logs

**Web app logs:** Terminal output where you ran `web_app.py`

**Docker logs:**
```bash
docker compose logs -f
```

**Database:** `./data/incidents.db` (use SQLite browser)

---

## 📝 License & Credits

**Developer:** Luckychowdary  
**Powered by:**
- OpenAI GPT-4o
- LangChain
- Milvus Vector Database
- Flask
- MORDOR Security Datasets

**License:** Internal Use

---

## 🎯 Quick Reference

### Start Everything
```bash
python launcher.py
```

### Stop Web App
```
Press Ctrl+C
```

### Stop Docker
```bash
docker compose stop
```

### Reset Everything
```bash
python launcher.py --menu
# Option 8: Reset Docker
```

### Test System
```bash
python test_ingest.py
```

### Dashboard
```
http://localhost:5000
```

### API Endpoint
```
POST http://localhost:5000/api/ingest
```

---

**That's everything! You now have a complete understanding of SOC-ASTRA. 🚀**

For questions or issues, check the troubleshooting section or review the code comments in each module.

