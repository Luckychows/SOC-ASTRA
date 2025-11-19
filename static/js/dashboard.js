// Dashboard JavaScript for SOC-ASTRA
// Handles real-time updates, filtering, and user interactions

// Global state
let state = {
    incidents: [],
    filters: {
        severity: null,
        status: '',
        sourceIp: ''
    },
    autoRefresh: true,
    refreshInterval: 5000,
    refreshTimer: null
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadIncidents();
    loadStats();
    startAutoRefresh();
});

// Event Listeners
function initializeEventListeners() {
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', handleSeverityFilter);
    });
    
    // Status filter
    document.getElementById('statusFilter').addEventListener('change', (e) => {
        state.filters.status = e.target.value;
        loadIncidents();
    });
    
    // IP search
    document.getElementById('ipSearch').addEventListener('input', (e) => {
        state.filters.sourceIp = e.target.value;
        debounce(() => loadIncidents(), 500)();
    });
    
    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', () => {
        loadIncidents();
        loadStats();
        showToast('Refreshed');
    });
    
    // Auto-refresh toggle
    document.getElementById('autoRefresh').addEventListener('change', (e) => {
        state.autoRefresh = e.target.checked;
        if (state.autoRefresh) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });
    
    // Modal close
    document.getElementById('modalClose').addEventListener('click', closeModal);
    
    // Click outside modal to close
    document.getElementById('incidentModal').addEventListener('click', (e) => {
        if (e.target.id === 'incidentModal') {
            closeModal();
        }
    });
}

// Severity Filter Handler
function handleSeverityFilter(e) {
    const btn = e.target;
    const severity = btn.dataset.severity;
    
    // Update active state
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Update filter
    state.filters.severity = severity === 'all' ? null : severity;
    
    // Reload incidents
    loadIncidents();
}

// Load Incidents
async function loadIncidents() {
    try {
        // Build query params
        const params = new URLSearchParams({
            limit: 100,
            offset: 0
        });
        
        if (state.filters.severity) {
            params.append('severity', state.filters.severity);
        }
        
        if (state.filters.status) {
            params.append('status', state.filters.status);
        }
        
        if (state.filters.sourceIp) {
            params.append('source_ip', state.filters.sourceIp);
        }
        
        // Fetch incidents
        const response = await fetch(`/api/incidents?${params}`);
        const data = await response.json();
        
        state.incidents = data.incidents || [];
        
        // Render incidents
        renderIncidents();
        
    } catch (error) {
        console.error('Error loading incidents:', error);
        showToast('Error loading incidents', 'error');
    }
}

// Render Incidents
function renderIncidents() {
    const container = document.getElementById('incidentList');
    const loadingState = document.getElementById('loadingState');
    const emptyState = document.getElementById('emptyState');
    
    // Hide loading
    loadingState.style.display = 'none';
    
    if (state.incidents.length === 0) {
        // Show empty state
        emptyState.style.display = 'block';
        
        // Remove existing incident cards
        container.querySelectorAll('.incident-card').forEach(card => card.remove());
        return;
    }
    
    // Hide empty state
    emptyState.style.display = 'none';
    
    // Clear and render incidents
    container.querySelectorAll('.incident-card').forEach(card => card.remove());
    
    state.incidents.forEach(incident => {
        const card = createIncidentCard(incident);
        container.appendChild(card);
    });
}

// Create Incident Card
function createIncidentCard(incident) {
    const card = document.createElement('div');
    card.className = `incident-card ${incident.severity.toLowerCase()}`;
    card.dataset.incidentId = incident.id;
    
    const severityClass = incident.severity.toLowerCase();
    const timestamp = new Date(incident.timestamp).toLocaleString();
    const createdAt = new Date(incident.created_at).toLocaleString();
    
    card.innerHTML = `
        <div class="incident-header">
            <div class="incident-title">
                <span class="severity-badge ${severityClass}">${incident.severity}</span>
                <strong>${incident.event_type}</strong>
            </div>
            <div style="text-align: right; color: #8b9cb6; font-size: 12px;">
                <div>ID: ${incident.alert_id}</div>
                <div>${timestamp}</div>
            </div>
        </div>
        
        <div class="incident-meta">
            <div class="meta-item">
                <span>🌐</span>
                <span>${incident.source_ip} → ${incident.dest_ip}</span>
            </div>
            <div class="meta-item">
                <span>👤</span>
                <span>${incident.username}</span>
            </div>
            <div class="meta-item">
                <span>💻</span>
                <span>${incident.hostname}</span>
            </div>
            <div class="meta-item">
                <span>📊</span>
                <span>${incident.confidence}% confidence</span>
            </div>
        </div>
        
        <div class="incident-body">
            ${incident.mitre_attack && incident.mitre_attack !== 'N/A' ? 
                `<div class="mitre-tag">🎯 ${incident.mitre_attack}</div>` : ''}
            <p><strong>Threat:</strong> ${incident.threat_type}</p>
            <p><strong>Analysis:</strong> ${truncateText(incident.analysis, 200)}</p>
            <p><strong>Recommendation:</strong> ${truncateText(incident.recommendation, 150)}</p>
        </div>
        
        <div class="incident-actions">
            <button class="btn-action" onclick="viewIncident(${incident.id})">
                👁️ View Details
            </button>
            <button class="btn-action success" onclick="updateStatus(${incident.id}, 'reviewed')">
                ✅ Mark Reviewed
            </button>
            <button class="btn-action danger" onclick="updateStatus(${incident.id}, 'dismissed')">
                ❌ Dismiss
            </button>
            ${incident.auto_escalate ? 
                `<button class="btn-action" onclick="updateStatus(${incident.id}, 'escalated')" style="background: rgba(255, 153, 68, 0.2); border-color: #ff9944; color: #ff9944;">
                    🚨 Escalate
                </button>` : ''}
        </div>
    `;
    
    return card;
}

// View Incident Details
async function viewIncident(incidentId) {
    try {
        const response = await fetch(`/api/incident/${incidentId}`);
        const incident = await response.json();
        
        if (incident.error) {
            showToast('Incident not found', 'error');
            return;
        }
        
        // Render modal content
        const modalBody = document.getElementById('modalBody');
        const modalTitle = document.getElementById('modalTitle');
        
        modalTitle.textContent = `Incident: ${incident.alert_id}`;
        
        modalBody.innerHTML = `
            <div style="margin-bottom: 20px;">
                <h3 style="margin-bottom: 10px;">Basic Information</h3>
                <table style="width: 100%; color: #e8eaed;">
                    <tr><td style="padding: 8px; color: #8b9cb6;">Event Type:</td><td style="padding: 8px;">${incident.event_type}</td></tr>
                    <tr><td style="padding: 8px; color: #8b9cb6;">Timestamp:</td><td style="padding: 8px;">${new Date(incident.timestamp).toLocaleString()}</td></tr>
                    <tr><td style="padding: 8px; color: #8b9cb6;">Source IP:</td><td style="padding: 8px;">${incident.source_ip}</td></tr>
                    <tr><td style="padding: 8px; color: #8b9cb6;">Destination IP:</td><td style="padding: 8px;">${incident.dest_ip}</td></tr>
                    <tr><td style="padding: 8px; color: #8b9cb6;">Username:</td><td style="padding: 8px;">${incident.username}</td></tr>
                    <tr><td style="padding: 8px; color: #8b9cb6;">Hostname:</td><td style="padding: 8px;">${incident.hostname}</td></tr>
                </table>
            </div>
            
            <div style="margin-bottom: 20px;">
                <h3 style="margin-bottom: 10px;">AI Analysis</h3>
                <div style="background: #0f1419; padding: 15px; border-radius: 6px; margin-bottom: 10px;">
                    <div style="margin-bottom: 10px;"><strong>Severity:</strong> <span class="severity-badge ${incident.severity.toLowerCase()}">${incident.severity}</span></div>
                    <div style="margin-bottom: 10px;"><strong>Confidence:</strong> ${incident.confidence}%</div>
                    <div style="margin-bottom: 10px;"><strong>Threat Type:</strong> ${incident.threat_type}</div>
                    <div style="margin-bottom: 10px;"><strong>MITRE ATT&CK:</strong> ${incident.mitre_attack}</div>
                    <div style="margin-bottom: 10px;"><strong>IP Reputation:</strong> ${incident.ip_reputation}</div>
                </div>
                <p style="margin-bottom: 10px;"><strong>Analysis:</strong></p>
                <p style="background: #0f1419; padding: 15px; border-radius: 6px;">${incident.analysis}</p>
                <p style="margin-top: 10px;"><strong>Recommendation:</strong></p>
                <p style="background: #0f1419; padding: 15px; border-radius: 6px;">${incident.recommendation}</p>
            </div>
            
            ${incident.ioc_indicators && incident.ioc_indicators.length > 0 ? `
                <div style="margin-bottom: 20px;">
                    <h3 style="margin-bottom: 10px;">IOC Indicators</h3>
                    <ul style="background: #0f1419; padding: 15px; border-radius: 6px; list-style: none;">
                        ${incident.ioc_indicators.map(ioc => `<li style="padding: 5px;">🚨 ${ioc}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${incident.raw_log ? `
                <div style="margin-bottom: 20px;">
                    <h3 style="margin-bottom: 10px;">Raw Log</h3>
                    <pre style="background: #0f1419; padding: 15px; border-radius: 6px; overflow-x: auto; color: #8b9cb6;">${incident.raw_log}</pre>
                </div>
            ` : ''}
        `;
        
        // Show modal
        document.getElementById('incidentModal').style.display = 'block';
        
    } catch (error) {
        console.error('Error loading incident details:', error);
        showToast('Error loading details', 'error');
    }
}

// Update Incident Status
async function updateStatus(incidentId, action) {
    try {
        const response = await fetch(`/api/incident/${incidentId}/action`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showToast(`Incident ${action}`, 'success');
            loadIncidents();
        } else {
            showToast(result.error || 'Action failed', 'error');
        }
        
    } catch (error) {
        console.error('Error updating incident:', error);
        showToast('Error updating incident', 'error');
    }
}

// Load Statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        // Update stats
        const db = data.database;
        document.getElementById('totalIncidents').textContent = db.incidents_last_24h || 0;
        document.getElementById('criticalCount').textContent = db.severity_counts.CRITICAL || 0;
        document.getElementById('highCount').textContent = db.severity_counts.HIGH || 0;
        document.getElementById('mediumCount').textContent = db.severity_counts.MEDIUM || 0;
        document.getElementById('lowCount').textContent = db.severity_counts.LOW || 0;
        
        // Update queue info
        const processor = data.processor;
        document.getElementById('queueSize').textContent = processor.queue.queue_size || 0;
        
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Auto-refresh
function startAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
    }
    
    state.refreshTimer = setInterval(() => {
        if (state.autoRefresh) {
            loadIncidents();
            loadStats();
        }
    }, state.refreshInterval);
}

function stopAutoRefresh() {
    if (state.refreshTimer) {
        clearInterval(state.refreshTimer);
        state.refreshTimer = null;
    }
}

// Modal Functions
function closeModal() {
    document.getElementById('incidentModal').style.display = 'none';
}

// Toast Notification
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Utility Functions
function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

// Make functions global for onclick handlers
window.viewIncident = viewIncident;
window.updateStatus = updateStatus;




