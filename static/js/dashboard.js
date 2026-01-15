/**
 * PhalanxAI Dashboard JavaScript
 */

// API base URL
const API_BASE = '/api';

// State
let currentPage = 'dashboard';
let alertsPage = 1;
let attackChart = null;
let hourlyChart = null;
let trafficChart = null;
let refreshInterval = null;

// Real-time traffic state
let trafficEventSource = null;
let trafficData = {
    labels: [],
    pps: [],
    benign: [],
    malicious: []
};
let isStreamPaused = false;
const MAX_DATA_POINTS = 60;

/**
 * Initialize the dashboard
 */
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initEventListeners();
    checkHealth();
    loadDashboardData();
    initTrafficStream();
    
    // Auto-refresh every 30 seconds
    refreshInterval = setInterval(() => {
        if (currentPage === 'dashboard') {
            loadDashboardData();
        } else if (currentPage === 'alerts') {
            loadAlerts();
        }
    }, 30000);
});

/**
 * Initialize navigation
 */
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });
    
    // View all link
    document.querySelectorAll('.view-all').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(link.dataset.page);
        });
    });
}

/**
 * Navigate to a page
 */
function navigateTo(page) {
    currentPage = page;
    
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
    
    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });
    document.getElementById(`page-${page}`).classList.add('active');
    
    // Update header
    const titles = {
        dashboard: 'Dashboard',
        alerts: 'Alerts',
        mitre: 'MITRE ATT&CK',
        analyze: 'Analyze Traffic',
        models: 'ML Models'
    };
    document.getElementById('page-title').textContent = titles[page] || 'Dashboard';
    
    // Load page-specific data
    if (page === 'alerts') {
        loadAlerts();
    } else if (page === 'mitre') {
        loadMitreMatrix();
    } else if (page === 'models') {
        loadModelInfo();
    }
}

/**
 * Initialize event listeners
 */
function initEventListeners() {
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadDashboardData();
        showNotification('Data refreshed', 'success');
    });
    
    // Train button
    document.getElementById('train-btn').addEventListener('click', trainModels);
    document.getElementById('start-training-btn').addEventListener('click', trainModels);
    
    // Generate demo alerts
    document.getElementById('generate-demo-btn').addEventListener('click', generateDemoAlerts);
    
    // Export alerts
    const exportBtn = document.getElementById('export-alerts-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            window.location.href = `${API_BASE}/alerts/export`;
        });
    }
    
    // Analyze form
    document.getElementById('analyze-form').addEventListener('submit', analyzeTraffic);
    
    // Modal close
    document.getElementById('close-modal').addEventListener('click', closeModal);
    document.getElementById('alert-modal').addEventListener('click', (e) => {
        if (e.target.id === 'alert-modal') closeModal();
    });
    
    // Technique details close
    document.getElementById('close-technique').addEventListener('click', () => {
        document.getElementById('technique-details').style.display = 'none';
    });
    
    // Filters
    document.getElementById('severity-filter').addEventListener('change', loadAlerts);
    document.getElementById('status-filter').addEventListener('change', loadAlerts);
    
    // Traffic stream toggle
    const toggleBtn = document.getElementById('toggle-stream-btn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', toggleTrafficStream);
    }
    
    // Mobile Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    if (sidebarToggle && sidebar && overlay) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
        });
        
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
        });
        
        // Close sidebar when clicking a nav item on mobile
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    sidebar.classList.remove('open');
                    overlay.classList.remove('active');
                }
            });
        });
    }
    
    // Network monitor controls
    const startMonitorBtn = document.getElementById('start-monitor-btn');
    const stopMonitorBtn = document.getElementById('stop-monitor-btn');
    
    if (startMonitorBtn) {
        startMonitorBtn.addEventListener('click', startNetworkMonitor);
    }
    if (stopMonitorBtn) {
        stopMonitorBtn.addEventListener('click', stopNetworkMonitor);
    }
    
    // Load available interfaces
    loadNetworkInterfaces();
}

/**
 * Check system health
 */
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();
        
        const statusDot = document.getElementById('system-status');
        const statusText = document.getElementById('status-text');
        
        if (data.status === 'healthy') {
            statusDot.className = 'status-dot online';
            statusText.textContent = data.models_loaded ? 'Models Ready' : 'Models Not Loaded';
        } else {
            statusDot.className = 'status-dot offline';
            statusText.textContent = 'System Error';
        }
    } catch (error) {
        document.getElementById('system-status').className = 'status-dot offline';
        document.getElementById('status-text').textContent = 'Offline';
    }
}

/**
 * Load dashboard data
 */
async function loadDashboardData() {
    try {
        const [statsResponse, alertsResponse] = await Promise.all([
            fetch(`${API_BASE}/stats`),
            fetch(`${API_BASE}/alerts?page=1&page_size=10`)
        ]);
        
        const stats = await statsResponse.json();
        const alertsData = await alertsResponse.json();
        
        // Update stats cards
        document.getElementById('stat-critical').textContent = stats.critical_count || 0;
        document.getElementById('stat-high').textContent = stats.high_count || 0;
        document.getElementById('stat-medium').textContent = stats.medium_count || 0;
        document.getElementById('stat-low').textContent = stats.low_count || 0;
        
        // Update badge
        document.getElementById('alert-badge').textContent = stats.total_alerts || 0;
        
        // Update charts
        updateAttackChart(stats.top_attack_types || {});
        updateHourlyChart(stats.hourly_distribution || {});
        
        // Update recent alerts
        updateRecentAlerts(alertsData.alerts || []);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

/**
 * Update attack distribution chart
 */
function updateAttackChart(data) {
    const ctx = document.getElementById('attack-chart').getContext('2d');
    
    const labels = Object.keys(data);
    const values = Object.values(data);
    
    if (attackChart) {
        attackChart.destroy();
    }
    
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(249, 115, 22, 0.8)',
                    'rgba(234, 179, 8, 0.8)',
                    'rgba(34, 197, 94, 0.8)',
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(139, 92, 246, 0.8)'
                ],
                borderColor: 'rgba(15, 15, 26, 1)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#a0a0b0',
                        font: { size: 12 },
                        padding: 12
                    }
                }
            }
        }
    });
}

/**
 * Update hourly activity chart
 */
function updateHourlyChart(data) {
    const ctx = document.getElementById('hourly-chart').getContext('2d');
    
    const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
    const values = labels.map((_, i) => data[String(i)] || 0);
    
    if (hourlyChart) {
        hourlyChart.destroy();
    }
    
    hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alerts',
                data: values,
                backgroundColor: 'rgba(99, 102, 241, 0.6)',
                borderColor: 'rgba(99, 102, 241, 1)',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#6b6b7b', maxTicksLimit: 12 }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#6b6b7b' },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Update recent alerts table
 */
function updateRecentAlerts(alerts) {
    const tbody = document.getElementById('recent-alerts-body');
    
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">No alerts yet. Train models and generate demo data to see alerts.</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = alerts.map(alert => `
        <tr onclick="showAlertDetail(${alert.id})">
            <td>${formatTime(alert.timestamp)}</td>
            <td><span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
            <td>${alert.attack_type}</td>
            <td>${alert.src_ip || 'N/A'}</td>
            <td>${alert.dst_ip || 'N/A'}${alert.dst_port ? ':' + alert.dst_port : ''}</td>
            <td>${alert.mitre_technique_id ? `<a href="#" class="mitre-link" onclick="event.stopPropagation(); showTechnique('${alert.mitre_technique_id}')">${alert.mitre_technique_id}</a>` : '-'}</td>
            <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
        </tr>
    `).join('');
}

/**
 * Load alerts page
 */
async function loadAlerts() {
    const severity = document.getElementById('severity-filter').value;
    
    try {
        let url = `${API_BASE}/alerts?page=${alertsPage}&page_size=20`;
        if (severity) url += `&severity=${severity}`;
        
        const response = await fetch(url);
        const data = await response.json();
        
        const tbody = document.getElementById('all-alerts-body');
        
        if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="10">No alerts found. Generate demo alerts to populate this table.</td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = data.alerts.map(alert => `
            <tr>
                <td>#${alert.id}</td>
                <td>${formatTime(alert.timestamp)}</td>
                <td><span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
                <td>${alert.attack_type}</td>
                <td>${alert.src_ip || 'N/A'}</td>
                <td>${alert.dst_ip || 'N/A'}${alert.dst_port ? ':' + alert.dst_port : ''}</td>
                <td>${Math.round(alert.confidence * 100)}%</td>
                <td>${alert.mitre_technique_id ? `<a href="#" class="mitre-link" onclick="showTechnique('${alert.mitre_technique_id}')">${alert.mitre_technique_id}</a>` : '-'}</td>
                <td><span class="status-badge ${alert.status}">${alert.status}</span></td>
                <td><button class="action-btn view" onclick="showAlertDetail(${alert.id})">View</button></td>
            </tr>
        `).join('');
        
        // Update pagination
        updatePagination(data.total, data.page, data.page_size);
        
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

/**
 * Update pagination controls
 */
function updatePagination(total, page, pageSize) {
    const container = document.getElementById('alerts-pagination');
    const totalPages = Math.ceil(total / pageSize);
    
    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    let html = '';
    
    if (page > 1) {
        html += `<button onclick="goToPage(${page - 1})">← Prev</button>`;
    }
    
    for (let i = 1; i <= Math.min(totalPages, 5); i++) {
        html += `<button class="${i === page ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
    }
    
    if (page < totalPages) {
        html += `<button onclick="goToPage(${page + 1})">Next →</button>`;
    }
    
    container.innerHTML = html;
}

function goToPage(page) {
    alertsPage = page;
    loadAlerts();
}

/**
 * Show alert detail modal
 */
async function showAlertDetail(alertId) {
    try {
        const response = await fetch(`${API_BASE}/alerts/${alertId}`);
        const alert = await response.json();
        
        const modal = document.getElementById('alert-modal');
        const body = document.getElementById('alert-modal-body');
        
        body.innerHTML = `
            <div class="result-section">
                <div class="result-title">Attack Type</div>
                <div class="result-value ${alert.is_malicious ? 'malicious' : 'benign'}">
                    ${alert.attack_type}
                </div>
            </div>
            <div class="result-section">
                <div class="result-title">Severity</div>
                <span class="severity-badge ${alert.severity.toLowerCase()}">${alert.severity}</span>
                <span style="margin-left: 12px;">Confidence: ${Math.round(alert.confidence * 100)}%</span>
            </div>
            <div class="result-section">
                <div class="result-title">Network Details</div>
                <p>Source: ${alert.src_ip || 'N/A'}:${alert.src_port || 'N/A'}</p>
                <p>Destination: ${alert.dst_ip || 'N/A'}:${alert.dst_port || 'N/A'}</p>
            </div>
            ${alert.mitre ? `
            <div class="result-section">
                <div class="result-title">MITRE ATT&CK</div>
                <p><strong>${alert.mitre.primary_technique?.technique_id}</strong>: ${alert.mitre.primary_technique?.name}</p>
                <p>Tactic: ${alert.mitre.primary_technique?.tactic}</p>
                <p><a href="${alert.mitre.primary_technique?.url}" target="_blank" class="mitre-link">View on MITRE ATT&CK →</a></p>
            </div>
            ` : ''}
            <div class="result-section">
                <div class="result-title">Summary</div>
                <p>${alert.summary}</p>
            </div>
            ${alert.recommended_actions ? `
            <div class="result-section">
                <div class="result-title">Recommended Actions</div>
                <ul class="recommendation-list">
                    ${alert.recommended_actions.map(a => `<li>${a}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        `;
        
        modal.classList.add('active');
        
    } catch (error) {
        console.error('Error loading alert detail:', error);
        showNotification('Failed to load alert details', 'error');
    }
}

function closeModal() {
    document.getElementById('alert-modal').classList.remove('active');
}

/**
 * Load MITRE ATT&CK matrix
 */
async function loadMitreMatrix() {
    try {
        const response = await fetch(`${API_BASE}/mitre/matrix`);
        const data = await response.json();
        
        const container = document.getElementById('mitre-matrix');
        
        let html = '<div style="display: flex; gap: 12px; overflow-x: auto; padding-bottom: 12px;">';
        
        for (const [tacticId, tactic] of Object.entries(data.matrix)) {
            if (!tactic.techniques || tactic.techniques.length === 0) continue;
            
            html += `
                <div class="mitre-tactic">
                    <div class="mitre-tactic-header">${tactic.name}</div>
                    ${tactic.techniques.map(t => `
                        <div class="mitre-technique ${t.detected ? 'detected' : ''}" 
                             onclick="showTechnique('${t.id}')">
                            ${t.id}<br>
                            <small>${t.name}</small>
                        </div>
                    `).join('')}
                </div>
            `;
        }
        
        html += '</div>';
        container.innerHTML = html;
        
    } catch (error) {
        console.error('Error loading MITRE matrix:', error);
    }
}

/**
 * Show technique details
 */
async function showTechnique(techniqueId) {
    try {
        const response = await fetch(`${API_BASE}/mitre/technique/${techniqueId}`);
        const technique = await response.json();
        
        const panel = document.getElementById('technique-details');
        const content = document.getElementById('technique-content');
        
        document.getElementById('technique-name').textContent = `${technique.technique_id}: ${technique.name}`;
        
        content.innerHTML = `
            <div class="result-section">
                <div class="result-title">Tactic</div>
                <p>${technique.tactic}</p>
            </div>
            <div class="result-section">
                <div class="result-title">Description</div>
                <p>${technique.description}</p>
            </div>
            <div class="result-section">
                <div class="result-title">Detection</div>
                <p>${technique.detection}</p>
            </div>
            <div class="result-section">
                <div class="result-title">Mitigations</div>
                <ul class="recommendation-list">
                    ${technique.mitigations.map(m => `<li>${m}</li>`).join('')}
                </ul>
            </div>
            <div class="result-section">
                <a href="${technique.url}" target="_blank" class="btn btn-secondary">
                    View on MITRE ATT&CK →
                </a>
            </div>
        `;
        
        panel.style.display = 'block';
        
    } catch (error) {
        console.error('Error loading technique:', error);
    }
}

/**
 * Load model info
 */
async function loadModelInfo() {
    try {
        const response = await fetch(`${API_BASE}/model-info`);
        const info = await response.json();
        
        // Random Forest
        const rfStats = document.getElementById('rf-stats');
        if (info.random_forest) {
            rfStats.innerHTML = `
                <span class="model-status loaded">Loaded</span>
                <p style="margin-top: 12px; font-size: 13px; color: var(--text-secondary);">
                    Classes: ${info.random_forest.n_classes}<br>
                    Features: ${info.random_forest.n_features}
                </p>
            `;
        } else {
            rfStats.innerHTML = '<span class="model-status not-loaded">Not Loaded</span>';
        }
        
        // Isolation Forest
        const ifStats = document.getElementById('if-stats');
        if (info.isolation_forest) {
            ifStats.innerHTML = `
                <span class="model-status loaded">Loaded</span>
                <p style="margin-top: 12px; font-size: 13px; color: var(--text-secondary);">
                    Threshold: ${info.isolation_forest.threshold.toFixed(4)}<br>
                    Features: ${info.isolation_forest.n_features}
                </p>
            `;
        } else {
            ifStats.innerHTML = '<span class="model-status not-loaded">Not Loaded</span>';
        }
        
        // Autoencoder
        const aeStats = document.getElementById('ae-stats');
        if (info.autoencoder) {
            aeStats.innerHTML = `
                <span class="model-status loaded">Loaded</span>
                <p style="margin-top: 12px; font-size: 13px; color: var(--text-secondary);">
                    Input Dim: ${info.autoencoder.input_dim}<br>
                    Encoding: ${info.autoencoder.encoding_dim}
                </p>
            `;
        } else {
            aeStats.innerHTML = '<span class="model-status not-loaded">Not Loaded</span>';
        }
        
    } catch (error) {
        console.error('Error loading model info:', error);
    }
}

/**
 * Train models
 */
async function trainModels() {
    const sampleSize = document.getElementById('training-samples')?.value || 5000;
    const logDiv = document.getElementById('training-log');
    const logContent = document.getElementById('log-content');
    
    if (logDiv) {
        logDiv.style.display = 'block';
        logContent.textContent = 'Starting training...\n';
    }
    
    showNotification('Training started...', 'info');
    
    try {
        const response = await fetch(`${API_BASE}/train`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                use_sample_data: true,
                sample_size: parseInt(sampleSize)
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            if (logContent) {
                logContent.textContent += `\nTraining completed in ${result.training_time_seconds.toFixed(2)}s\n`;
                logContent.textContent += `\nRandom Forest: ${JSON.stringify(result.metrics.random_forest, null, 2)}\n`;
                logContent.textContent += `\nIsolation Forest: ${JSON.stringify(result.metrics.isolation_forest, null, 2)}\n`;
                logContent.textContent += `\nAutoencoder: ${JSON.stringify(result.metrics.autoencoder, null, 2)}\n`;
            }
            
            showNotification('Models trained successfully!', 'success');
            checkHealth();
            loadModelInfo();
        } else {
            throw new Error(result.message || 'Training failed');
        }
        
    } catch (error) {
        console.error('Training error:', error);
        if (logContent) {
            logContent.textContent += `\nError: ${error.message}\n`;
        }
        showNotification('Training failed: ' + error.message, 'error');
    }
}

/**
 * Generate demo alerts
 */
async function generateDemoAlerts() {
    showNotification('Generating demo alerts...', 'info');
    
    try {
        const response = await fetch(`${API_BASE}/demo/generate-alerts?count=20`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        showNotification(result.message, 'success');
        loadAlerts();
        loadDashboardData();
        
    } catch (error) {
        console.error('Error generating demo alerts:', error);
        showNotification('Failed to generate alerts. Train models first.', 'error');
    }
}

/**
 * Analyze traffic
 */
async function analyzeTraffic(e) {
    e.preventDefault();
    
    const formData = {
        src_ip: document.getElementById('src_ip').value || null,
        dst_ip: document.getElementById('dst_ip').value || null,
        src_port: parseInt(document.getElementById('src_port').value) || null,
        "Destination Port": parseInt(document.getElementById('dst_port').value) || 80,
        "Flow Duration": parseFloat(document.getElementById('flow_duration').value) || 1000000,
        "Total Fwd Packets": parseInt(document.getElementById('total_fwd_packets').value) || 10,
        "Total Backward Packets": parseInt(document.getElementById('total_bwd_packets').value) || 8,
        "Flow Bytes/s": parseFloat(document.getElementById('flow_bytes_s').value) || 5000,
        "Flow Packets/s": parseFloat(document.getElementById('flow_packets_s').value) || 100,
        "SYN Flag Count": parseInt(document.getElementById('syn_flag_count').value) || 1
    };
    
    try {
        const response = await fetch(`${API_BASE}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        const resultDiv = document.getElementById('analysis-result');
        const content = document.getElementById('result-content');
        
        content.innerHTML = `
            <div class="result-section">
                <div class="result-title">Classification</div>
                <div class="result-value ${result.is_malicious ? 'malicious' : 'benign'}">
                    ${result.attack_type}
                </div>
            </div>
            <div class="result-section">
                <div class="result-title">Severity</div>
                <span class="severity-badge ${result.severity.toLowerCase()}">${result.severity}</span>
                <span style="margin-left: 12px;">Confidence: ${Math.round(result.confidence * 100)}%</span>
            </div>
            ${result.mitre_technique_id ? `
            <div class="result-section">
                <div class="result-title">MITRE ATT&CK</div>
                <p><strong>${result.mitre_technique_id}</strong>: ${result.mitre_technique_name}</p>
                <p>Tactic: ${result.mitre_tactic}</p>
            </div>
            ` : ''}
            ${result.recommended_actions && result.is_malicious ? `
            <div class="result-section">
                <div class="result-title">Recommended Actions</div>
                <ul class="recommendation-list">
                    ${result.recommended_actions.slice(0, 4).map(a => `<li>${a}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        `;
        
        resultDiv.style.display = 'block';
        
    } catch (error) {
        console.error('Analysis error:', error);
        showNotification('Analysis failed. Make sure models are trained.', 'error');
    }
}

/**
 * Utility functions
 */
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + 
           ' ' + date.toLocaleDateString();
}

function showNotification(message, type = 'info') {
    // Simple notification using console for now
    // Could be extended to show toast notifications
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // Create temporary toast notification
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: ${type === 'success' ? 'var(--low)' : type === 'error' ? 'var(--critical)' : 'var(--accent-primary)'};
        color: white;
        padding: 14px 24px;
        border-radius: 8px;
        font-size: 14px;
        z-index: 9999;
        animation: fadeIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Make functions available globally
window.showAlertDetail = showAlertDetail;
window.showTechnique = showTechnique;
window.goToPage = goToPage;


// ============ Real-Time Traffic Streaming ============

/**
 * Initialize real-time traffic stream
 */
function initTrafficStream() {
    const canvas = document.getElementById('traffic-chart');
    if (!canvas) return;
    
    // Initialize chart
    const ctx = canvas.getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Packets/s',
                    data: [],
                    borderColor: 'rgba(99, 102, 241, 1)',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    yAxisID: 'y'
                },
                {
                    label: 'Benign Flows',
                    data: [],
                    borderColor: 'rgba(34, 197, 94, 1)',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.4,
                    pointRadius: 0,
                    yAxisID: 'y1'
                },
                {
                    label: 'Malicious Flows',
                    data: [],
                    borderColor: 'rgba(239, 68, 68, 1)',
                    backgroundColor: 'rgba(239, 68, 68, 0.3)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 300
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#a0a0b0',
                        font: { size: 11 },
                        boxWidth: 12,
                        padding: 16
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { 
                        color: '#6b6b7b',
                        maxTicksLimit: 10,
                        font: { size: 10 }
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#6b6b7b' },
                    title: {
                        display: true,
                        text: 'Packets/s',
                        color: '#6b6b7b'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#6b6b7b' },
                    title: {
                        display: true,
                        text: 'Flows',
                        color: '#6b6b7b'
                    }
                }
            }
        }
    });
    
    // Start SSE connection
    connectTrafficStream();
}

/**
 * Connect to SSE traffic stream
 */
function connectTrafficStream() {
    if (trafficEventSource) {
        trafficEventSource.close();
    }
    
    // Use the unified monitor/stream endpoint (handles both real and simulated data)
    trafficEventSource = new EventSource(`${API_BASE}/monitor/stream`);
    
    trafficEventSource.onmessage = (event) => {
        if (isStreamPaused) return;
        
        try {
            const data = JSON.parse(event.data);
            updateTrafficMetrics(data);
            
            // Only update chart if we have data (not idle)
            if (data.status !== 'idle') {
                updateTrafficChart(data);
            }
            
            // Update status indicator based on whether it's simulation or real
            const statusText = document.getElementById('monitor-status-text');
            const indicator = document.getElementById('live-indicator');
            
            if (data.status === 'idle') {
                if (statusText) statusText.textContent = 'READY';
                indicator?.classList.remove('capturing');
            } else if (data.simulation) {
                if (statusText) statusText.textContent = 'SIMULATION';
                indicator?.classList.remove('capturing');
            } else {
                // Real data! Update UI accordingly
                if (statusText && !statusText.textContent.includes('LIVE')) {
                    statusText.textContent = 'LIVE';
                }
                indicator?.classList.add('capturing');
            }
            
            // Flash on spike/attack
            if (data.is_spike || data.malicious_flows > 5) {
                flashTrafficMonitor();
            }
            
            // Update alerts if new
            if (data.new_alerts > 0) {
                document.getElementById('alert-badge').textContent = data.total_alerts;
                // Refresh alerts table
                loadAlerts();
            }
            
        } catch (e) {
            console.error('Error parsing traffic data:', e);
        }
    };
    
    trafficEventSource.onerror = () => {
        console.log('Traffic stream disconnected, reconnecting...');
        setTimeout(connectTrafficStream, 3000);
    };
}

/**
 * Update traffic metrics display
 */
function updateTrafficMetrics(data) {
    const ppsEl = document.getElementById('metric-pps');
    const mbpsEl = document.getElementById('metric-mbps');
    const flowsEl = document.getElementById('metric-flows');
    const threatEl = document.getElementById('metric-threat');
    
    if (ppsEl) ppsEl.textContent = formatNumber(data.packets_per_second);
    if (mbpsEl) mbpsEl.textContent = data.mbps.toFixed(1);
    if (flowsEl) flowsEl.textContent = data.total_flows;
    if (threatEl) threatEl.textContent = data.malicious_percentage.toFixed(1) + '%';
}

/**
 * Update real-time traffic chart
 */
function updateTrafficChart(data) {
    if (!trafficChart) return;
    
    const time = new Date(data.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    
    // Add new data points
    trafficData.labels.push(time);
    trafficData.pps.push(data.packets_per_second);
    trafficData.benign.push(data.benign_flows);
    trafficData.malicious.push(data.malicious_flows);
    
    // Trim to MAX_DATA_POINTS
    if (trafficData.labels.length > MAX_DATA_POINTS) {
        trafficData.labels.shift();
        trafficData.pps.shift();
        trafficData.benign.shift();
        trafficData.malicious.shift();
    }
    
    // Update chart
    trafficChart.data.labels = trafficData.labels;
    trafficChart.data.datasets[0].data = trafficData.pps;
    trafficChart.data.datasets[1].data = trafficData.benign;
    trafficChart.data.datasets[2].data = trafficData.malicious;
    trafficChart.update('none');
}

/**
 * Toggle traffic stream pause/resume
 */
function toggleTrafficStream() {
    isStreamPaused = !isStreamPaused;
    
    const btn = document.getElementById('toggle-stream-btn');
    const indicator = document.getElementById('live-indicator');
    
    if (isStreamPaused) {
        btn.textContent = 'Resume';
        indicator.classList.add('paused');
        indicator.querySelector('.pulse').nextSibling.textContent = ' PAUSED';
    } else {
        btn.textContent = 'Pause';
        indicator.classList.remove('paused');
        indicator.querySelector('.pulse').nextSibling.textContent = ' LIVE';
    }
}

/**
 * Flash traffic monitor on spike/attack
 */
function flashTrafficMonitor() {
    const monitor = document.querySelector('.traffic-monitor');
    if (monitor) {
        monitor.classList.add('spike');
        setTimeout(() => monitor.classList.remove('spike'), 500);
    }
}

/**
 * Format large numbers with K/M suffix
 */
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (trafficEventSource) {
        trafficEventSource.close();
    }
});


// ============ Network Monitor Controls ============

let monitorRunning = false;

/**
 * Load available network interfaces
 */
async function loadNetworkInterfaces() {
    try {
        const response = await fetch(`${API_BASE}/monitor/interfaces`);
        const data = await response.json();
        
        const select = document.getElementById('interface-select');
        if (!select) {
            console.log('Interface select element not found');
            return;
        }
        
        console.log('Loading interfaces:', data);
        
        if (data.available && data.interfaces && data.interfaces.length > 0) {
            select.innerHTML = '<option value="">Select Interface</option>';
            
            // Add primary interfaces first (eth, wlan, en)
            const primary = data.interfaces.filter(iface => 
                iface.startsWith('eth') || iface.startsWith('wlan') || 
                iface.startsWith('en') || iface.startsWith('wl')
            );
            
            primary.forEach(iface => {
                select.innerHTML += `<option value="${iface}">${iface}</option>`;
            });
            
            // Add separator if we have primary interfaces
            if (primary.length > 0) {
                select.innerHTML += '<option value="" disabled>──────────</option>';
            }
            
            // Add other interfaces
            data.interfaces.forEach(iface => {
                if (!primary.includes(iface)) {
                    select.innerHTML += `<option value="${iface}">${iface}</option>`;
                }
            });
            
            console.log('Interfaces loaded successfully');
        } else {
            select.innerHTML = '<option value="">No interfaces available</option>';
            select.disabled = true;
            const startBtn = document.getElementById('start-monitor-btn');
            if (startBtn) startBtn.disabled = true;
            console.log('No interfaces available or capture not supported');
        }
        
        // Check if monitor is already running
        checkMonitorStatus();
        
    } catch (error) {
        console.error('Error loading interfaces:', error);
        const select = document.getElementById('interface-select');
        if (select) {
            select.innerHTML = '<option value="">Error loading</option>';
        }
    }
}

/**
 * Check current monitor status
 */
async function checkMonitorStatus() {
    try {
        const response = await fetch(`${API_BASE}/monitor/status`);
        const data = await response.json();
        
        if (data.running) {
            monitorRunning = true;
            updateMonitorUI(true, data.interface);
        }
    } catch (error) {
        console.error('Error checking monitor status:', error);
    }
}

/**
 * Start network monitoring
 */
async function startNetworkMonitor() {
    const interfaceSelect = document.getElementById('interface-select');
    const selectedInterface = interfaceSelect.value;
    
    if (!selectedInterface) {
        showNotification('Please select a network interface', 'warning');
        return;
    }
    
    showNotification(`Starting capture on ${selectedInterface}...`, 'info');
    
    try {
        const response = await fetch(`${API_BASE}/monitor/start?interface=${selectedInterface}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            monitorRunning = true;
            
            // Reset pause state so graph updates
            isStreamPaused = false;
            const toggleBtn = document.getElementById('toggle-stream-btn');
            if (toggleBtn) toggleBtn.textContent = 'Pause';
            
            updateMonitorUI(true, data.interface);
            showNotification(`Network monitoring started on ${data.interface}`, 'success');
            
            // Reconnect to real stream
            if (trafficEventSource) {
                trafficEventSource.close();
            }
            connectTrafficStream();
        } else {
            if (response.status === 403) {
                showNotification('Permission denied. Run server with sudo for packet capture.', 'error');
            } else {
                showNotification(data.detail || 'Failed to start monitoring', 'error');
            }
        }
    } catch (error) {
        console.error('Error starting monitor:', error);
        showNotification('Failed to start network monitoring', 'error');
    }
}

/**
 * Stop network monitoring
 */
async function stopNetworkMonitor() {
    showNotification('Stopping network capture...', 'info');
    
    try {
        const response = await fetch(`${API_BASE}/monitor/stop`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        monitorRunning = false;
        updateMonitorUI(false);
        showNotification('Network monitoring stopped', 'success');
        
    } catch (error) {
        console.error('Error stopping monitor:', error);
        showNotification('Failed to stop monitoring', 'error');
    }
}

/**
 * Update monitor UI state
 */
function updateMonitorUI(running, interfaceName = null) {
    const startBtn = document.getElementById('start-monitor-btn');
    const stopBtn = document.getElementById('stop-monitor-btn');
    const interfaceSelect = document.getElementById('interface-select');
    const statusText = document.getElementById('monitor-status-text');
    const indicator = document.getElementById('live-indicator');
    
    if (running) {
        startBtn.style.display = 'none';
        stopBtn.style.display = 'inline-flex';
        interfaceSelect.disabled = true;
        statusText.textContent = `LIVE (${interfaceName || 'capturing'})`;
        indicator.classList.remove('paused');
        indicator.classList.add('capturing');
    } else {
        startBtn.style.display = 'inline-flex';
        stopBtn.style.display = 'none';
        interfaceSelect.disabled = false;
        statusText.textContent = 'SIMULATION';
        indicator.classList.remove('capturing');
    }
}


