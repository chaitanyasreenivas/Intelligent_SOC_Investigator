let globalAlertContext = null;
let globalLogsContext = null;

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const encodedAlert = params.get('alert');

    if (!encodedAlert) {
        document.getElementById('loading').textContent = 'Error: No alert data found in URL.';
        return;
    }

    try {
        const alertString = atob(encodedAlert);
        const alert = JSON.parse(alertString);
        
        globalAlertContext = JSON.stringify(alert);

        document.getElementById('alert-title').textContent = alert.rule.description;
        const ip = alert.data?.win?.eventdata?.IpAddress || 'N/A';
        const user = alert.data?.win?.eventdata?.TargetUserName || 'N/A';
        document.getElementById('alert-subtitle').textContent = `Target User: ${user} | Attacker IP: ${ip}`;

        fetchInvestigationDetails(alert);

    } catch (e) {
        console.error("Error", e);
        document.getElementById('loading').textContent = 'Error decoding alert data.';
    }
});

function cleanAIOutput(text) {
    if (!text) return "";
    let clean = text.replace(/```html/g, '').replace(/```/g, '');
    if (clean.includes("TRUE Positive")) {
        clean = clean.replace(/TRUE Positive/g, '<span class="verdict-badge verdict-true">🚨 True Positive</span>');
    } else if (clean.includes("FALSE Positive")) {
        clean = clean.replace(/FALSE Positive/g, '<span class="verdict-badge verdict-false">✅ False Positive</span>');
    }
    clean = clean.replace(/\n/g, '<br>'); 
    return clean;
}

async function fetchInvestigationDetails(alert) {
    try {
        const response = await fetch('/api/investigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(alert),
        });

        if (!response.ok) throw new Error(`API error: ${response.status}`);
        const data = await response.json();

        globalLogsContext = data.related_logs && data.related_logs.length > 0 
            ? data.related_logs.join('\n') 
            : "No related logs found.";

        // 1. Threat Intel
        renderThreatIntel(data.threat_intel);

        // 2. AI Analysis
        let analysisHtml = cleanAIOutput(data.analysis);
        analysisHtml = analysisHtml.replace(/(T\d{4}(\.\d{3})?)/g, '<span class="mitre-badge">$1</span>');
        analysisHtml = analysisHtml.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        document.getElementById('ai-analysis-content').innerHTML = analysisHtml;

        // 3. Playbook
        let playbookHtml = cleanAIOutput(data.playbook);
        playbookHtml = playbookHtml.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        document.getElementById('dynamic-playbook-content').innerHTML = playbookHtml;

        // 4. Logs
        document.getElementById('logs-content').textContent = globalLogsContext;

        // 5. Graph (Safe Mode)
        try {
            if (typeof vis !== 'undefined') {
                renderNetworkGraph(alert);
                // NEW: Render Timeline if we have logs
                if (data.related_logs && data.related_logs.length > 0) {
                    renderTimeline(data.related_logs);
                } else {
                    document.getElementById('timeline-visualization').innerHTML = '<p style="padding:20px; color:#777; text-align:center;">No log events to visualize.</p>';
                }
            }
        } catch (err) { console.error("Vis error", err); }

        document.getElementById('loading').style.display = 'none';
        document.getElementById('results-container').style.display = 'block';

    } catch (error) {
        console.error(error);
        document.getElementById('loading').textContent = `Analysis Failed: ${error.message}`;
    }
}

// --- NEW: Timeline Renderer ---
function renderTimeline(logs) {
    const container = document.getElementById('timeline-visualization');
    const items = new vis.DataSet();
    
    // Regex to find ISO-like timestamps (YYYY-MM-DD HH:MM:SS)
    // Adjust this regex if your logs are different!
    const timeRegex = /(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})/;

    logs.forEach((log, index) => {
        const match = log.match(timeRegex);
        if (match) {
            const timestamp = match[0];
            // Clean the log message (remove timestamp, truncate)
            let content = log.replace(timestamp, '').trim().substring(0, 50) + '...';
            
            items.add({
                id: index,
                content: content,
                start: timestamp
            });
        }
    });

    if (items.length === 0) {
        container.innerHTML = '<p style="padding:20px; color:#777; text-align:center;">Could not extract timestamps from logs.</p>';
        return;
    }

    const options = {
        height: '300px',
        zoomMin: 1000 * 60 * 60, // Min zoom 1 hour
        zoomMax: 1000 * 60 * 60 * 24 * 31 // Max zoom 1 month
    };

    new vis.Timeline(container, items, options);
}

function renderNetworkGraph(alert) {
    const container = document.getElementById('network-graph');
    
    const user = alert.data?.win?.eventdata?.TargetUserName || 'Unknown User';
    const ip = alert.data?.win?.eventdata?.IpAddress || 'External IP';
    const ruleName = alert.rule.description.substring(0, 20) + '...'; 
    const computer = alert.agent?.name || 'Server';

    const nodes = new vis.DataSet([
        { id: 1, label: ruleName, color: '#e74c3c', shape: 'box', font: { color: 'white' }, size: 20 }, 
        { id: 2, label: user, color: '#3498db', shape: 'ellipse', font: { color: 'white' } }, 
        { id: 3, label: ip, color: '#f1c40f', shape: 'ellipse' },   
        { id: 4, label: computer, color: '#95a5a6', shape: 'database' }
    ]);

    const edges = new vis.DataSet([
        { from: 3, to: 1, label: 'triggered', arrows: 'to' }, 
        { from: 2, to: 1, label: 'involved', arrows: 'to' },  
        { from: 1, to: 4, label: 'occurred on', arrows: 'to' }
    ]);

    const data = { nodes: nodes, edges: edges };
    const options = {
        nodes: { borderWidth: 2, shadow: true },
        edges: { width: 2, shadow: true, color: '#2c3e50', length: 200 },
        physics: { enabled: true, solver: 'forceAtlas2Based' },
        layout: { randomSeed: 2 }
    };
    
    new vis.Network(container, data, options);
}

function renderThreatIntel(ti) {
    const container = document.getElementById('ti-content');
    if (!ti) {
        container.innerHTML = `<p style="color: #777; font-style: italic;">No external threat intelligence found.</p>`;
        return;
    }
    const score = ti.abuseConfidenceScore;
    let colorClass = 'ti-safe';
    if (score > 20) colorClass = 'ti-warn';
    if (score > 80) colorClass = 'ti-risk';

    container.innerHTML = `
        <div class="ti-score">
            <span class="ti-score-val ${colorClass}">${score}%</span>
            <span class="ti-score-label">Abuse Confidence Score</span>
        </div>
        <div class="ti-grid">
            <div class="ti-item"><label>ISP</label><span>${ti.isp || 'N/A'}</span></div>
            <div class="ti-item"><label>Country</label><span>${ti.countryCode || 'N/A'}</span></div>
            <div class="ti-item"><label>Domain</label><span>${ti.domain || 'N/A'}</span></div>
            <div class="ti-item"><label>Usage</label><span>${ti.usageType || 'N/A'}</span></div>
        </div>
    `;
}

function generatePDF() {
    const element = document.body;
    const btn = document.querySelector('.btn-export');
    const chat = document.getElementById('copilot-widget');
    
    btn.style.display = 'none';
    chat.style.display = 'none';

    const opt = {
        margin: 0.2,
        filename: 'Investigation_Report.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
    };

    html2pdf().set(opt).from(element).save().then(() => {
        btn.style.display = 'flex';
        chat.style.display = 'block';
    });
}

/* --- Chat Logic --- */
function toggleChat() {
    const w = document.getElementById('copilot-window');
    const b = document.getElementById('copilot-toggle');
    if (w.style.display === 'none' || !w.style.display) {
        w.style.display = 'flex';
        b.style.display = 'none';
    } else {
        w.style.display = 'none';
        b.style.display = 'flex';
    }
}

function handleKeyPress(e) { if (e.key === 'Enter') sendMessage(); }

async function sendMessage() {
    const input = document.getElementById('user-input');
    const q = input.value.trim();
    if (!q) return;

    addMessageToUI(q, 'user-message');
    input.value = '';
    
    const loadingId = addMessageToUI('Thinking...', 'bot-message');

    try {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: q, alert_context: globalAlertContext, logs_context: globalLogsContext })
        });
        const data = await res.json();
        document.getElementById(loadingId).remove();
        addMessageToUI(data.answer, 'bot-message');
    } catch (error) {
        document.getElementById(loadingId).innerText = "Error talking to AI.";
    }
}

function addMessageToUI(text, className) {
    const div = document.getElementById('copilot-messages');
    const msg = document.createElement('div');
    msg.className = `message ${className}`;
    msg.innerHTML = text.replace(/\n/g, '<br>');
    msg.id = 'msg-' + Math.random().toString(36).substr(2, 9);
    div.appendChild(msg);
    div.scrollTop = div.scrollHeight;
    return msg.id;
}