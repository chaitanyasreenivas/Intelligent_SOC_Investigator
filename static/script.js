// --- NEW: Chart variables ---
let alertChart = null; // Doughnut
let topAlertsChart = null; // Bar
let alertsOverTimeChart = null; // Line

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all charts
    renderAlertChart(0, 0, 0); 
    renderTopAlertsChart([]); // Init with empty data
    renderAlertsOverTimeChart({ labels: [], data: [] }); // Init with empty data
    
    // Start live monitoring
    fetchAlerts(); // Fetch immediately
    setInterval(fetchAlerts, 5000); // Fetch every 5 seconds
});

/**
 * Fetches alerts and all analysis data from the backend
 */
async function fetchAlerts() {
    const statusLight = document.getElementById('status-light');
    const statusText = document.getElementById('status-text');

    try {
        const response = await fetch('/api/alerts');
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        // --- NEW: Get all data from the response ---
        const data = await response.json();
        
        // Update charts, KPIs, and alert columns
        renderAlerts(data.alerts); // Pass just the alerts list
        
        // --- NEW: Render the new charts ---
        renderTopAlertsChart(data.top_5_alerts);
        renderAlertsOverTimeChart(data.time_series);

        // Update status indicator to LIVE
        statusLight.classList.remove('error');
        statusLight.classList.add('live');
        statusText.textContent = "Live Monitoring Active";

    } catch (error) {
        console.error("Could not fetch alerts:", error);
        // Update status indicator to ERROR
        statusLight.classList.remove('live');
        statusLight.classList.add('error');
        statusText.textContent = "Connection Lost";
    }
}

/**
 * Renders alerts into 3 columns AND updates KPI cards
 */
function renderAlerts(alerts) {
    const highContainer = document.querySelector('#alerts-high .alert-column-content');
    const mediumContainer = document.querySelector('#alerts-medium .alert-column-content');
    const lowContainer = document.querySelector('#alerts-low .alert-column-content');

    highContainer.innerHTML = '';
    mediumContainer.innerHTML = '';
    lowContainer.innerHTML = '';

    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;

    // We still call renderAlertChart from here, as it's based on the counts
    alerts.forEach(alert => {
        // 'category' is added by the backend
        switch (alert.category) {
            case 'High': highCount++; break;
            case 'Medium': medCount++; break;
            case 'Low': lowCount++; break;
        }
    });
    
    // Reverse to show newest on top
    alerts.reverse().forEach(alert => {
        const card = createAlertCard(alert);
        switch (alert.category) {
            case 'High': highContainer.appendChild(card); break;
            case 'Medium': mediumContainer.appendChild(card); break;
            case 'Low': lowContainer.appendChild(card); break;
        }
    });

    if (highCount === 0) highContainer.innerHTML = '<p>No high alerts.</p>';
    if (medCount === 0) mediumContainer.innerHTML = '<p>No medium alerts.</p>';
    if (lowCount === 0) lowContainer.innerHTML = '<p>No low alerts.</p>';

    // --- Update KPI Cards ---
    document.getElementById('kpi-high-count').textContent = highCount;
    document.getElementById('kpi-medium-count').textContent = medCount;
    document.getElementById('kpi-low-count').textContent = lowCount;

    // --- Update the Doughnut Chart ---
    renderAlertChart(highCount, medCount, lowCount);
}

/**
 * Renders or updates the main doughnut chart
 */
function renderAlertChart(high, med, low) {
    const ctx = document.getElementById('alert-chart').getContext('2d');
    const data = {
        labels: ['High', 'Medium', 'Low'],
        datasets: [{
            label: 'Alerts',
            data: [high, med, low],
            backgroundColor: ['#e74c3c', '#f39c12', '#2ecc71'],
            borderColor: '#ffffff',
            borderWidth: 3
        }]
    };
    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right',
                labels: { font: { size: 14, family: 'Inter' } }
            },
            title: {
                display: true,
                text: 'Alert Severity Distribution',
                font: { size: 16, family: 'Inter', weight: '600' },
                color: '#333'
            }
        }
    };

    if (alertChart) alertChart.destroy();
    alertChart = new Chart(ctx, { type: 'doughnut', data: data, options: options });
}

// --- NEW: Renders Top 5 Alerts Bar Chart ---
function renderTopAlertsChart(topAlerts) {
    const ctx = document.getElementById('top-alerts-chart').getContext('2d');
    const labels = topAlerts.map(item => {
        // Truncate long labels
        let label = item[0];
        if (label.length > 30) {
            label = label.substring(0, 30) + '...';
        }
        return label;
    });
    const data = topAlerts.map(item => item[1]);

    if (topAlertsChart) topAlertsChart.destroy();
    topAlertsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alert Count',
                data: data,
                backgroundColor: [
                    'rgba(231, 76, 60, 0.7)',
                    'rgba(243, 156, 18, 0.7)',
                    'rgba(52, 152, 219, 0.7)',
                    'rgba(155, 89, 182, 0.7)',
                    'rgba(46, 204, 113, 0.7)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y', // Horizontal bar chart
            plugins: {
                legend: { display: false },
                title: { display: false }
            },
            scales: {
                x: { 
                    beginAtZero: true,
                    ticks: {
                        // Ensure only whole numbers are shown on axis
                        precision: 0
                    }
                }
            }
        }
    });
}

// --- NEW: Renders Alerts Over Time Line Chart ---
function renderAlertsOverTimeChart(timeSeries) {
    const ctx = document.getElementById('alerts-over-time-chart').getContext('2d');
    if (alertsOverTimeChart) alertsOverTimeChart.destroy();
    alertsOverTimeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeSeries.labels,
            datasets: [{
                label: 'Alerts per Hour',
                data: timeSeries.data,
                fill: true,
                borderColor: 'rgb(0, 123, 255)',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                title: { display: false }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    ticks: {
                        // Show fewer labels if there are too many
                        autoSkip: true,
                        maxTicksLimit: 10
                    }
                }
            }
        }
    });
}


/**
 * Helper: Creates a single alert card element
 */
function createAlertCard(alert) {
    const card = document.createElement('div');
    card.className = `alert-card ${alert.category}`;
    card.dataset.alertId = alert.rule.id + (alert.timestamp || '');
    const alertText = document.createElement('p');
    alertText.textContent = alert.rule.description;
    const alertSubText = document.createElement('span');
    const userName = alert.data?.win?.eventdata?.TargetUserName || 'N/A';
    const ipAddress = alert.data?.win?.eventdata?.IpAddress || 'N/A';
    alertSubText.textContent = `User: ${userName}, IP: ${ipAddress}`;
    const investigateButton = document.createElement('button');
    investigateButton.textContent = 'Investigate';
    investigateButton.onclick = () => handleInvestigate(alert);
    card.appendChild(investigateButton);
    card.appendChild(alertText);
    card.appendChild(alertSubText);
    return card;
}

/**
 * UPDATED: This function no longer shows a panel.
 * It opens a new browser tab and passes the alert data to it.
 */
async function handleInvestigate(alert) {
    try {
        const alertString = JSON.stringify(alert);
        // Base64-encode the string to make it URL-safe
        const encodedAlert = btoa(alertString);
        window.open(`/investigation?alert=${encodedAlert}`, '_blank');
    } catch (error) {
        console.error("Failed to open investigation window:", error);
    }
}