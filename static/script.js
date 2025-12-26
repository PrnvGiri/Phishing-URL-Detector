document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    document.getElementById('year').textContent = new Date().getFullYear();

    // Accordion Logic
    const accBtn = document.getElementById('deepScanToggle');
    const accContent = document.getElementById('deepScanContent');
    const chevron = accBtn.querySelector('.chevron');

    accBtn.addEventListener('click', () => {
        const isClosed = accContent.classList.contains('hidden');
        if (isClosed) {
            accContent.classList.remove('hidden');
            chevron.setAttribute('data-lucide', 'chevron-up');
        } else {
            accContent.classList.add('hidden');
            chevron.setAttribute('data-lucide', 'chevron-down');
        }
        lucide.createIcons();
    });
});

document.getElementById('analyzeBtn').addEventListener('click', analyzeUrl);
document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeUrl();
});

let riskChart = null;

async function analyzeUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;

    // Reset UI
    document.getElementById('result').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.remove('hidden');
    document.body.classList.remove('is-safe', 'is-phishing');
    document.getElementById('deepScanContent').classList.add('hidden'); // Close accordion on new scan

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (response.ok) {
            showResult(data);
        } else {
            showError(data.error || 'Something went wrong.');
        }

    } catch (err) {
        showError('Network error. Is the server running?');
    } finally {
        document.getElementById('loading').classList.add('hidden');
    }
}

function showResult(data) {
    const resultDiv = document.getElementById('result');
    resultDiv.classList.remove('hidden');

    const isPhishing = data.result === 'Phishing';
    const container = document.body;

    const icon = document.getElementById('verdictIcon');
    const title = document.getElementById('resultTitle');
    const desc = document.getElementById('resultDesc');
    const probVal = document.getElementById('probValue');
    const reasonsBox = document.getElementById('reasonsContainer');
    const reasonsList = document.getElementById('reasonsList');

    container.classList.remove('is-safe', 'is-phishing');

    const probability = (data.probability * 100).toFixed(1);
    probVal.textContent = `${probability}%`;

    if (isPhishing) {
        container.classList.add('is-phishing');
        title.textContent = 'THREAT DETECTED';
        desc.textContent = 'This URL exhibits malicious behavior.';
        icon.setAttribute('data-lucide', 'alert-octagon');

        if (data.reasons && data.reasons.length > 0) {
            reasonsBox.classList.remove('hidden');
            reasonsList.innerHTML = data.reasons.map(r => `<li>${r}</li>`).join('');
        } else {
            reasonsBox.classList.add('hidden');
        }
    } else {
        container.classList.add('is-safe');
        title.textContent = 'SAFE DESTINATION';
        desc.textContent = 'No known threats found.';
        icon.setAttribute('data-lucide', 'shield-check');
        reasonsBox.classList.add('hidden');
    }

    renderDomainInfo(data.domain_info);
    renderFeatures(data.features);
    renderChart(data);

    // NEW: Render Deep Scan Data
    renderDeepScan(data.dns_info, data.site_data);

    lucide.createIcons();
}

function renderDomainInfo(info) {
    const list = document.getElementById('domainInfoList');
    if (!info) { list.innerHTML = '<li>No info available</li>'; return; }
    list.innerHTML = `
        <li><strong>Registrar:</strong> <span>${info.registrar}</span></li>
        <li><strong>Org:</strong> <span>${info.org}</span></li>
        <li><strong>Country:</strong> <span>${info.country}</span></li>
        <li><strong>Created:</strong> <span>${info.creation_date}</span></li>
    `;
}

function renderFeatures(features) {
    const list = document.getElementById('featuresList');
    list.innerHTML = '';
    const featureMap = { 'URLLength': 'Length', 'NoOfSubDomain': 'Subdomains', 'SuspiciousKeywords': 'Keywords', 'Entropy': 'Entropy', 'IsHTTPS': 'HTTPS' };
    for (const [key, label] of Object.entries(featureMap)) {
        if (features[key] !== undefined) {
            let val = features[key];
            if (key === 'Entropy') val = val.toFixed(2);
            if (key === 'IsHTTPS') val = val === 1 ? 'Yes' : 'No';
            list.innerHTML += `<li><strong>${label}</strong> <span>${val}</span></li>`;
        }
    }
}

function renderDeepScan(dns, site) {
    // DNS
    const dnsBox = document.getElementById('dnsContainer');
    let dnsHtml = '';
    if (dns) {
        for (const [type, records] of Object.entries(dns)) {
            if (records && records.length > 0) {
                // Limit to first 2 records per type to save space
                const show = records.slice(0, 2).join('<br>');
                dnsHtml += `<div class="dns-record"><span class="record-type">${type}</span> ${show}</div>`;
            }
        }
    }
    dnsBox.innerHTML = dnsHtml || 'No DNS records found.';

    // Site Data
    const siteList = document.getElementById('siteDataList');
    siteList.innerHTML = '';
    if (site) {
        siteList.innerHTML += `<li><strong>Title:</strong> <span>${site.title}</span></li>`;
        siteList.innerHTML += `<li><strong>Server:</strong> <span>${site.server_header}</span></li>`;
        siteList.innerHTML += `<li><strong>Login Form:</strong> <span style="color: ${site.has_login_form ? '#f43f5e' : '#10b981'}">${site.has_login_form ? 'DETECTED' : 'None'}</span></li>`;
    }
}

function renderChart(data) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    if (riskChart) riskChart.destroy();
    const f = data.features;
    const isPhishing = data.result === 'Phishing';
    const bg = isPhishing ? 'rgba(244, 63, 94, 0.4)' : 'rgba(16, 185, 129, 0.4)';
    const border = isPhishing ? '#f43f5e' : '#10b981';
    const dataPoints = [Math.min(10, (f.SuspiciousKeywords || 0) * 5), Math.min(10, (f.Entropy || 0) * 1.5), Math.min(10, (f.URLLength / 100) * 10), Math.min(10, (f.NoOfOtherSpecialCharsInURL || 0) * 2), isPhishing ? 9 : 1];
    riskChart = new Chart(ctx, {
        type: 'radar',
        data: { labels: ['Keywords', 'Entropy', 'Length', 'Complex', 'AI Score'], datasets: [{ label: 'Threat Vector', data: dataPoints, backgroundColor: bg, borderColor: border, pointBackgroundColor: '#fff', pointBorderColor: border }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { r: { angleLines: { color: 'rgba(255,255,255,0.1)' }, grid: { color: 'rgba(255,255,255,0.1)' }, pointLabels: { color: '#94a3b8', font: { size: 10 } }, suggestedMin: 0, suggestedMax: 10, ticks: { display: false } } }, plugins: { legend: { display: false } } }
    });
}

function showError(msg) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = msg;
    errorDiv.classList.remove('hidden');
}
