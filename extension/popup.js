// popup.js
document.addEventListener('DOMContentLoaded', () => {
    const statusMessage = document.getElementById('threat-level');
    const urlDisplay = document.getElementById('url-display');
    const container = document.getElementById('hud-container');
    const canvas = document.getElementById('radarCanvas');
    const ctx = canvas.getContext('2d');

    const canvasSize = 240;
    const center = canvasSize / 2;
    const maxRadius = 90;
    
    // Labels for the 8 axes
    const axes = [
        "LENGTH", "DOTS", "HTTP", "HYPHENS",
        "DEPTH", "DIGITS", "AT_SYM", "KEYWORDS"
    ];

    // Helper: draw the static radar background
    const drawRadarBackground = (state = 'scanning') => {
        ctx.clearRect(0, 0, canvasSize, canvasSize);
        
        // HIGHER NEON OPACITY WHEN THREAT IDENTIFIED
        if (state === 'phishing') {
            ctx.strokeStyle = "rgba(255, 0, 60, 0.5)";
        } else if (state === 'safe') {
            ctx.strokeStyle = "rgba(0, 255, 204, 0.4)";
        } else {
            ctx.strokeStyle = "rgba(255, 255, 255, 0.2)";
        }
        
        ctx.lineWidth = 1;
        ctx.fillStyle = "rgba(255, 255, 255, 0.6)";
        ctx.font = "10px monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        // Draw concentric octagons
        for (let r = 1; r <= 3; r++) {
            const radius = (maxRadius / 3) * r;
            ctx.beginPath();
            for (let i = 0; i < 8; i++) {
                const angle = (Math.PI * 2 * i) / 8 - Math.PI / 2;
                const x = center + radius * Math.cos(angle);
                const y = center + radius * Math.sin(angle);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            }
            ctx.closePath();
            ctx.stroke();
        }

        // Draw axes lines and labels
        for (let i = 0; i < 8; i++) {
            const angle = (Math.PI * 2 * i) / 8 - Math.PI / 2;
            
            // Line
            ctx.beginPath();
            ctx.moveTo(center, center);
            const edgeX = center + maxRadius * Math.cos(angle);
            const edgeY = center + maxRadius * Math.sin(angle);
            ctx.lineTo(edgeX, edgeY);
            ctx.stroke();

            // Label
            const labelRadius = maxRadius + 15;
            const labelX = center + labelRadius * Math.cos(angle);
            const labelY = center + labelRadius * Math.sin(angle);
            ctx.fillText(axes[i], labelX, labelY);
        }
    };

    // Helper: normalize features to [0, 1] for radar chart
    const normalizeFeatures = (f) => {
        // Strict mathematical normalization per user spec
        return [
            Math.min(f.url_length / 120, 1.0),
            Math.min(f.num_dots / 5, 1.0),
            f.is_http,  // Binary flag, directly mapped
            Math.min(f.num_hyphens / 5, 1.0),
            Math.min(f.url_depth / 6, 1.0),
            Math.min(f.num_digits / 25, 1.0),
            f.has_at_symbol, // Binary flag, directly mapped
            f.contains_kw // Binary flag, directly mapped
        ];
    };

    // Helper: draw the data polygon
    const drawDataPolygon = (normalizedValues, state) => {
        ctx.beginPath();
        for (let i = 0; i < 8; i++) {
            const angle = (Math.PI * 2 * i) / 8 - Math.PI / 2;
            const radius = normalizedValues[i] * maxRadius;
            const x = center + radius * Math.cos(angle);
            const y = center + radius * Math.sin(angle);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.closePath();
        
        ctx.lineWidth = 2;
        if (state === 'phishing') {
            ctx.fillStyle = "rgba(255, 0, 60, 0.4)";
            ctx.strokeStyle = "#ff003c";
        } else if (state === 'safe') {
            ctx.fillStyle = "rgba(0, 255, 204, 0.4)";
            ctx.strokeStyle = "#00ffcc";
        } else {
            // Default blank/scanning
            ctx.fillStyle = "rgba(241, 196, 15, 0.4)";
            ctx.strokeStyle = "#f1c40f";
        }
        ctx.fill();
        ctx.stroke();
    };

    const updateUI = (state, message) => {
        statusMessage.textContent = message;
        
        container.classList.remove('scanning', 'safe', 'critical', 'error');
        if (state === 'phishing') {
            container.classList.add('critical');
        } else if (state === 'safe') {
            container.classList.add('safe');
        } else {
            container.classList.add(state);
        }
    };

    // Init UI with default background
    drawRadarBackground('scanning');

    // 1. Query the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        if (!tabs || tabs.length === 0) {
            updateUI('error', 'TARGET NOT ACQUIRED (TAB ERROR)');
            return;
        }

        const currentUrl = tabs[0].url;
        if (!currentUrl) {
            updateUI('error', 'TARGET NOT ACQUIRED (RESTRICTED URL)');
            return;
        }
        
        urlDisplay.textContent = currentUrl;
        
        // Add title for hover text on extremely long URLs
        urlDisplay.title = currentUrl;

        // Skip internal chrome:// or edge:// urls
        if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
            updateUI('safe', 'THREAT LEVEL: NEGLIGIBLE (SYSTEM PAGE)');
            drawRadarBackground('safe');
            return;
        }

        try {
            // 2. Send POST request to FastAPI server running locally
            const response = await fetch('http://127.0.0.1:8000/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: currentUrl })
            });

            if (!response.ok) {
                throw new Error(`Server returned status: ${response.status}`);
            }

            const data = await response.json();
            
            // Draw Radar Data
            if (data.features) {
                const normVals = normalizeFeatures(data.features);
                drawRadarBackground(data.status); // Redraw grid with neon intensity
                drawDataPolygon(normVals, data.status);
            }

            // 3. Update the UI based on prediction status
            if (data.status === 'phishing') {
                updateUI('phishing', 'THREAT LEVEL: CRITICAL - EVADE!');
            } else {
                updateUI('safe', 'THREAT LEVEL: NEGLIGIBLE');
            }

        } catch (error) {
            console.error('Scan error:', error);
            updateUI('error', 'CONNECTION LOST TO SERVER');
        }
    });
});
