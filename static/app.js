let ws;

function initApp() {
    connectWebSocket();
    pollData();
    setInterval(pollData, 5000); // Polling a cada 5s pro status

    document.getElementById('btn-block').addEventListener('click', () => actionIp('block'));
    document.getElementById('btn-whitelist').addEventListener('click', () => actionIp('whitelist'));
}

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
        logTerminal('> WS Conectado ao IronGate Core.', 'sys');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleWsEvent(data);
        } catch(e) {
            console.error('Falha no JSON do WS', e);
        }
    };

    ws.onclose = () => {
        logTerminal('> WS Desconectado. Tentando novamente...', 'warn');
        setTimeout(connectWebSocket, 3000);
    };
}

function handleWsEvent(data) {
    if (data.type === 'BLOCK') {
        logTerminal(`[BLOCK] IP ${data.ip} banido! Score: ${data.score}`, 'block');
        pollData(); // Refresh table
    } else if (data.type === 'ALERT') {
        logTerminal(`[ALERT] ${data.message}`, 'warn');
    }
}

async function pollData() {
    try {
        const [statusRes, ipsRes, guardRes] = await Promise.all([
            fetch('/api/status'),
            fetch('/api/ips'),
            fetch('/api/guard-status')
        ]);

        if (statusRes.ok) {
            const status = await statusRes.json();
            document.getElementById('stat-requests').innerText = status.total_requests;
            document.getElementById('stat-ips').innerText = status.active_ips;
            document.getElementById('stat-bans').innerText = status.active_bans;
        }

        if (ipsRes.ok) {
            const ips = await ipsRes.json();
            renderTable(ips);
        }

        if (guardRes.ok) {
            const guard = await guardRes.json();
            updateGuardStatus(guard);
        }
    } catch(err) {
        console.error("Poll fail", err);
        updateGuardStatus({ state: 'error' });
    }
}

function updateGuardStatus(guard) {
    const led = document.getElementById('guard-status');
    const text = document.getElementById('guard-text');
    
    led.className = 'led'; // reset
    if (guard.state === 'emergency') {
        led.classList.add('red');
        text.innerText = 'EMERGÊNCIA (Falhou gravação)';
    } else if (guard.state === 'error') {
        led.classList.add('yellow');
        text.innerText = 'DESCONECTADO';
    } else {
        led.classList.add('green');
        text.innerText = `GUARD ATIVO (Writes: ${guard.writes || 0})`;
    }
}

function renderTable(ips) {
    // ips is an array of objects
    const tbody = document.querySelector('#ips-table tbody');
    tbody.innerHTML = '';
    
    ips.slice(0, 50).forEach(ip => {
        let scoreClass = 'score-low';
        if (ip.score >= 50) scoreClass = 'score-high';
        else if (ip.score >= 30) scoreClass = 'score-med';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${ip.ip}</td>
            <td class="${scoreClass}">${parseFloat(ip.score).toFixed(1)}</td>
            <td>${ip.requests || 0}</td>
            <td>${ip.strikes || 0}</td>
            <td>
                <button class="btn btn-danger" onclick="actionIp('block', '${ip.ip}')" style="padding: 4px 8px; font-size: 0.7rem">BLOCK</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function actionIp(action, ipOverride) {
    const ip = ipOverride || document.getElementById('ip-input').value.trim();
    if (!ip) return;

    try {
        const res = await fetch(`/api/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        if (res.ok) {
            logTerminal(`> Ação ${action} executada com sucesso no IP ${ip}`, 'sys');
            document.getElementById('ip-input').value = '';
            pollData();
        } else {
            logTerminal(`> Falha na ação ${action} no IP ${ip}`, 'warn');
        }
    } catch(e) {
        logTerminal(`> POST error: ${e.message}`, 'warn');
    }
}

function logTerminal(msg, typeClass) {
    const term = document.getElementById('log-terminal');
    const div = document.createElement('div');
    div.className = `log-entry ${typeClass}`;
    
    const time = new Date().toLocaleTimeString();
    div.innerText = `[${time}] ${msg}`;
    
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
    
    // Manter logs maximos
    while(term.children.length > 100) {
        term.removeChild(term.firstChild);
    }
}

document.addEventListener('DOMContentLoaded', initApp);
