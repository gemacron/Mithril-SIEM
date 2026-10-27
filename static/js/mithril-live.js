/**
 * MITHRIL SIEM - Real-Time SOC Live Stream & Dashboard Synchronizer
 * Actualiza en tiempo real:
 * - WebSocket Live Traffic Feed con animaciones tácticas
 * - Mapa Táctico 2D (pulsos geográficos azul/rojo)
 * - 5 Contadores KPI superiores con micro-pulsos
 * - Badges de alerta en el Navbar
 * - Panel de Infraestructura de Proxies (RPS, CPU, RAM, Estado)
 * - Cola de Candidatos a Bloqueo (Autoban en espera con botones interactivos)
 */

document.addEventListener('DOMContentLoaded', () => {
  const tableBody = document.getElementById('liveFeedTableBody');
  const nodesTableBody = document.getElementById('nodesTableBody');
  const candidatesContainer = document.getElementById('candidatesContainer');

  // KPIs
  const kpiOnlineNodes = document.getElementById('kpiOnlineNodes');
  const kpiTotalNodes = document.getElementById('kpiTotalNodes');
  const kpiTotalLogs = document.getElementById('kpiTotalLogs');
  const kpiThreats = document.getElementById('kpiThreats');
  const kpiPendingBans = document.getElementById('kpiPendingBans');
  const kpiActiveBans = document.getElementById('kpiActiveBans');

  // Navbar Badges
  const navPendingBansBadge = document.getElementById('navPendingBansBadge');
  const navActiveBansCount = document.getElementById('navActiveBansCount');
  const navOnlineNodesCount = document.getElementById('navOnlineNodesCount');

  // Socket status indicator
  const indicator = document.getElementById('socketStatusIndicator');

  // Helper para leer cookies (CSRF)
  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].trim();
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }

  function updateKpiWithPulse(element, newValue) {
    if (!element) return;
    const current = element.textContent.trim();
    if (current !== String(newValue)) {
      element.textContent = newValue;
      element.classList.remove('kpi-pulse');
      void element.offsetWidth;
      element.classList.add('kpi-pulse');
    }
  }

  function incrementKpi(element) {
    if (!element) return;
    const current = parseInt(element.textContent.trim() || '0', 10);
    updateKpiWithPulse(element, current + 1);
  }

  // ==========================================
  // RENDERIZADO DINÁMICO DE SECCIONES
  // ==========================================

  function renderNodesTable(nodes) {
    if (!nodesTableBody) return;
    if (!nodes || nodes.length === 0) {
      nodesTableBody.innerHTML = `
        <tr>
          <td colspan="3" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">
            No hay proxies dados de alta.<br>
            <a href="/nodes/create/" style="color: var(--neon-cyan); font-size: 0.8rem;">+ Agregar tu primer proxy Nginx</a>
          </td>
        </tr>
      `;
      return;
    }

    let html = '';
    nodes.forEach(n => {
      const isOnline = n.status === 'ONLINE';
      const badgeClass = isOnline ? 'badge safe' : 'badge high';
      const statusText = isOnline ? 'ONLINE' : 'OFFLINE';
      const telemetry = (n.cpu !== undefined && n.ram !== undefined)
        ? `<div style="font-size: 0.68rem; color: var(--text-dim); margin-top: 2px;">CPU: ${n.cpu}% | RAM: ${n.ram}%</div>`
        : '';

      html += `
        <tr>
          <td>
            <strong style="color: var(--text-main); font-size: 0.88rem;">${n.name}</strong><br>
            <span style="color: var(--text-dim); font-size: 0.72rem; font-family: var(--font-mono);">${n.ip}</span>
            ${telemetry}
          </td>
          <td>
            <span class="${badgeClass}">${statusText}</span>
          </td>
          <td style="color: var(--neon-cyan); font-weight: 700; font-family: var(--font-mono); font-size: 0.95rem;">
            ${n.rps}
          </td>
        </tr>
      `;
    });
    nodesTableBody.innerHTML = html;
  }

  function renderCandidates(candidates) {
    if (!candidatesContainer) return;
    const csrfToken = getCookie('csrftoken') || '';

    if (!candidates || candidates.length === 0) {
      candidatesContainer.innerHTML = `
        <div style="text-align: center; color: var(--text-dim); padding: 2rem 1rem;">
          <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
          <p style="font-size: 0.85rem;">No hay candidatos pendientes de bloqueo.</p>
          <p style="font-size: 0.75rem; margin-top: 0.25rem;">La heurística y las reglas están monitoreando el tráfico en segundo plano.</p>
        </div>
      `;
      return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
    candidates.forEach(c => {
      const scoreBadge = c.score >= 80 ? 'badge critical' : 'badge high';
      const reason = c.reason || 'Detección de patrones anómalos o escaneo sospechoso.';
      const shortReason = reason.length > 90 ? reason.substring(0, 90) + '...' : reason;

      html += `
        <div style="background: rgba(13, 18, 31, 0.7); border: 1px solid var(--border-dim); border-radius: 6px; padding: 0.85rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-main); font-size: 0.9rem;">
              🌐 ${c.ip}
            </span>
            <span class="${scoreBadge}">Riesgo: ${c.score}/100</span>
          </div>
          <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.75rem;">
            ${shortReason}
          </p>
          <div style="display: flex; gap: 0.5rem;">
            <form method="POST" action="/mitigation/candidates/approve/${c.id}/" style="flex: 1;">
              <input type="hidden" name="csrfmiddlewaretoken" value="${csrfToken}">
              <input type="hidden" name="duration_hours" value="24">
              <button type="submit" class="btn btn-crimson" style="width: 100%; justify-content: center; font-size: 0.75rem; padding: 0.35rem 0.6rem;">
                🛑 Bloquear (24h)
              </button>
            </form>
            <form method="POST" action="/mitigation/candidates/dismiss/${c.id}/">
              <input type="hidden" name="csrfmiddlewaretoken" value="${csrfToken}">
              <button type="submit" class="btn btn-dim" style="font-size: 0.75rem; padding: 0.35rem 0.6rem;" title="Descartar">
                ✕ Descartar
              </button>
            </form>
          </div>
        </div>
      `;
    });
    html += '</div>';
    candidatesContainer.innerHTML = html;
  }

  // ==========================================
  // SINCRONIZACIÓN PERIÓDICA DE ESTADO (POLLER)
  // ==========================================

  function fetchLiveStats() {
    fetch('/api/live-stats/')
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        // Actualizar KPIs
        if (data.online_nodes !== undefined) updateKpiWithPulse(kpiOnlineNodes, data.online_nodes);
        if (data.total_nodes !== undefined) updateKpiWithPulse(kpiTotalNodes, data.total_nodes);
        if (data.total_logs_today !== undefined) updateKpiWithPulse(kpiTotalLogs, data.total_logs_today);
        if (data.threats_today !== undefined) updateKpiWithPulse(kpiThreats, data.threats_today);
        if (data.pending_bans !== undefined) updateKpiWithPulse(kpiPendingBans, data.pending_bans);
        if (data.active_bans !== undefined) updateKpiWithPulse(kpiActiveBans, data.active_bans);

        // Actualizar Navbar Badges
        if (navPendingBansBadge && data.pending_bans !== undefined) {
          navPendingBansBadge.textContent = data.pending_bans;
          navPendingBansBadge.style.display = data.pending_bans > 0 ? 'inline-block' : 'none';
        }
        if (navActiveBansCount && data.active_bans !== undefined) {
          navActiveBansCount.textContent = data.active_bans;
        }
        if (navOnlineNodesCount && data.online_nodes !== undefined) {
          navOnlineNodesCount.textContent = data.online_nodes;
        }

        // Actualizar tablas
        if (data.nodes) renderNodesTable(data.nodes);
        if (data.candidates) renderCandidates(data.candidates);
      })
      .catch(err => {
        console.debug('Error sincronizando live-stats:', err);
      });
  }

  // ==========================================
  // WEBSOCKET LIVE STREAM CLIENT
  // ==========================================

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socketUrl = `${protocol}//${window.location.host}/ws/live-stream/`;

  function connectSocket() {
    const socket = new WebSocket(socketUrl);

    socket.onopen = () => {
      console.log('🛡️ Mithril SIEM: Conectado a Live Stream WebSocket.');
      if (indicator) {
        indicator.textContent = 'STREAM ACTIVO';
        indicator.className = 'badge safe';
      }
    };

    socket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);

        // 1. Añadir pulso táctico en el mapa 2D
        if (window.mithrilMap) {
          const lat = parseFloat(event.latitude);
          const lon = parseFloat(event.longitude);
          if (!isNaN(lat) && !isNaN(lon)) {
            window.mithrilMap.addLivePulse(lat, lon, event.is_threat, event.client_ip);
          }
        }

        // 2. Incrementar contadores en vivo al instante
        incrementKpi(kpiTotalLogs);
        if (event.is_threat) {
          incrementKpi(kpiThreats);
        }

        // 3. Insertar fila en el Live Feed
        if (tableBody) {
          // Limpiar fila inicial si existe
          const emptyRow = tableBody.querySelector('td[colspan="7"]');
          if (emptyRow && emptyRow.parentElement) {
            emptyRow.parentElement.remove();
          }

          const row = document.createElement('tr');
          const statusColor = event.status_code >= 400 ? 'color: var(--neon-crimson);' : 'color: var(--neon-emerald);';
          const badgeClass = event.is_threat ? 'badge critical' : 'badge low';
          const badgeText = event.is_threat ? 'AMENAZA' : 'NORMAL';
          const flashClass = event.is_threat ? 'row-flash-crimson' : 'row-flash-cyan';
          const uriDisplay = event.uri ? (event.uri.length > 35 ? event.uri.substring(0, 35) + '...' : event.uri) : '/';
          const countryDisplay = event.country_name || event.country_code || 'Remoto';

          row.className = flashClass;
          row.innerHTML = `
            <td><span class="${badgeClass}">${badgeText}</span></td>
            <td><strong>${event.timestamp || ''}</strong></td>
            <td><code>${event.client_ip || ''}</code></td>
            <td>${countryDisplay}</td>
            <td><span style="color: var(--neon-cyan); font-weight: 600;">${event.method || 'GET'}</span> <code>${uriDisplay}</code></td>
            <td style="${statusColor} font-weight: bold;">${event.status_code || 200}</td>
            <td><code>${event.node || 'Direct'}</code></td>
          `;

          tableBody.insertBefore(row, tableBody.firstChild);

          // Limitar buffer a 25 filas visibles
          while (tableBody.children.length > 25) {
            tableBody.removeChild(tableBody.lastChild);
          }
        }
      } catch (err) {
        console.error('Error parseando evento WebSocket:', err);
      }
    };

    socket.onclose = () => {
      console.warn('Mithril WebSocket desconectado. Reintentando en 3s...');
      if (indicator) {
        indicator.textContent = 'RECONECTANDO';
        indicator.className = 'badge high';
      }
      setTimeout(connectSocket, 3000);
    };

    socket.onerror = (err) => {
      console.error('Error en WebSocket:', err);
      socket.close();
    };
  }

  // Iniciar cliente de streaming y poller de sincronización
  if (tableBody) {
    connectSocket();
  }

  // Poller periódico cada 2.5 segundos para refrescar todas las secciones
  fetchLiveStats();
  setInterval(fetchLiveStats, 2500);
});
