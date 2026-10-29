/**
 * MITHRIL SIEM - Real-Time SOC Live Stream & Dashboard Synchronizer (Zero-Freeze Edition)
 * Optimizado para alta carga y análisis continuo sin bloqueos de UI:
 * - Identificación visual de IPs de Cloudflare (☁️ CF / CLOUDFLARE)
 * - Disparo garantizado de flechas de ataque en el Mapa 2D tanto por WebSocket como por Poller
 * - Batching de WebSocket mediante requestAnimationFrame + DocumentFragment
 * - Diffing inteligente de Candidatos a Bloqueo y Nodos
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

  let lastNodesSignature = '';
  let lastCandidatesSignature = '';
  let isFetchingStats = false;
  let isWsConnected = false;
  let isFeedPaused = false;
  const pausedEventsQueue = [];

  const wsQueue = [];
  let rafScheduled = false;

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

  function isPrivateLocalIp(ip) {
    if (!ip) return false;
    const s = String(ip).trim().replace(/^🎯\s*/, '');
    if (!s || s === '-' || s === '::1' || s.startsWith('127.')) return true;
    if (s.startsWith('10.') || s.startsWith('192.168.') || s.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s)) return true;
    return false;
  }

  function isEventLocal(event) {
    if (!event) return false;
    if (event.is_local_ip === true) return true;
    const realIp = event.real_client_ip;
    const clientIp = event.client_ip;
    if (realIp && isPrivateLocalIp(realIp)) return true;
    if (!event.is_cloudflare && clientIp && isPrivateLocalIp(clientIp)) return true;
    return false;
  }

  function cfBadgeHtml(isCf, fullText = false, realClientIp = '', cfNodeIp = '') {
    let html = '';
    if (isCf) {
      const label = fullText ? '☁️ CLOUDFLARE' : '☁️ CF';
      const titleText = cfNodeIp ? `Nodo Cloudflare: ${cfNodeIp}` : 'IP perteneciente a la red CDN/Proxy de Cloudflare';
      html += `<span style="background: rgba(243, 128, 32, 0.18); color: #f6821f; border: 1px solid rgba(243, 128, 32, 0.55); font-size: 0.62rem; font-weight: 700; padding: 0.08rem 0.35rem; border-radius: 4px; margin-left: 0.25rem; font-family: var(--font-mono);" title="${titleText}">${label}</span>`;
    }
    if (realClientIp && fullText && !isPrivateLocalIp(realClientIp)) {
      html += `<span style="background: rgba(0, 229, 255, 0.15); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.5); font-size: 0.62rem; font-weight: 700; padding: 0.08rem 0.35rem; border-radius: 4px; margin-left: 0.22rem; font-family: var(--font-mono);" title="IP Real del Cliente detrás de Cloudflare">🎯 IP Real: ${realClientIp}</span>`;
    }
    return html;
  }

  function realClientIpCellHtml(event) {
    if (event.real_client_ip) {
      if (!isPrivateLocalIp(event.real_client_ip)) {
        return `<code style="background: rgba(0, 229, 255, 0.14); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.5); font-size: 0.75rem; font-weight: 800; padding: 0.12rem 0.45rem; border-radius: 4px;" title="IP Real del Cliente detrás de Cloudflare">🎯 ${event.real_client_ip}</code>`;
      }
      return `<code style="background: rgba(148, 163, 184, 0.16); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.45); font-size: 0.74rem; font-weight: 700; padding: 0.12rem 0.45rem; border-radius: 4px;" title="IP Local Privada / Balanceador">🏢 ${event.real_client_ip}</code>`;
    }
    if (!event.is_cloudflare) {
      if (isPrivateLocalIp(event.client_ip)) {
        return `<code style="background: rgba(148, 163, 184, 0.16); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.45); font-size: 0.74rem; font-weight: 700; padding: 0.12rem 0.45rem; border-radius: 4px;" title="IP Local Privada / Balanceador">🏢 ${event.client_ip || '-'}</code>`;
      }
      return `<code style="color: var(--neon-emerald); font-size: 0.75rem;">${event.client_ip || '-'}</code>`;
    }
    const ua = String(event.user_agent || '');
    if (ua.includes('Cloudflare-Traffic-Manager') || ua.includes('Zabbix')) {
      return `<span style="color: #f6821f; font-size: 0.7rem; font-family: var(--font-mono);" title="Petición originada directamente por el monitor de salud de Cloudflare / Zabbix">☁️ Sonda Healthcheck</span>`;
    }
    if (event.method === 'HTTPS') {
      return `<span style="color: var(--text-dim); font-size: 0.7rem; font-family: var(--font-mono);" title="Paquete TLS ClientHello previo a las cabeceras HTTP">🔒 Handshake TLS</span>`;
    }
    return `<span style="color: var(--neon-amber); font-size: 0.7rem; font-family: var(--font-mono);" title="Petición recibida vía nodo Cloudflare">☁️ Conexión Edge</span>`;
  }

  function updateKpiFast(element, newValue) {
    if (!element) return;
    const strVal = String(newValue);
    if (element.textContent !== strVal) {
      element.textContent = strVal;
    }
  }

  function addKpiDelta(element, delta) {
    if (!element || !delta) return;
    const current = parseInt(element.textContent || '0', 10) || 0;
    element.textContent = String(current + delta);
  }

  window.submitCandidateDecisionAjax = function (event, candidateId, actionType) {
    if (event) event.preventDefault();
    const csrfToken = getCookie('csrftoken') || '';
    const formData = new FormData();
    formData.append('csrfmiddlewaretoken', csrfToken);
    formData.append('duration_hours', '24');

    const url = `/mitigation/candidates/${candidateId}/${actionType}/`;
    fetch(url, {
      method: 'POST',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
      body: formData
    })
      .then(() => {
        lastCandidatesSignature = '';
        fetchLiveStats();
        if (typeof closeCandidateInspectModal === 'function') {
          closeCandidateInspectModal();
        }
      })
      .catch(err => console.debug('Error aplicando decisión:', err));
    return false;
  };

  function renderNodesTable(nodes) {
    if (!nodesTableBody) return;
    const sig = JSON.stringify(nodes || []);
    if (sig === lastNodesSignature) return;
    lastNodesSignature = sig;

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
    const sig = JSON.stringify(candidates || []);
    if (sig === lastCandidatesSignature) return;
    lastCandidatesSignature = sig;

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
      const shortReason = reason;
      const payloadHtml = c.payload
        ? `<div style="font-size: 0.7rem; font-family: var(--font-mono); color: var(--neon-amber); background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); padding: 0.2rem 0.45rem; border-radius: 4px; margin-bottom: 0.65rem; word-break: break-all; white-space: pre-wrap;">⚡ ${c.payload}</div>`
        : '';

      html += `
        <div style="background: rgba(13, 18, 31, 0.7); border: 1px solid var(--border-dim); border-radius: 6px; padding: 0.85rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-main); font-size: 0.9rem; display: inline-flex; align-items: center; flex-wrap: wrap;">
              🌐 ${c.ip} ${cfBadgeHtml(c.is_cloudflare, true, c.real_client_ip, c.cloudflare_ip)}
            </span>
            <span class="${scoreBadge}">Riesgo: ${c.score}/100</span>
          </div>
          <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.4rem;">
            ${shortReason}
          </p>
          ${payloadHtml}
          <div style="display: flex; gap: 0.4rem;">
            <button type="button" class="btn btn-cyan" style="font-size: 0.75rem; padding: 0.35rem 0.6rem;" onclick="openCandidateInspectModal(${c.id})" title="Ver qué intentó hacer y todos los datos de la petición">
              🔍 Info
            </button>
            <button type="button" class="btn btn-crimson" style="flex: 1; justify-content: center; font-size: 0.75rem; padding: 0.35rem 0.6rem;" onclick="submitCandidateDecisionAjax(event, ${c.id}, 'approve')">
              🛑 Bloquear (24h)
            </button>
            <button type="button" class="btn btn-dim" style="font-size: 0.75rem; padding: 0.35rem 0.6rem;" onclick="submitCandidateDecisionAjax(event, ${c.id}, 'dismiss')" title="Descartar">
              ✕ Descartar
            </button>
          </div>
        </div>
      `;
    });
    html += '</div>';
    candidatesContainer.innerHTML = html;
  }

  function fetchLiveStats() {
    if (isFetchingStats) return;
    isFetchingStats = true;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);

    fetch('/api/live-stats/', { signal: controller.signal })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (data.online_nodes !== undefined) updateKpiFast(kpiOnlineNodes, data.online_nodes);
        if (data.total_nodes !== undefined) updateKpiFast(kpiTotalNodes, data.total_nodes);
        if (data.total_logs_today !== undefined) updateKpiFast(kpiTotalLogs, data.total_logs_today);
        if (data.threats_today !== undefined) updateKpiFast(kpiThreats, data.threats_today);
        if (data.pending_bans !== undefined) updateKpiFast(kpiPendingBans, data.pending_bans);
        if (data.active_bans !== undefined) updateKpiFast(kpiActiveBans, data.active_bans);

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

        if (data.nodes) renderNodesTable(data.nodes);
        if (data.candidates) renderCandidates(data.candidates);

        // La tabla del Live Feed se gestiona de forma fluida y continua por WebSocket para evitar
        // parpadeos y reseteos bruscos. El poller solo puebla la tabla en frío si no hay WebSocket activo.
        if (!isWsConnected && data.recent_logs && tableBody && tableBody.children.length === 0) {
          let rowsHtml = '';
          data.recent_logs.forEach((event) => {
            const statusColor = event.status_code >= 400 ? 'color: var(--neon-crimson);' : 'color: var(--neon-emerald);';
            const badgeClass = event.is_threat ? 'badge critical' : 'badge low';
            const badgeText = event.is_threat ? 'AMENAZA' : 'NORMAL';
            const uriDisplay = event.uri || '/';
            const countryDisplay = event.country_name || event.country_code || 'Remoto';
            const isLoc = isEventLocal(event);
            const hideRowStyle = (hideLocalIps && isLoc) ? 'style="display: none;"' : '';

            rowsHtml += `
              <tr data-log-id="${event.id || ''}" data-is-local="${isLoc ? 'true' : 'false'}" data-client-ip="${event.client_ip || ''}" data-real-ip="${event.real_client_ip || ''}" ${hideRowStyle}>
                <td><span class="${badgeClass}">${badgeText}</span></td>
                <td><strong>${event.timestamp || ''}</strong></td>
                <td><code>${event.client_ip || ''}</code>${cfBadgeHtml(event.is_cloudflare, false, '', event.cloudflare_ip)}</td>
                <td>${realClientIpCellHtml(event)}</td>
                <td>${countryDisplay}</td>
                <td style="max-width: 450px; word-break: break-all;"><span style="color: var(--neon-cyan); font-weight: 600;">${event.method || 'GET'}</span> <code style="word-break: break-all; white-space: pre-wrap; font-size: 0.74rem;">${uriDisplay}</code></td>
                <td style="${statusColor} font-weight: bold;">${event.status_code || 200}</td>
                <td><code>${event.node || 'Direct'}</code></td>
              </tr>
            `;
          });
          tableBody.innerHTML = rowsHtml;
          updateRowAgesAndFade();
        }
      })
      .catch(err => {
        if (err.name !== 'AbortError') {
          console.debug('Error sincronizando live-stats:', err);
        }
      })
      .finally(() => {
        clearTimeout(timeoutId);
        isFetchingStats = false;
      });
  }

  // Control interactivo del filtro de IPs Locales / Balanceador
  const localIpToggle = document.getElementById('filterHideLocalIpsToggle');
  let hideLocalIps = true;

  // Botón y controles de Pausa / Inspección de URLs
  const pauseFeedBtn = document.getElementById('togglePauseFeedBtn');
  const pauseFeedIcon = document.getElementById('pauseFeedIcon');
  const pauseFeedText = document.getElementById('pauseFeedText');
  const feedPausedBadge = document.getElementById('feedPausedBadge');

  function setFeedPausedState(paused) {
    isFeedPaused = paused;
    if (pauseFeedIcon) pauseFeedIcon.textContent = paused ? '▶️' : '⏸️';
    if (pauseFeedText) pauseFeedText.textContent = paused ? 'Reanudar Feed' : 'Pausar Feed';
    if (feedPausedBadge) feedPausedBadge.style.display = paused ? 'inline-block' : 'none';
    if (!paused && pausedEventsQueue.length > 0) {
      const toFlush = pausedEventsQueue.splice(0, 15);
      toFlush.forEach(ev => wsQueue.push(ev));
      if (!rafScheduled) {
        rafScheduled = true;
        requestAnimationFrame(flushWsQueue);
      }
    }
  }

  if (pauseFeedBtn) {
    pauseFeedBtn.addEventListener('click', () => {
      setFeedPausedState(!isFeedPaused);
    });
  }

  if (tableBody && tableBody.parentElement) {
    // Al posar el mouse sobre la tabla, pausar temporalmente para que el operador pueda leer URLs y datos
    tableBody.parentElement.addEventListener('mouseenter', () => {
      if (!isFeedPaused) {
        setFeedPausedState(true);
      }
    });
    tableBody.parentElement.addEventListener('mouseleave', () => {
      if (isFeedPaused) {
        setFeedPausedState(false);
      }
    });
  }

  function applyLocalFilterToDom() {
    if (!tableBody) return;
    const rows = tableBody.querySelectorAll('tr[data-log-id], tr[data-client-ip], tr[data-is-local]');
    rows.forEach(r => {
      if (!hideLocalIps) {
        // Al destildar, mostrar inmediatamente todas las filas
        r.style.display = '';
        return;
      }
      const isLocAttr = r.getAttribute('data-is-local');
      const rClientIp = r.getAttribute('data-client-ip');
      const rRealIp = r.getAttribute('data-real-ip');
      let isLocalRow = (isLocAttr === 'true');
      if (rRealIp && isPrivateLocalIp(rRealIp)) isLocalRow = true;
      if (rClientIp && isPrivateLocalIp(rClientIp)) isLocalRow = true;
      if (r.innerText.includes('192.168.') || r.innerText.includes('10.') || r.innerText.includes('🏢')) isLocalRow = true;

      r.style.display = isLocalRow ? 'none' : '';
    });
    updateRowAgesAndFade();
  }

  if (localIpToggle) {
    const saved = localStorage.getItem('mithril_hide_local_ips');
    if (saved !== null) {
      hideLocalIps = (saved === 'true');
      localIpToggle.checked = hideLocalIps;
    } else {
      hideLocalIps = localIpToggle.checked;
    }

    localIpToggle.addEventListener('change', () => {
      hideLocalIps = localIpToggle.checked;
      localStorage.setItem('mithril_hide_local_ips', hideLocalIps ? 'true' : 'false');
      applyLocalFilterToDom();
    });

    applyLocalFilterToDom();
  }

  // Desvanecimiento y caída gradual (Fade Out) hacia el fondo de la tabla
  function updateRowAgesAndFade() {
    if (!tableBody) return;
    const allRows = Array.from(tableBody.querySelectorAll('tr[data-log-id]'));
    const visibleRows = allRows.filter(r => r.style.display !== 'none');
    const MAX_VISIBLE = 32;

    visibleRows.forEach((row, idx) => {
      if (idx < 18) {
        row.style.opacity = '1';
      } else if (idx < 24) {
        row.style.opacity = '0.85';
      } else if (idx < 28) {
        row.style.opacity = '0.62';
      } else if (idx < MAX_VISIBLE) {
        row.style.opacity = '0.38';
      } else {
        // Fila que superó el límite visible: desvanecimiento gradual con animación CSS
        if (!row.classList.contains('live-row-fading')) {
          row.classList.add('live-row-fading');
          setTimeout(() => {
            if (row && row.parentNode) {
              row.remove();
            }
          }, 600);
        }
      }
    });

    // Poda de seguridad para que el DOM no crezca indefinidamente
    if (allRows.length > 70) {
      for (let i = 70; i < allRows.length; i++) {
        if (allRows[i] && allRows[i].parentNode) {
          allRows[i].remove();
        }
      }
    }
  }

  // Intervalo continuo para desvanecer suavemente peticiones viejas incluso en calma de tráfico
  setInterval(updateRowAgesAndFade, 2500);

  function flushWsQueue() {
    rafScheduled = false;
    if (wsQueue.length === 0) return;

    // Si está pausado (por botón o por cursor sobre la tabla), guardar en cola en memoria sin mover el DOM
    if (isFeedPaused) {
      while (wsQueue.length > 0 && pausedEventsQueue.length < 60) {
        pausedEventsQueue.push(wsQueue.shift());
      }
      wsQueue.length = 0;
      return;
    }

    const batch = wsQueue.splice(-6);
    wsQueue.length = 0;

    let logsDelta = 0;
    let threatsDelta = 0;
    const fragment = document.createDocumentFragment();

    batch.forEach(event => {
      logsDelta += 1;
      if (event.is_threat) threatsDelta += 1;

      const isLoc = isEventLocal(event);

      if (window.mithrilMap) {
        if (!(hideLocalIps && isLoc)) {
          const lat = parseFloat(event.latitude);
          const lon = parseFloat(event.longitude);
          if (!isNaN(lat) && !isNaN(lon)) {
            window.mithrilMap.addLivePulse(lat, lon, event.is_threat, event.client_ip, event.is_cloudflare, event.real_client_ip);
          }
        }
      }

      if (tableBody) {
        const row = document.createElement('tr');
        row.className = 'live-row-new'; // Deslizamiento suave de entrada
        const statusColor = event.status_code >= 400 ? 'color: var(--neon-crimson);' : 'color: var(--neon-emerald);';
        const badgeClass = event.is_threat ? 'badge critical' : 'badge low';
        const badgeText = event.is_threat ? 'AMENAZA' : 'NORMAL';
        const uriDisplay = event.uri || '/';
        const countryDisplay = event.country_name || event.country_code || 'Remoto';

        if (event.id) row.setAttribute('data-log-id', event.id);
        row.setAttribute('data-is-local', isLoc ? 'true' : 'false');
        row.setAttribute('data-client-ip', event.client_ip || '');
        row.setAttribute('data-real-ip', event.real_client_ip || '');

        if (hideLocalIps && isLoc) {
          row.style.display = 'none';
        }

        row.innerHTML = `
          <td><span class="${badgeClass}">${badgeText}</span></td>
          <td><strong>${event.timestamp || ''}</strong></td>
          <td><code>${event.client_ip || ''}</code>${cfBadgeHtml(event.is_cloudflare, false, '', event.cloudflare_ip)}</td>
          <td>${realClientIpCellHtml(event)}</td>
          <td>${countryDisplay}</td>
          <td style="max-width: 450px; word-break: break-all;"><span style="color: var(--neon-cyan); font-weight: 600;">${event.method || 'GET'}</span> <code style="word-break: break-all; white-space: pre-wrap; font-size: 0.74rem;">${uriDisplay}</code></td>
          <td style="${statusColor} font-weight: bold;">${event.status_code || 200}</td>
          <td><code>${event.node || 'Direct'}</code></td>
        `;
        fragment.insertBefore(row, fragment.firstChild);
      }
    });

    addKpiDelta(kpiTotalLogs, logsDelta);
    addKpiDelta(kpiThreats, threatsDelta);

    if (tableBody) {
      const emptyRow = tableBody.querySelector('td[colspan="8"], td[colspan="7"]');
      if (emptyRow && emptyRow.parentElement) {
        emptyRow.parentElement.remove();
      }
      tableBody.insertBefore(fragment, tableBody.firstChild);
      updateRowAgesAndFade();
    }
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socketUrl = `${protocol}//${window.location.host}/ws/live-stream/`;

  function connectSocket() {
    const socket = new WebSocket(socketUrl);

    socket.onopen = () => {
      isWsConnected = true;
      if (indicator) {
        indicator.textContent = 'STREAM ACTIVO';
        indicator.className = 'badge safe';
      }
    };

    socket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        if (wsQueue.length > 50) wsQueue.shift();
        wsQueue.push(event);
        if (!rafScheduled) {
          rafScheduled = true;
          requestAnimationFrame(flushWsQueue);
        }
      } catch (err) {
        console.error('Error parseando evento WebSocket:', err);
      }
    };

    socket.onclose = () => {
      isWsConnected = false;
      if (indicator) {
        indicator.textContent = 'RECONECTANDO';
        indicator.className = 'badge high';
      }
      setTimeout(connectSocket, 3000);
    };

    socket.onerror = () => {
      socket.close();
    };
  }

  if (tableBody) {
    connectSocket();
  }

  fetchLiveStats();
  setInterval(fetchLiveStats, 3000);
});
