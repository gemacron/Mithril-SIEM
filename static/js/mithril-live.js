/**
 * MITHRIL SIEM - WebSocket Live Stream Client
 */

document.addEventListener('DOMContentLoaded', () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socketUrl = `${protocol}//${window.location.host}/ws/live-stream/`;
  const tableBody = document.getElementById('liveFeedTableBody');

  function connectSocket() {
    const socket = new WebSocket(socketUrl);

    socket.onopen = () => {
      console.log('🛡️ Mithril SIEM: Conectado a Live Stream WebSocket.');
      const indicator = document.getElementById('socketStatusIndicator');
      if (indicator) {
        indicator.textContent = 'ONLINE';
        indicator.className = 'badge safe';
      }
    };

    socket.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);

        // 1. Añadir pulso en el mapa 2D
        if (window.mithrilMap && event.latitude && event.longitude) {
          window.mithrilMap.addLivePulse(event.latitude, event.longitude, event.is_threat);
        }

        // 2. Insertar fila en la tabla en vivo
        if (tableBody) {
          const row = document.createElement('tr');
          const statusColor = event.status_code >= 400 ? 'color: var(--neon-crimson);' : 'color: var(--neon-emerald);';
          const badgeClass = event.is_threat ? 'badge critical' : 'badge low';
          const badgeText = event.is_threat ? 'AMENAZA' : 'NORMAL';

          row.innerHTML = `
            <td><span class="${badgeClass}">${badgeText}</span></td>
            <td><strong>${event.timestamp}</strong></td>
            <td><code>${event.client_ip}</code></td>
            <td>${event.country_name || event.country_code}</td>
            <td><span style="color: var(--neon-cyan);">${event.method}</span> <code>${event.uri.substring(0, 35)}</code></td>
            <td style="${statusColor} font-weight: bold;">${event.status_code}</td>
            <td><code>${event.node}</code></td>
          `;

          tableBody.insertBefore(row, tableBody.firstChild);

          // Limitar a 20 filas visibles
          while (tableBody.children.length > 20) {
            tableBody.removeChild(tableBody.lastChild);
          }
        }
      } catch (err) {
        console.error('Error parseando evento WebSocket:', err);
      }
    };

    socket.onclose = () => {
      console.warn('Mithril WebSocket desconectado. Reintentando en 3s...');
      const indicator = document.getElementById('socketStatusIndicator');
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

  // Iniciar conexión si el elemento existe en la página
  if (tableBody) {
    connectSocket();
  }
});
