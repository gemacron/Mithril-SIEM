/**
 * MITHRIL SIEM - 2D Interactive Tactical World Map (High-Performance Optimized)
 * Canvas de alto rendimiento sin dependencias externas:
 * - Capa base vectorial (océano + grilla + continentes) pre-renderizada en Offscreen Canvas (0 CPU por frame)
 * - Estación radar para Nodos Proxy con escáner rotativo continuo
 * - Puntos de tráfico histórico con preservación en memoria y auras de riesgo (Cyan / Carmesí)
 * - Cola acotada de ondas sónicas y arcos balísticos (60 FPS garantizados incluso bajo ataques DoS)
 * - Poller asíncrono con AbortController sin solapamiento de peticiones
 */

class TacticalWorldMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d', { alpha: false });

    // Offscreen canvas para cachear fondo, grilla y continentes
    this.bgCanvas = document.createElement('canvas');
    this.bgCtx = this.bgCanvas.getContext('2d', { alpha: false });

    this.points = [];
    this.pulses = [];
    this.arcs = [];
    this.nodes = [];
    this.isFetching = false;

    this.mouse = { x: -100, y: -100, active: false };
    this.hoverPoint = null;

    this.resize();
    window.addEventListener('resize', () => this.resize());

    // Eventos del mouse para interactividad
    this.canvas.addEventListener('mousemove', (e) => this.handleMouseMove(e), { passive: true });
    this.canvas.addEventListener('mouseleave', () => {
      this.mouse.active = false;
      this.hoverPoint = null;
    });

    // Cargar puntos y nodos iniciales
    this.fetchData();

    // Poller de mapa cada 8 segundos con protección anti-solapamiento
    setInterval(() => this.fetchData(), 8000);

    // Loop de renderizado continuo a 60 FPS
    this.render = this.render.bind(this);
    requestAnimationFrame(this.render);
  }

  resize() {
    const parent = this.canvas.parentElement;
    if (!parent) return;

    this.width = parent.clientWidth || 800;
    this.height = parent.clientHeight || 440;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(this.width * dpr);
    this.canvas.height = Math.floor(this.height * dpr);
    this.ctx.setTransform(1, 0, 0, 1, 0, 0);
    this.ctx.scale(dpr, dpr);

    // Redimensionar y pre-renderizar el mapa base estático una sola vez
    this.bgCanvas.width = Math.floor(this.width * dpr);
    this.bgCanvas.height = Math.floor(this.height * dpr);
    this.bgCtx.setTransform(1, 0, 0, 1, 0, 0);
    this.bgCtx.scale(dpr, dpr);
    this.renderStaticBackground();
  }

  geoToCanvas(lat, lon) {
    const x = ((lon + 180) / 360) * this.width;
    const y = ((90 - lat) / 180) * this.height;
    return { x, y };
  }

  canvasToGeo(x, y) {
    const lon = (x / this.width) * 360 - 180;
    const lat = 90 - (y / this.height) * 180;
    return { lat, lon };
  }

  handleMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    this.mouse.x = e.clientX - rect.left;
    this.mouse.y = e.clientY - rect.top;
    this.mouse.active = true;

    this.hoverPoint = null;
    for (let i = 0; i < this.points.length; i++) {
      const pt = this.points[i];
      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      if (Math.hypot(x - this.mouse.x, y - this.mouse.y) < 10) {
        this.hoverPoint = { ...pt, screenX: x, screenY: y };
        break;
      }
    }
  }

  addLivePulse(lat, lon, isThreat = false, clientIp = '') {
    const coords = this.geoToCanvas(lat, lon);
    const color = isThreat ? '#ff3366' : '#00e5ff';

    // 1. Limitar cola máxima de pulsos simultáneos para no saturar GPU/Canvas en ráfagas DoS
    if (this.pulses.length >= 35) {
      this.pulses.shift();
    }
    this.pulses.push({
      x: coords.x,
      y: coords.y,
      radius: 2,
      maxRadius: isThreat ? 28 : 18,
      alpha: 1.0,
      color: color,
      isThreat: isThreat
    });

    // 2. Trazar arco táctico hacia el nodo proxy
    if (this.nodes.length > 0) {
      const targetNode = this.nodes[0];
      const target = this.geoToCanvas(targetNode.latitude, targetNode.longitude);
      const dist = Math.hypot(coords.x - target.x, coords.y - target.y);

      if (dist > 20) {
        if (this.arcs.length >= 30) {
          this.arcs.shift();
        }
        this.arcs.push({
          startX: coords.x,
          startY: coords.y,
          endX: target.x,
          endY: target.y,
          progress: 0.0,
          speed: 0.04,
          color: color
        });
      }
    }

    // 3. Añadir o actualizar en los puntos visibles de la sesión (preservando amenazas)
    const existingIdx = this.points.findIndex(p => Math.abs(p.lat - lat) < 0.1 && Math.abs(p.lon - lon) < 0.1);
    if (existingIdx !== -1) {
      if (isThreat) {
        this.points[existingIdx].isThreat = true;
        this.points[existingIdx].status_code = 403;
      }
    } else {
      this.points.unshift({
        lat: lat,
        lon: lon,
        ip: clientIp,
        isThreat: isThreat,
        status_code: isThreat ? 403 : 200
      });
      if (this.points.length > 90) this.points.pop();
    }
  }

  fetchData() {
    if (this.isFetching) return;
    this.isFetching = true;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    fetch('/api/map-data/', { signal: controller.signal })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (data.nodes && Array.isArray(data.nodes)) {
          this.nodes = data.nodes;
        }

        if (data.points && Array.isArray(data.points) && data.points.length > 0) {
          const incoming = data.points.map(p => ({
            lat: parseFloat(p.latitude) || 0,
            lon: parseFloat(p.longitude) || 0,
            ip: p.client_ip || '',
            country: p.country_name || '',
            isThreat: Boolean(p.is_threat) || (p.status_code >= 400),
            status_code: p.status_code
          }));
          this.points = incoming.slice(0, 90);
        }
      })
      .catch(err => {
        if (err.name !== 'AbortError') {
          console.debug("Error sincronizando mapa:", err);
        }
      })
      .finally(() => {
        clearTimeout(timeoutId);
        this.isFetching = false;
      });
  }

  // ==========================================
  // PRE-RENDERIZADO DE CAPA BASE ESTÁTICA
  // ==========================================

  drawPolygonOn(ctx, coords) {
    ctx.beginPath();
    coords.forEach((c, idx) => {
      const { x, y } = this.geoToCanvas(c[0], c[1]);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  }

  renderStaticBackground() {
    const ctx = this.bgCtx;
    if (!ctx) return;

    // 1. Fondo de océano profundo táctico
    ctx.fillStyle = '#060910';
    ctx.fillRect(0, 0, this.width, this.height);

    // 2. Grilla geográfica
    ctx.strokeStyle = 'rgba(25, 36, 55, 0.45)';
    ctx.lineWidth = 0.5;

    for (let lat = -60; lat <= 80; lat += 20) {
      const y = ((90 - lat) / 180) * this.height;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(this.width, y);
      ctx.stroke();

      ctx.fillStyle = 'rgba(100, 116, 139, 0.4)';
      ctx.font = '9px monospace';
      ctx.fillText(`${lat}°`, 4, y - 2);
    }

    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * this.width;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, this.height);
      ctx.stroke();

      if (lon !== -180) {
        ctx.fillStyle = 'rgba(100, 116, 139, 0.4)';
        ctx.font = '9px monospace';
        ctx.fillText(`${lon}°`, x + 3, this.height - 4);
      }
    }

    const ecuadorY = 0.5 * this.height;
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.2)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, ecuadorY);
    ctx.lineTo(this.width, ecuadorY);
    ctx.stroke();

    const greenwichX = 0.5 * this.width;
    ctx.beginPath();
    ctx.moveTo(greenwichX, 0);
    ctx.lineTo(greenwichX, this.height);
    ctx.stroke();

    // 3. Continentes vectoriales
    ctx.fillStyle = '#0b1220';
    ctx.strokeStyle = '#1e2d42';
    ctx.lineWidth = 1.2;

    this.drawPolygonOn(ctx, [
      [72, -165], [70, -135], [68, -85], [58, -60], [45, -53], [44, -65],
      [30, -81], [25, -80], [29, -89], [26, -97], [18, -95], [14, -87],
      [8, -78], [15, -93], [22, -105], [32, -117], [38, -123], [48, -125],
      [58, -136], [60, -150], [65, -168]
    ]);
    this.drawPolygonOn(ctx, [
      [12, -72], [11, -60], [5, -51], [-2, -44], [-8, -35], [-18, -38],
      [-23, -43], [-33, -51], [-42, -63], [-54, -67], [-55, -73], [-46, -75],
      [-35, -73], [-18, -71], [-5, -81], [5, -77], [8, -77]
    ]);
    this.drawPolygonOn(ctx, [
      [71, 28], [69, 16], [58, 6], [54, 8], [53, 1], [48, -4],
      [43, -9], [37, -9], [36, -5], [36, 1], [43, 4], [44, 12],
      [41, 15], [38, 23], [40, 26], [45, 36], [55, 38], [60, 30], [65, 32]
    ]);
    this.drawPolygonOn(ctx, [
      [58, -5], [57, -2], [51, 1], [50, -5], [54, -4]
    ]);
    this.drawPolygonOn(ctx, [
      [37, 10], [36, -5], [31, -10], [21, -17], [14, -17], [5, -8],
      [4, 7], [-5, 12], [-16, 12], [-33, 18], [-34, 26], [-26, 33],
      [-12, 40], [10, 51], [12, 44], [28, 34], [31, 32], [32, 24]
    ]);
    this.drawPolygonOn(ctx, [
      [-12, 49], [-16, 50], [-25, 47], [-25, 44], [-16, 44]
    ]);
    this.drawPolygonOn(ctx, [
      [73, 80], [77, 105], [76, 140], [67, 178], [60, 163], [52, 142],
      [43, 132], [38, 120], [30, 122], [22, 114], [21, 108], [10, 104],
      [2, 102], [13, 100], [21, 90], [22, 70], [25, 62], [30, 48],
      [40, 48], [40, 36], [42, 28], [65, 42], [70, 60]
    ]);
    this.drawPolygonOn(ctx, [
      [45, 142], [41, 141], [35, 140], [33, 131], [37, 137], [43, 144]
    ]);
    this.drawPolygonOn(ctx, [
      [-11, 142], [-15, 145], [-24, 152], [-34, 151], [-38, 147],
      [-38, 140], [-35, 118], [-22, 114], [-15, 123], [-12, 136]
    ]);
  }

  // ==========================================
  // RENDERIZADO PRINCIPAL LIGERO (60 FPS)
  // ==========================================

  render() {
    const ctx = this.ctx;

    // 1. Copiar capa estática pre-renderizada (ultrarrápido)
    ctx.drawImage(this.bgCanvas, 0, 0, this.width, this.height);

    // 2. Arcos de trayectoria balística
    for (let i = this.arcs.length - 1; i >= 0; i--) {
      const arc = this.arcs[i];
      const midX = (arc.startX + arc.endX) / 2;
      const midY = Math.min(arc.startY, arc.endY) - 50;

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(arc.startX, arc.startY);
      ctx.quadraticCurveTo(midX, midY, arc.endX, arc.endY);
      ctx.strokeStyle = arc.color;
      ctx.lineWidth = 1.2;
      ctx.globalAlpha = 0.35;
      ctx.setLineDash([4, 4]);
      ctx.stroke();

      const t = arc.progress;
      const curX = (1 - t) * (1 - t) * arc.startX + 2 * (1 - t) * t * midX + t * t * arc.endX;
      const curY = (1 - t) * (1 - t) * arc.startY + 2 * (1 - t) * t * midY + t * t * arc.endY;

      ctx.setLineDash([]);
      ctx.globalAlpha = 1.0;
      ctx.beginPath();
      ctx.arc(curX, curY, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
      ctx.restore();

      arc.progress += arc.speed;
      if (arc.progress >= 1.0) {
        this.arcs.splice(i, 1);
      }
    }

    // 3. Puntos de tráfico e incidentes activos
    for (let i = 0; i < this.points.length; i++) {
      const pt = this.points[i];
      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      const color = pt.isThreat ? '#ff3366' : '#00e5ff';

      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, 3.2, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(x, y, 6.2, 0, Math.PI * 2);
      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.35;
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.restore();
    }

    // 4. Nodos Proxy de Nginx (Bases Defensivas Tácticas)
    const now = Date.now();
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const { x, y } = this.geoToCanvas(node.latitude, node.longitude);
      const isOnline = node.status === 'ONLINE';
      const nodeColor = isOnline ? '#00e676' : '#ff9900';

      ctx.save();
      const ringRadius = ((now / 20) % 25) + 6;
      const ringAlpha = 1 - (ringRadius - 6) / 25;
      ctx.beginPath();
      ctx.arc(x, y, ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = nodeColor;
      ctx.lineWidth = 1.5;
      ctx.globalAlpha = ringAlpha * 0.7;
      ctx.stroke();

      ctx.globalAlpha = 1.0;
      ctx.fillStyle = nodeColor;
      ctx.beginPath();
      ctx.moveTo(x, y - 6);
      ctx.lineTo(x + 6, y);
      ctx.lineTo(x, y + 6);
      ctx.lineTo(x - 6, y);
      ctx.closePath();
      ctx.fill();

      ctx.font = '10px monospace';
      ctx.fillStyle = '#f1f5f9';
      ctx.fillText(`📡 [PROXY] ${node.name}`, x + 10, y + 3);
      ctx.restore();
    }

    // 5. Ondas sónicas pulsantes en vivo
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      ctx.save();
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.strokeStyle = p.color;
      ctx.lineWidth = p.isThreat ? 2.2 : 1.4;
      ctx.globalAlpha = p.alpha;
      ctx.stroke();
      ctx.restore();

      p.radius += 0.65;
      p.alpha -= 0.028;

      if (p.alpha <= 0 || p.radius >= p.maxRadius) {
        this.pulses.splice(i, 1);
      }
    }

    // 6. HUD Táctico bajo el cursor
    if (this.mouse.active) {
      const geo = this.canvasToGeo(this.mouse.x, this.mouse.y);
      ctx.save();

      ctx.strokeStyle = 'rgba(0, 229, 255, 0.25)';
      ctx.lineWidth = 0.5;
      ctx.beginPath();
      ctx.moveTo(this.mouse.x, 0);
      ctx.lineTo(this.mouse.x, this.height);
      ctx.moveTo(0, this.mouse.y);
      ctx.lineTo(this.width, this.mouse.y);
      ctx.stroke();

      ctx.font = '9px monospace';
      ctx.fillStyle = 'rgba(0, 229, 255, 0.8)';
      ctx.fillText(`${geo.lat.toFixed(2)}°, ${geo.lon.toFixed(2)}°`, this.mouse.x + 8, this.mouse.y - 8);

      if (this.hoverPoint) {
        const hp = this.hoverPoint;
        const text = `${hp.ip} (${hp.country || 'Remoto'}) [${hp.status_code || 200}]`;
        ctx.fillStyle = 'rgba(13, 18, 31, 0.92)';
        ctx.strokeStyle = hp.isThreat ? '#ff3366' : '#00e5ff';
        ctx.lineWidth = 1;
        ctx.fillRect(hp.screenX + 12, hp.screenY - 24, text.length * 7 + 10, 20);
        ctx.strokeRect(hp.screenX + 12, hp.screenY - 24, text.length * 7 + 10, 20);

        ctx.fillStyle = '#ffffff';
        ctx.fillText(text, hp.screenX + 17, hp.screenY - 10);
      }
      ctx.restore();
    }

    requestAnimationFrame(this.render);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.mithrilMap = new TacticalWorldMap('tacticalMapCanvas');
});
