/**
 * MITHRIL SIEM - 2D Interactive Tactical World Map
 * Renderizado de alto rendimiento en Canvas sin dependencias externas
 */

class TacticalWorldMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.points = [];
    this.pulses = [];

    this.resize();
    window.addEventListener('resize', () => this.resize());

    // Cargar puntos iniciales de la API
    this.fetchInitialData();

    // Loop de renderizado
    this.render = this.render.bind(this);
    requestAnimationFrame(this.render);
  }

  resize() {
    this.width = this.canvas.parentElement.clientWidth;
    this.height = this.canvas.parentElement.clientHeight || 440;
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  geoToCanvas(lat, lon) {
    // Proyección Equirrectangular
    const x = ((lon + 180) / 360) * this.width;
    const y = ((90 - lat) / 180) * this.height;
    return { x, y };
  }

  addLivePulse(lat, lon, isThreat = false) {
    const { x, y } = this.geoToCanvas(lat, lon);
    this.pulses.push({
      x,
      y,
      radius: 2,
      maxRadius: isThreat ? 24 : 14,
      alpha: 1.0,
      color: isThreat ? '#ff3366' : '#00e5ff'
    });
  }

  fetchInitialData() {
    fetch('/api/map-data/')
      .then(res => res.json())
      .then(data => {
        if (data.points) {
          data.points.forEach(p => {
            this.points.push({
              lat: p.latitude,
              lon: p.longitude,
              ip: p.client_ip,
              country: p.country_name,
              isThreat: p.status_code >= 400
            });
          });
        }
      })
      .catch(err => console.error("Error cargando mapa:", err));
  }

  drawGrid() {
    const ctx = this.ctx;
    ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
    ctx.lineWidth = 0.5;

    // Latitudes
    for (let lat = -60; lat <= 80; lat += 20) {
      const y = ((90 - lat) / 180) * this.height;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(this.width, y);
      ctx.stroke();
    }

    // Longitudes
    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * this.width;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, this.height);
      ctx.stroke();
    }
  }

  drawContinents() {
    // Esbozo esquemático vectorial de continentes en masa oscura
    const ctx = this.ctx;
    ctx.fillStyle = '#0f172a';
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;

    // América del Norte
    this.drawPolygon([
      [70, -165], [65, -60], [45, -55], [25, -80], [15, -90], [20, -105], [50, -125], [60, -140]
    ]);

    // América del Sur
    this.drawPolygon([
      [12, -75], [5, -50], [-10, -35], [-35, -55], [-55, -65], [-30, -70], [-5, -80]
    ]);

    // Europa
    this.drawPolygon([
      [70, 25], [60, 5], [45, -5], [36, -5], [36, 25], [45, 30], [55, 35], [65, 30]
    ]);

    // África
    this.drawPolygon([
      [35, -5], [30, 32], [10, 50], [-35, 20], [-30, 15], [5, 10], [15, -15]
    ]);

    // Asia
    this.drawPolygon([
      [70, 60], [70, 170], [60, 160], [35, 120], [20, 105], [10, 75], [25, 60], [40, 50], [60, 45]
    ]);

    // Oceanía / Australia
    this.drawPolygon([
      [-15, 130], [-12, 142], [-25, 150], [-38, 145], [-35, 115], [-20, 115]
    ]);
  }

  drawPolygon(coords) {
    const ctx = this.ctx;
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

  render() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    // 1. Fondo de océano
    ctx.fillStyle = '#060910';
    ctx.fillRect(0, 0, this.width, this.height);

    // 2. Grilla táctica y Continentes
    this.drawGrid();
    this.drawContinents();

    // 3. Puntos fijos
    this.points.forEach(pt => {
      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = pt.isThreat ? '#ff3366' : '#00e5ff';
      ctx.shadowColor = pt.isThreat ? '#ff3366' : '#00e5ff';
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    });

    // 4. Ondas pulsantes de tráfico en vivo
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.strokeStyle = p.color;
      ctx.lineWidth = 1.5;
      ctx.globalAlpha = p.alpha;
      ctx.stroke();
      ctx.globalAlpha = 1.0;

      p.radius += 0.5;
      p.alpha -= 0.025;

      if (p.alpha <= 0 || p.radius >= p.maxRadius) {
        this.pulses.splice(i, 1);
      }
    }

    requestAnimationFrame(this.render);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.mithrilMap = new TacticalWorldMap('tacticalMapCanvas');
});
