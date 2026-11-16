/**
 * MITHRIL SIEM - 2D Realistic Tactical World Map & Active Attack Vector System
 * - Cartografía mundial de alta fidelidad (costas detalladas, penínsulas, islas y relieve batimétrico)
 * - Pre-renderizado en Offscreen Canvas para mantener 60 FPS constantes sin colgar el navegador
 * - Flechas direccionales de ataque (➤) con estela luminosa (Comet Trail) y etiqueta de vector en vivo
 * - Emisor continuo de vectores para ataques activos / candidatos a bloqueo
 * - Identificación visual de nodos e IPs de Cloudflare CDN (☁️ CF)
 */

class TacticalWorldMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d', { alpha: false });

    this.bgCanvas = document.createElement('canvas');
    this.bgCtx = this.bgCanvas.getContext('2d', { alpha: false });

    this.points = [];
    this.pulses = [];
    this.arcs = [];
    this.nodes = [
      { id: 'default', name: 'Proxy Principal', status: 'ONLINE', latitude: -34.6037, longitude: -58.3816 }
    ];
    this.isFetching = false;
    this.threatCursorIdx = 0;

    this.mouse = { x: -100, y: -100, active: false };
    this.hoverPoint = null;

    this.showExternal = true;
    this.showLocal = true;
    this.showProbes = true;
    this.initFilterToggles();

    this.resize();
    window.addEventListener('resize', () => this.resize());

    this.canvas.addEventListener('mousemove', (e) => this.handleMouseMove(e), { passive: true });
    this.canvas.addEventListener('mouseleave', () => {
      this.mouse.active = false;
      this.hoverPoint = null;
    });

    this.fetchData();
    setInterval(() => this.fetchData(), 8000);

    // Re-emisor de flechas para ataques activos / candidatos para que el vector actual siempre sea visible
    setInterval(() => this.emitActiveThreatVectors(), 1800);

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

    this.bgCanvas.width = Math.floor(this.width * dpr);
    this.bgCanvas.height = Math.floor(this.height * dpr);
    this.bgCtx.setTransform(1, 0, 0, 1, 0, 0);
    this.bgCtx.scale(dpr, dpr);
    this.renderStaticBackground();
  }

  initFilterToggles() {
    const extToggle = document.getElementById('mapToggleExternal');
    const locToggle = document.getElementById('mapToggleLocal');
    const probesToggle = document.getElementById('mapToggleProbes');

    const savedExt = localStorage.getItem('mithril_map_show_external');
    if (savedExt !== null) {
      this.showExternal = (savedExt === 'true');
      if (extToggle) extToggle.checked = this.showExternal;
    } else if (extToggle) {
      this.showExternal = extToggle.checked;
    }

    const savedLoc = localStorage.getItem('mithril_map_show_local');
    if (savedLoc !== null) {
      this.showLocal = (savedLoc === 'true');
      if (locToggle) locToggle.checked = this.showLocal;
    } else if (locToggle) {
      this.showLocal = locToggle.checked;
    }

    const savedProbes = localStorage.getItem('mithril_map_show_probes');
    if (savedProbes !== null) {
      this.showProbes = (savedProbes === 'true');
      if (probesToggle) probesToggle.checked = this.showProbes;
    } else if (probesToggle) {
      this.showProbes = probesToggle.checked;
    }

    if (extToggle) {
      extToggle.addEventListener('change', () => {
        this.showExternal = extToggle.checked;
        localStorage.setItem('mithril_map_show_external', this.showExternal ? 'true' : 'false');
        this.onFilterChanged();
      });
    }

    if (locToggle) {
      locToggle.addEventListener('change', () => {
        this.showLocal = locToggle.checked;
        localStorage.setItem('mithril_map_show_local', this.showLocal ? 'true' : 'false');
        this.onFilterChanged();
      });
    }

    if (probesToggle) {
      probesToggle.addEventListener('change', () => {
        this.showProbes = probesToggle.checked;
        localStorage.setItem('mithril_map_show_probes', this.showProbes ? 'true' : 'false');
        this.onFilterChanged();
      });
    }
  }

  onFilterChanged() {
    // 1. Poda inmediata de arcos balísticos en vuelo que no cumplan los filtros activos
    this.arcs = this.arcs.filter(arc => {
      const isLoc = this.isItemLocal(arc);
      const isPrb = Boolean(arc.isProbe);
      if (isLoc && !this.showLocal) return false;
      if (!isLoc && !this.showExternal) return false;
      if (isPrb && !this.showProbes) return false;
      return true;
    });

    // 2. Poda inmediata de ondas de pulso que no cumplan los filtros activos
    this.pulses = this.pulses.filter(p => {
      const isLoc = Boolean(p.isLocal);
      const isPrb = Boolean(p.isProbe);
      if (isLoc && !this.showLocal) return false;
      if (!isLoc && !this.showExternal) return false;
      if (isPrb && !this.showProbes) return false;
      return true;
    });
  }

  isLocalIp(ip) {
    if (!ip) return false;
    const s = String(ip).trim().replace(/^🎯\s*/, '').replace(/^🏢\s*/, '');
    if (!s || s === '-' || s === '::1' || s.startsWith('127.')) return true;
    if (s.startsWith('10.') || s.startsWith('192.168.') || s.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s)) return true;
    return false;
  }

  isItemLocal(item) {
    if (!item) return false;
    if (item.isLocal !== undefined) return Boolean(item.isLocal);
    if (item.is_local !== undefined) return Boolean(item.is_local);
    if (item.realClientIp && this.isLocalIp(item.realClientIp)) return true;
    if (!item.isCloudflare && item.ip && this.isLocalIp(item.ip)) return true;
    if (item.country && (item.country.includes('LAN') || item.country.includes('Local'))) return true;
    return false;
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
      const isLoc = this.isItemLocal(pt);
      if (isLoc && !this.showLocal) continue;
      if (!isLoc && !this.showExternal) continue;
      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      if (Math.hypot(x - this.mouse.x, y - this.mouse.y) < 11) {
        this.hoverPoint = { ...pt, isLocal: isLoc, screenX: x, screenY: y };
        break;
      }
    }
  }

  getTargetNodeCoords(originX, originY, nodeName = '') {
    let targetNode = null;
    if (this.nodes && this.nodes.length > 0) {
      if (nodeName) {
        targetNode = this.nodes.find(n => n.name === nodeName) || null;
      }
      if (!targetNode) {
        targetNode = this.nodes[0];
      }
    } else {
      targetNode = { latitude: -34.6037, longitude: -58.3816, name: 'Proxy Principal' };
    }
    const target = this.geoToCanvas(targetNode.latitude, targetNode.longitude);

    // Si por alguna razón el origen coincide con el destino, desplazar origen para que la flecha siempre sea visible
    const dist = Math.hypot(originX - target.x, originY - target.y);
    if (dist < 25) {
      return {
        startX: Math.max(30, originX - 95),
        startY: Math.max(30, originY - 65),
        endX: target.x,
        endY: target.y
      };
    }
    return { startX: originX, startY: originY, endX: target.x, endY: target.y };
  }

  spawnTrajectoryArrow(startX, startY, endX, endY, color, isThreat, labelText, isCloudflare = false, isLocal = false, isProbe = false) {
    if (this.arcs.length >= 28) {
      this.arcs.shift();
    }
    const dx = endX - startX;
    const dy = endY - startY;
    const dist = Math.hypot(dx, dy);
    const arcLift = Math.min(110, Math.max(38, dist * 0.28));

    this.arcs.push({
      startX,
      startY,
      endX,
      endY,
      midX: (startX + endX) / 2,
      midY: Math.min(startY, endY) - arcLift,
      progress: 0.0,
      speed: isThreat ? 0.018 : 0.024,
      color,
      isThreat,
      isCloudflare,
      isLocal,
      isProbe: Boolean(isProbe),
      label: labelText || ''
    });
  }

  addLivePulse(lat, lon, isThreat = false, clientIp = '', isCloudflare = false, realClientIp = '', isLocal = false, isProbe = false, nodeName = '', countryCode = '', countryName = '') {
    if (window.mithrilParaguayMap) {
      window.mithrilParaguayMap.addLivePulse(lat, lon, isThreat, clientIp, isCloudflare, realClientIp, isLocal, isProbe, nodeName, countryCode, countryName);
    }
    const isLoc = Boolean(isLocal) || this.isLocalIp(realClientIp || clientIp);
    const probe = Boolean(isProbe) || (isCloudflare && !realClientIp);

    // Respetar de inmediato los filtros activos en el mapa táctico
    if (isLoc && !this.showLocal) return;
    if (!isLoc && !this.showExternal) return;
    if (probe && !this.showProbes) return;

    const coords = this.geoToCanvas(lat, lon);
    const isDirect = (!isCloudflare && !isLoc);
    const color = isThreat ? '#ff2a5f' : (isLoc ? '#c084fc' : (isCloudflare ? '#f6821f' : '#f87171'));

    if (this.pulses.length >= 35) {
      this.pulses.shift();
    }
    this.pulses.push({
      x: coords.x,
      y: coords.y,
      radius: 2,
      maxRadius: isThreat ? 30 : 18,
      alpha: 1.0,
      color: color,
      isThreat: isThreat,
      isLocal: isLoc,
      isProbe: probe,
      isDirect: isDirect
    });

    const vec = this.getTargetNodeCoords(coords.x, coords.y, nodeName);
    const realClient = realClientIp || (!isCloudflare ? clientIp : '');
    const primaryLabelIp = realClient || clientIp || 'IP';
    const cfNodeTag = (isCloudflare && clientIp && clientIp !== realClient) ? ' (☁️CF)' : (isCloudflare ? ' (☁️CF)' : '');
    const prefix = isThreat ? '🚨 ' : (isLoc ? '🏢 ' : '🎯 ');
    const tag = `${prefix}${primaryLabelIp}${cfNodeTag}`;
    this.spawnTrajectoryArrow(vec.startX, vec.startY, vec.endX, vec.endY, color, isThreat, tag, isCloudflare, isLoc, probe);

    const existingIdx = this.points.findIndex(p => Math.abs(p.lat - lat) < 0.1 && Math.abs(p.lon - lon) < 0.1);
    if (existingIdx !== -1) {
      if (isThreat) {
        this.points[existingIdx].isThreat = true;
        this.points[existingIdx].status_code = 403;
      }
      if (isCloudflare) {
        this.points[existingIdx].isCloudflare = true;
      }
      if (realClientIp) {
        this.points[existingIdx].realClientIp = realClientIp;
      }
      if (nodeName) {
        this.points[existingIdx].nodeName = nodeName;
      }
      this.points[existingIdx].isLocal = isLoc;
      this.points[existingIdx].isProbe = probe;
    } else {
      this.points.unshift({
        lat: lat,
        lon: lon,
        ip: clientIp,
        realClientIp: realClientIp,
        nodeName: nodeName,
        isThreat: isThreat,
        isCloudflare: isCloudflare,
        isLocal: isLoc,
        isProbe: probe,
        country: isLoc ? 'Red Local (LAN)' : '',
        status_code: isThreat ? 403 : 200
      });
      if (this.points.length > 90) this.points.pop();
    }
  }

  emitActiveThreatVectors() {
    // Mantiene visible la flecha de ataque actual para los atacantes/candidatos recientes en el mapa
    if (!this.points || this.points.length === 0) return;
    const activePoints = this.points.filter(p => {
      const isLoc = this.isItemLocal(p);
      const isPrb = Boolean(p.isProbe);
      if (isLoc && !this.showLocal) return false;
      if (!isLoc && !this.showExternal) return false;
      if (isPrb && !this.showProbes) return false;
      return true;
    });
    if (activePoints.length === 0) return;

    const threats = activePoints.filter(p => p.isThreat);
    const pool = threats.length > 0 ? threats.slice(0, 6) : activePoints.slice(0, 3);
    if (pool.length === 0) return;

    const pt = pool[this.threatCursorIdx % pool.length];
    this.threatCursorIdx += 1;

    const isLoc = this.isItemLocal(pt);
    const isDirect = (!pt.isCloudflare && !isLoc);
    const coords = this.geoToCanvas(pt.lat, pt.lon);
    const vec = this.getTargetNodeCoords(coords.x, coords.y, pt.nodeName || pt.node_name || '');
    const color = pt.isThreat ? '#ff2a5f' : (isLoc ? '#c084fc' : (pt.isCloudflare ? '#f6821f' : '#f87171'));
    const realClient = pt.realClientIp || (!pt.isCloudflare ? pt.ip : '');
    const primaryLabelIp = realClient || pt.ip || 'TRAFICO';
    const cfNodeTag = (pt.isCloudflare && pt.ip && pt.ip !== realClient) ? ' (☁️CF)' : (pt.isCloudflare ? ' (☁️CF)' : '');
    const prefix = pt.isThreat ? '🚨 ' : (isLoc ? '🏢 ' : '🎯 ');
    const label = `${prefix}${primaryLabelIp}${cfNodeTag}`;

    this.spawnTrajectoryArrow(vec.startX, vec.startY, vec.endX, vec.endY, color, pt.isThreat, label, pt.isCloudflare, isLoc, pt.isProbe);
    if (this.pulses.length < 25) {
      this.pulses.push({
        x: vec.startX,
        y: vec.startY,
        radius: 2,
        maxRadius: pt.isThreat ? 24 : 15,
        alpha: 0.9,
        color: color,
        isThreat: pt.isThreat,
        isLocal: isLoc,
        isProbe: Boolean(pt.isProbe)
      });
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
        if (window.mithrilParaguayMap) {
          window.mithrilParaguayMap.syncFromMapData(data);
        }
        if (data.nodes && Array.isArray(data.nodes) && data.nodes.length > 0) {
          this.nodes = data.nodes;
        }

        if (data.points && Array.isArray(data.points) && data.points.length > 0) {
          const hadNoPoints = this.points.length === 0;
          const incoming = data.points.map(p => ({
            lat: parseFloat(p.latitude) || 0,
            lon: parseFloat(p.longitude) || 0,
            ip: p.client_ip || '',
            realClientIp: p.real_client_ip || '',
            country: p.country_name || '',
            countryCode: p.country_code || '',
            nodeName: p.node_name || '',
            isThreat: Boolean(p.is_threat) || (p.status_code >= 400),
            isCloudflare: Boolean(p.is_cloudflare),
            isLocal: Boolean(p.is_local) || this.isLocalIp(p.real_client_ip || p.client_ip),
            isProbe: Boolean(p.is_probe) || (Boolean(p.is_cloudflare) && !p.real_client_ip),
            status_code: p.status_code
          }));
          this.points = incoming.slice(0, 90);

          if (hadNoPoints) {
            this.emitActiveThreatVectors();
          }
        }
      })
      .catch(err => {
        if (err.name !== 'AbortError') {
          console.debug('Error sincronizando mapa:', err);
        }
      })
      .finally(() => {
        clearTimeout(timeoutId);
        this.isFetching = false;
      });
  }

  // ==========================================
  // CARTOGRAFÍA MUNDIAL REALISTA DE ALTA RESOLUCIÓN
  // ==========================================

  getWorldPolygons() {
    return [
      // América del Norte (Alaska, Canadá, Bahía de Hudson, Costa Este, Florida, Golfo de México, Baja California, Centroamérica)
      [
        [71.3, -156.8], [70.2, -141.0], [69.5, -133.0], [68.5, -124.0], [68.8, -114.0], [67.8, -102.0],
        [64.2, -96.0], [63.0, -83.0], [58.5, -94.0], [54.8, -82.5], [51.3, -80.5], [54.0, -79.0],
        [58.8, -78.0], [62.5, -74.0], [60.5, -64.8], [55.0, -59.0], [52.0, -55.6], [47.5, -52.8],
        [46.8, -56.0], [49.0, -64.5], [47.0, -60.5], [44.6, -63.6], [43.5, -65.6], [45.0, -67.0],
        [43.6, -70.2], [41.7, -70.0], [40.6, -74.0], [38.9, -74.9], [36.9, -76.0], [35.2, -75.5],
        [32.8, -79.9], [30.3, -81.4], [25.2, -80.2], [25.1, -81.1], [27.8, -82.8], [29.9, -84.4],
        [30.2, -88.0], [29.1, -89.2], [29.6, -93.8], [27.8, -97.1], [25.9, -97.1], [22.2, -97.8],
        [19.2, -96.1], [18.1, -94.4], [18.6, -91.8], [21.2, -89.6], [21.5, -87.1], [18.2, -87.8],
        [15.8, -88.6], [15.9, -85.9], [15.0, -83.1], [11.0, -83.8], [9.9, -83.0], [9.4, -79.9],
        [8.9, -77.4], [7.2, -77.9], [8.1, -78.5], [8.5, -79.5], [7.5, -80.1], [8.3, -82.9],
        [10.0, -85.8], [12.5, -87.2], [13.7, -90.1], [14.5, -92.2], [16.2, -95.2], [16.9, -99.9],
        [18.0, -102.8], [20.4, -105.7], [23.2, -106.4], [27.9, -111.0], [31.3, -113.5], [31.8, -114.8],
        [28.0, -112.8], [22.9, -109.9], [24.8, -112.2], [27.8, -115.0], [30.5, -116.0], [32.6, -117.1],
        [34.4, -120.5], [37.8, -122.5], [40.4, -124.4], [46.2, -124.0], [48.4, -124.7], [49.3, -123.1],
        [54.2, -130.4], [58.3, -134.4], [59.8, -141.0], [60.0, -149.5], [58.8, -152.5], [55.0, -163.0],
        [58.5, -157.5], [60.5, -165.5], [63.5, -161.5], [64.5, -166.5], [66.3, -161.8], [68.9, -166.2],
        [70.5, -160.5]
      ],
      // Groenlandia
      [
        [83.2, -32.0], [81.5, -14.0], [76.5, -18.5], [70.5, -22.0], [68.0, -31.5], [65.5, -37.5],
        [62.5, -42.0], [59.8, -43.9], [61.0, -48.2], [64.2, -51.7], [68.5, -53.5], [72.5, -55.8],
        [76.0, -61.0], [77.5, -70.5], [78.5, -72.5], [81.2, -62.0], [82.5, -48.0]
      ],
      // Isla de Baffin / Ártico Canadiense
      [
        [73.5, -80.0], [70.5, -68.0], [66.5, -61.5], [62.0, -66.0], [64.0, -76.0], [68.5, -81.0], [71.5, -85.0]
      ],
      // Cuba y La Española
      [
        [23.1, -82.4], [22.5, -79.0], [21.1, -76.0], [19.9, -74.1], [19.8, -77.7], [21.6, -80.0], [21.8, -84.9]
      ],
      [
        [19.9, -72.8], [19.7, -70.0], [18.4, -68.4], [18.0, -71.7], [18.4, -74.4]
      ],
      // América del Sur (Colombia, Venezuela, Brasil, Río de la Plata, Patagonia, Tierra del Fuego, Chile, Perú, Ecuador)
      [
        [11.2, -74.2], [12.2, -71.2], [11.5, -69.5], [10.6, -66.9], [10.6, -62.0], [8.5, -60.0],
        [6.8, -58.1], [5.8, -55.2], [4.9, -52.3], [1.8, -50.0], [-0.2, -48.5], [-1.5, -44.3],
        [-2.9, -40.0], [-5.2, -35.5], [-8.0, -34.8], [-13.0, -38.5], [-17.8, -39.2], [-22.9, -42.0],
        [-23.0, -43.2], [-24.0, -46.3], [-25.5, -48.5], [-28.5, -48.8], [-32.0, -52.1], [-34.9, -54.9],
        [-35.5, -57.2], [-38.0, -57.5], [-38.9, -62.1], [-41.0, -62.8], [-42.8, -64.5], [-46.0, -67.5],
        [-47.8, -65.9], [-50.2, -68.5], [-52.4, -68.4], [-54.8, -65.2], [-55.6, -68.0], [-54.2, -71.5],
        [-52.0, -75.0], [-48.0, -75.2], [-43.5, -74.0], [-39.8, -73.4], [-36.8, -73.1], [-33.0, -71.6],
        [-29.9, -71.3], [-23.6, -70.4], [-18.5, -70.3], [-16.2, -73.6], [-13.8, -76.3], [-12.0, -77.1],
        [-8.1, -79.0], [-5.1, -81.1], [-3.4, -80.0], [-2.2, -80.9], [-0.9, -80.7], [0.9, -79.8],
        [2.5, -78.6], [4.0, -77.4], [7.2, -77.8], [8.6, -76.9], [10.4, -75.5]
      ],
      // Europa Continental (Península Ibérica, Francia, Italia, Grecia, Mar Negro, Escandinavia, Kola, Báltico)
      [
        [36.1, -5.6], [37.0, -8.9], [38.7, -9.4], [41.2, -8.7], [43.0, -9.3], [43.6, -5.7],
        [43.4, -1.8], [46.1, -1.2], [48.4, -4.7], [48.7, -1.6], [49.7, -1.9], [50.9, 1.6],
        [51.9, 4.1], [53.4, 5.5], [53.9, 8.7], [57.7, 10.6], [54.5, 10.2], [54.1, 12.1],
        [54.4, 18.6], [55.7, 21.1], [57.8, 22.5], [59.4, 24.7], [59.9, 29.8], [54.5, 19.5],
        [60.5, 27.5], [60.4, 22.2], [63.8, 22.8], [65.8, 24.1], [65.6, 22.1], [62.5, 17.5],
        [59.3, 18.1], [56.1, 15.6], [55.4, 13.0], [57.7, 11.9], [59.9, 10.7], [58.1, 8.0],
        [59.0, 5.6], [62.1, 5.1], [64.0, 10.0], [68.0, 14.0], [70.0, 19.0], [71.1, 25.8],
        [70.0, 29.5], [69.0, 33.1], [66.5, 40.5], [64.5, 40.5], [66.0, 34.5], [68.0, 39.5],
        [69.5, 60.0], [50.0, 55.0], [47.2, 39.7], [45.3, 36.6], [44.6, 33.5], [46.5, 30.7],
        [44.2, 28.6], [42.0, 27.9], [41.0, 29.0], [40.4, 26.7], [40.6, 22.9], [38.0, 24.0],
        [36.4, 22.5], [38.2, 21.7], [39.6, 20.1], [41.3, 19.4], [42.6, 18.1], [45.3, 14.4],
        [45.6, 13.8], [45.4, 12.3], [44.4, 12.3], [42.5, 14.2], [40.1, 18.5], [39.8, 18.3],
        [40.4, 17.2], [37.9, 15.6], [38.2, 12.7], [37.5, 15.1], [41.2, 13.5], [41.8, 12.2],
        [43.5, 10.3], [44.4, 8.9], [43.7, 7.3], [43.3, 5.4], [43.0, 3.0], [41.4, 2.2],
        [39.5, -0.3], [37.6, -1.0], [36.7, -4.4]
      ],
      // Reino Unido
      [
        [50.1, -5.2], [50.4, -3.5], [50.8, 0.2], [51.4, 1.4], [52.7, 1.7], [53.6, 0.1],
        [55.0, -1.4], [56.0, -3.1], [57.6, -1.8], [58.6, -3.1], [58.5, -5.0], [57.2, -5.8],
        [55.8, -5.6], [54.8, -5.0], [53.4, -3.0], [53.3, -4.6], [51.7, -5.1], [51.4, -3.2]
      ],
      // Irlanda
      [
        [51.5, -9.8], [52.2, -6.4], [53.3, -6.1], [55.2, -6.1], [55.3, -7.5], [54.2, -10.0], [52.6, -9.9]
      ],
      // Islandia
      [
        [63.5, -19.5], [64.4, -14.5], [66.2, -14.8], [66.5, -22.5], [65.5, -24.2], [64.1, -21.9]
      ],
      // África (Marruecos, Mediterráneo, Mar Rojo, Cuerno de África, Cabo de Buena Esperanza, Golfo de Guinea)
      [
        [35.8, -5.8], [35.2, -2.9], [36.8, 3.1], [37.3, 9.8], [34.8, 10.8], [32.9, 13.2],
        [31.0, 17.5], [32.8, 21.6], [31.5, 25.2], [31.2, 29.9], [31.5, 32.3], [29.9, 32.5],
        [27.2, 33.8], [22.0, 36.9], [18.5, 38.8], [15.6, 39.5], [12.6, 43.4], [11.6, 43.1],
        [11.8, 51.3], [8.5, 50.3], [4.5, 48.0], [2.0, 45.3], [-1.7, 41.5], [-4.0, 39.7],
        [-6.8, 39.3], [-10.5, 40.5], [-15.0, 40.7], [-19.8, 34.9], [-23.8, 35.5], [-25.9, 32.6],
        [-29.9, 31.0], [-33.0, 27.9], [-34.0, 25.6], [-34.8, 20.0], [-33.9, 18.4], [-28.6, 16.5],
        [-22.9, 14.5], [-17.2, 11.8], [-12.3, 13.6], [-8.8, 13.2], [-5.8, 12.2], [-0.7, 8.8],
        [4.0, 9.7], [4.5, 7.1], [6.4, 3.4], [5.5, -0.2], [4.8, -2.0], [5.2, -4.0],
        [4.4, -7.7], [6.3, -10.8], [8.5, -13.2], [11.8, -16.1], [14.7, -17.5], [18.1, -16.0],
        [20.9, -17.0], [23.7, -15.9], [27.9, -12.9], [30.4, -9.6], [33.6, -7.6]
      ],
      // Madagascar
      [
        [-12.0, 49.3], [-15.3, 50.4], [-19.5, 49.0], [-25.0, 47.0], [-25.5, 45.2],
        [-23.3, 43.7], [-19.0, 44.2], [-15.7, 46.3], [-13.5, 48.0]
      ],
      // Medio Oriente y Asia Continental (Anatolia, Arabia, India, Indochina, China, Corea, Kamchatka, Siberia)
      [
        [41.0, 29.1], [41.3, 36.3], [41.0, 40.5], [43.0, 41.0], [45.0, 38.0], [47.0, 39.5],
        [50.0, 55.0], [69.5, 60.0], [72.5, 70.0], [73.5, 80.5], [77.7, 104.3], [73.5, 114.0],
        [71.5, 130.0], [70.8, 150.0], [69.0, 170.0], [66.0, 179.0], [62.5, 179.0], [60.0, 165.0],
        [56.0, 163.0], [51.0, 156.7], [54.0, 155.8], [59.5, 150.8], [59.0, 142.0], [54.5, 137.0],
        [51.5, 140.8], [43.1, 131.9], [40.0, 128.0], [37.5, 129.2], [35.1, 129.0], [34.8, 126.4],
        [37.5, 126.6], [39.8, 124.3], [40.7, 122.2], [38.9, 121.6], [39.0, 117.7], [37.5, 122.1],
        [36.0, 120.3], [34.5, 119.5], [31.2, 121.5], [29.9, 122.0], [26.0, 119.6], [24.5, 118.1],
        [22.3, 114.2], [21.5, 111.0], [20.2, 110.0], [21.5, 108.5], [20.8, 106.7], [18.5, 105.8],
        [16.0, 108.2], [12.2, 109.2], [10.3, 107.1], [8.6, 104.8], [10.4, 104.5], [12.6, 101.2],
        [13.5, 100.6], [9.1, 99.3], [7.0, 100.6], [3.1, 103.4], [1.3, 103.8], [3.1, 101.4],
        [5.4, 100.3], [8.0, 98.3], [12.0, 98.6], [16.5, 97.6], [16.8, 94.3], [20.1, 92.9],
        [22.3, 91.8], [21.8, 89.0], [20.3, 86.7], [17.7, 83.3], [16.2, 81.2], [13.1, 80.3],
        [9.9, 78.1], [8.1, 77.5], [9.9, 76.3], [12.9, 74.8], [15.4, 73.8], [19.0, 72.8],
        [21.6, 72.2], [20.7, 70.9], [22.5, 69.0], [23.8, 68.5], [24.9, 67.0], [25.2, 62.3],
        [25.6, 57.8], [27.2, 56.3], [29.0, 50.8], [30.0, 48.5], [29.4, 48.0], [26.2, 50.2],
        [25.3, 51.5], [24.5, 54.4], [25.3, 56.4], [22.5, 59.8], [20.5, 58.9], [17.0, 54.1],
        [14.5, 49.1], [12.8, 45.0], [12.6, 43.5], [15.5, 42.7], [21.5, 39.2], [24.1, 38.0],
        [28.0, 34.6], [29.5, 34.9], [31.5, 34.5], [32.8, 35.0], [33.9, 35.5], [36.2, 35.9],
        [36.8, 34.6], [36.9, 30.7], [36.7, 27.4], [38.4, 27.1], [40.0, 26.2]
      ],
      // Sri Lanka
      [
        [9.8, 80.2], [8.5, 81.2], [6.0, 80.2], [7.5, 79.8]
      ],
      // Japón (Honshu, Hokkaido, Kyushu)
      [
        [45.5, 141.9], [43.3, 145.6], [42.0, 143.2], [41.5, 140.9], [39.7, 142.0], [35.7, 140.8],
        [34.7, 138.9], [33.5, 135.8], [33.9, 130.9], [31.2, 130.7], [32.8, 129.8], [34.4, 131.4],
        [35.6, 135.2], [37.5, 137.3], [39.7, 140.1], [41.2, 140.4], [43.2, 140.3]
      ],
      // Taiwán
      [
        [25.3, 121.6], [23.5, 121.5], [21.9, 120.8], [23.6, 120.1]
      ],
      // Filipinas (Luzón y Mindanao)
      [
        [18.5, 121.5], [16.0, 122.0], [13.0, 124.0], [14.5, 120.5], [16.5, 120.3]
      ],
      [
        [9.8, 125.5], [7.0, 126.5], [6.0, 124.5], [8.2, 122.5]
      ],
      // Indonesia (Sumatra, Java, Borneo, Sulawesi, Nueva Guinea)
      [
        [5.6, 95.3], [3.6, 98.7], [0.5, 103.5], [-3.0, 105.8], [-5.9, 105.7], [-3.8, 102.2], [0.0, 99.5]
      ],
      [
        [-6.0, 106.0], [-6.9, 112.5], [-8.4, 114.4], [-8.0, 110.5], [-6.8, 105.5]
      ],
      [
        [7.0, 117.0], [4.2, 117.9], [1.2, 118.8], [-3.5, 116.2], [-3.2, 111.8], [-1.0, 109.2], [1.8, 109.6], [4.9, 114.9]
      ],
      [
        [-0.8, 131.2], [-2.5, 140.7], [-6.5, 147.8], [-10.2, 150.5], [-9.1, 143.2], [-8.3, 138.9], [-4.5, 135.2], [-2.2, 132.0]
      ],
      // Australia
      [
        [-11.0, 142.5], [-14.5, 144.8], [-19.2, 146.8], [-23.5, 151.2], [-27.5, 153.2], [-33.9, 151.2],
        [-37.5, 150.0], [-38.8, 146.3], [-38.3, 141.5], [-35.5, 138.5], [-34.9, 135.8], [-32.2, 133.7],
        [-31.8, 128.0], [-33.9, 121.9], [-35.0, 117.9], [-33.9, 115.0], [-32.0, 115.8], [-27.8, 114.1],
        [-21.9, 114.1], [-20.3, 118.6], [-18.0, 122.2], [-14.5, 125.5], [-14.8, 129.0], [-12.4, 130.8],
        [-12.1, 136.8], [-16.5, 138.2], [-17.5, 140.8], [-12.6, 141.8]
      ],
      // Tasmania
      [
        [-40.8, 145.0], [-41.2, 148.3], [-43.5, 146.8], [-42.2, 145.2]
      ],
      // Nueva Zelanda (Isla Norte e Isla Sur)
      [
        [-34.5, 172.8], [-36.8, 174.8], [-37.7, 178.5], [-41.3, 174.8], [-39.3, 173.8], [-37.0, 174.2]
      ],
      [
        [-40.7, 172.7], [-41.5, 174.0], [-43.6, 172.7], [-46.5, 168.3], [-45.8, 166.5], [-42.5, 171.2]
      ]
    ];
  }

  renderStaticBackground() {
    const ctx = this.bgCtx;
    if (!ctx) return;

    // 1. Fondo oceánico con gradiente radial profundo estilo centro de mando satelital
    const oceanGrad = ctx.createRadialGradient(
      this.width * 0.5, this.height * 0.45, 40,
      this.width * 0.5, this.height * 0.5, Math.max(this.width, this.height) * 0.75
    );
    oceanGrad.addColorStop(0, '#071224');
    oceanGrad.addColorStop(0.6, '#040a15');
    oceanGrad.addColorStop(1, '#02050b');
    ctx.fillStyle = oceanGrad;
    ctx.fillRect(0, 0, this.width, this.height);

    // 2. Grilla geográfica de precisión
    ctx.strokeStyle = 'rgba(28, 52, 84, 0.35)';
    ctx.lineWidth = 0.5;

    for (let lat = -60; lat <= 80; lat += 20) {
      const y = ((90 - lat) / 180) * this.height;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(this.width, y);
      ctx.stroke();

      ctx.fillStyle = 'rgba(100, 130, 165, 0.45)';
      ctx.font = '9px monospace';
      ctx.fillText(`${lat}°`, 5, y - 3);
    }

    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * this.width;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, this.height);
      ctx.stroke();

      if (lon !== -180) {
        ctx.fillStyle = 'rgba(100, 130, 165, 0.45)';
        ctx.font = '9px monospace';
        ctx.fillText(`${lon}°`, x + 3, this.height - 5);
      }
    }

    // Ecuador y Greenwich
    const ecuadorY = 0.5 * this.height;
    const greenwichX = 0.5 * this.width;
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.16)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    ctx.moveTo(0, ecuadorY);
    ctx.lineTo(this.width, ecuadorY);
    ctx.moveTo(greenwichX, 0);
    ctx.lineTo(greenwichX, this.height);
    ctx.stroke();

    // 3. Continentes de alta fidelidad con halo batimétrico costero y sombreado topográfico
    const polygons = this.getWorldPolygons();
    const landGrad = ctx.createLinearGradient(0, 0, 0, this.height);
    landGrad.addColorStop(0, '#10243d');
    landGrad.addColorStop(0.5, '#0c1b2e');
    landGrad.addColorStop(1, '#091524');

    polygons.forEach(coords => {
      ctx.beginPath();
      coords.forEach((c, idx) => {
        const { x, y } = this.geoToCanvas(c[0], c[1]);
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.closePath();

      // Halo de plataforma continental
      ctx.strokeStyle = 'rgba(0, 195, 255, 0.12)';
      ctx.lineWidth = 3.5;
      ctx.stroke();

      // Relleno terrestre
      ctx.fillStyle = landGrad;
      ctx.fill();

      // Línea costera nítida
      ctx.strokeStyle = '#244b75';
      ctx.lineWidth = 1.05;
      ctx.stroke();
    });

    // 4. Nodos IXP mundiales de referencia sutil (ambientación realista SOC)
    const worldHubs = [
      [39.04, -77.48], [37.77, -122.41], [50.11, 8.68], [51.50, -0.12],
      [35.67, 139.65], [1.35, 103.81], [-23.55, -46.63], [40.41, -3.70],
      [-33.86, 151.20], [55.75, 37.61], [39.90, 116.40], [19.07, 72.87]
    ];
    ctx.fillStyle = 'rgba(0, 229, 255, 0.22)';
    worldHubs.forEach(h => {
      const { x, y } = this.geoToCanvas(h[0], h[1]);
      ctx.beginPath();
      ctx.arc(x, y, 1.4, 0, Math.PI * 2);
      ctx.fill();
    });
  }

  // ==========================================
  // RENDERIZADO PRINCIPAL LIGERO (60 FPS)
  // ==========================================

  drawArrowhead(ctx, x, y, angle, size, color) {
    ctx.save();
    ctx.translate(x, y);
    ctx.rotate(angle);
    ctx.beginPath();
    ctx.moveTo(size, 0);
    ctx.lineTo(-size * 0.85, -size * 0.58);
    ctx.lineTo(-size * 0.4, 0);
    ctx.lineTo(-size * 0.85, size * 0.58);
    ctx.closePath();
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    ctx.lineWidth = 1.3;
    ctx.strokeStyle = color;
    ctx.stroke();
    ctx.restore();
  }

  render() {
    const ctx = this.ctx;

    // 1. Copiar mapa mundial realista pre-renderizado
    ctx.drawImage(this.bgCanvas, 0, 0, this.width, this.height);

    // 2. Puntos de tráfico e incidentes activos (con halo Cloudflare naranja o Violeta LAN)
    for (let i = 0; i < this.points.length; i++) {
      const pt = this.points[i];
      const isLoc = this.isItemLocal(pt);
      const isPrb = Boolean(pt.isProbe);
      if (isLoc && !this.showLocal) continue;
      if (!isLoc && !this.showExternal) continue;
      if (isPrb && !this.showProbes) continue;

      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      const color = pt.isThreat
        ? '#ff2a5f'
        : (isLoc ? '#c084fc' : (pt.isCloudflare ? '#f6821f' : '#00e5ff'));

      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, pt.isThreat ? 3.6 : 3.0, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(x, y, pt.isThreat ? 7.5 : 6.0, 0, Math.PI * 2);
      ctx.strokeStyle = pt.isCloudflare ? '#f6821f' : (isLoc ? '#c084fc' : color);
      ctx.globalAlpha = pt.isThreat ? 0.55 : 0.35;
      ctx.lineWidth = (pt.isCloudflare || isLoc) ? 1.5 : 1.0;
      ctx.stroke();
      ctx.restore();
    }

    // 3. Arcos de trayectoria balística con Flecha Direccional de Ataque (➤) y Estela Luminosa
    for (let i = this.arcs.length - 1; i >= 0; i--) {
      const arc = this.arcs[i];
      const isLoc = this.isItemLocal(arc);
      const isPrb = Boolean(arc.isProbe);
      if ((isLoc && !this.showLocal) || (!isLoc && !this.showExternal) || (isPrb && !this.showProbes)) {
        arc.progress += arc.speed;
        if (arc.progress >= 1.0) {
          this.arcs.splice(i, 1);
        }
        continue;
      }
      const { startX, startY, midX, midY, endX, endY, progress: t, color, isThreat, label } = arc;

      ctx.save();
      // Línea guía punteada de toda la trayectoria
      ctx.beginPath();
      ctx.moveTo(startX, startY);
      ctx.quadraticCurveTo(midX, midY, endX, endY);
      ctx.strokeStyle = color;
      ctx.lineWidth = isThreat ? 1.4 : 1.0;
      ctx.globalAlpha = isThreat ? 0.42 : 0.25;
      ctx.setLineDash([4, 4]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Estela luminosa (Comet Trail) detrás de la flecha
      const trailSteps = 8;
      const trailLength = 0.22;
      for (let s = 0; s < trailSteps; s++) {
        const t0 = Math.max(0, t - (s + 1) * (trailLength / trailSteps));
        const t1 = Math.max(0, t - s * (trailLength / trailSteps));
        if (t1 <= 0) continue;

        const x0 = (1 - t0) * (1 - t0) * startX + 2 * (1 - t0) * t0 * midX + t0 * t0 * endX;
        const y0 = (1 - t0) * (1 - t0) * startY + 2 * (1 - t0) * t0 * midY + t0 * t0 * endY;
        const x1 = (1 - t1) * (1 - t1) * startX + 2 * (1 - t1) * t1 * midX + t1 * t1 * endX;
        const y1 = (1 - t1) * (1 - t1) * startY + 2 * (1 - t1) * t1 * midY + t1 * t1 * endY;

        ctx.beginPath();
        ctx.moveTo(x0, y0);
        ctx.lineTo(x1, y1);
        ctx.strokeStyle = color;
        ctx.globalAlpha = ((trailSteps - s) / trailSteps) * 0.9;
        ctx.lineWidth = isThreat ? 2.8 : 2.0;
        ctx.stroke();
      }

      // Posición actual y ángulo tangente de la flecha (derivada de la curva Bézier cuadrática)
      const curX = (1 - t) * (1 - t) * startX + 2 * (1 - t) * t * midX + t * t * endX;
      const curY = (1 - t) * (1 - t) * startY + 2 * (1 - t) * t * midY + t * t * endY;
      const tanX = 2 * (1 - t) * (midX - startX) + 2 * t * (endX - midX);
      const tanY = 2 * (1 - t) * (midY - startY) + 2 * t * (endY - midY);
      const angle = Math.atan2(tanY, tanX);

      ctx.globalAlpha = 1.0;
      this.drawArrowhead(ctx, curX, curY, angle, isThreat ? 7.5 : 5.8, color);

      // Etiqueta flotante junto a la flecha de ataque
      if (label && t > 0.12 && t < 0.88) {
        ctx.font = 'bold 9px monospace';
        ctx.fillStyle = isThreat ? '#fda4af' : '#fed7aa';
        ctx.fillText(label, curX + 9, curY - 7);
      }
      ctx.restore();

      arc.progress += arc.speed;
      if (arc.progress >= 1.0) {
        // Onda de impacto en el servidor proxy al llegar la flecha
        if (this.pulses.length < 35) {
          this.pulses.push({
            x: endX,
            y: endY,
            radius: 3,
            maxRadius: isThreat ? 26 : 16,
            alpha: 0.95,
            color: color,
            isThreat: isThreat
          });
        }
        this.arcs.splice(i, 1);
      }
    }

    // 4. Nodos Proxy de Nginx (Bases Defensivas Tácticas)
    const now = Date.now();
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const { x, y } = this.geoToCanvas(node.latitude, node.longitude);
      const isOnline = node.status === 'ONLINE';
      const nodeColor = isOnline ? '#00e676' : '#ff9900';

      ctx.save();
      const ringRadius = ((now / 20) % 26) + 6;
      const ringAlpha = 1 - (ringRadius - 6) / 26;
      ctx.beginPath();
      ctx.arc(x, y, ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = nodeColor;
      ctx.lineWidth = 1.6;
      ctx.globalAlpha = ringAlpha * 0.75;
      ctx.stroke();

      ctx.globalAlpha = 1.0;
      ctx.fillStyle = nodeColor;
      ctx.beginPath();
      ctx.moveTo(x, y - 6.5);
      ctx.lineTo(x + 6.5, y);
      ctx.lineTo(x, y + 6.5);
      ctx.lineTo(x - 6.5, y);
      ctx.closePath();
      ctx.fill();

      ctx.font = 'bold 10px monospace';
      ctx.fillStyle = '#f8fafc';
      ctx.fillText(`🛡️ [NODO] ${node.name}`, x + 10, y + 3);
      ctx.restore();
    }

    // 5. Ondas sónicas pulsantes en vivo
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      const isLoc = Boolean(p.isLocal);
      const isPrb = Boolean(p.isProbe);
      if ((isLoc && !this.showLocal) || (!isLoc && !this.showExternal) || (isPrb && !this.showProbes)) {
        p.radius += 0.65;
        p.alpha -= 0.028;
        if (p.alpha <= 0 || p.radius >= p.maxRadius) {
          this.pulses.splice(i, 1);
        }
        continue;
      }

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
      ctx.fillStyle = 'rgba(0, 229, 255, 0.85)';
      ctx.fillText(`${geo.lat.toFixed(2)}°, ${geo.lon.toFixed(2)}°`, this.mouse.x + 8, this.mouse.y - 8);

      if (this.hoverPoint) {
        const hp = this.hoverPoint;
        const mainIp = hp.realClientIp || hp.ip || '';
        const cfSuffix = (hp.isCloudflare && hp.realClientIp && hp.ip !== hp.realClientIp)
          ? ` [☁️ Nodo CF: ${hp.ip}]`
          : (hp.isCloudflare ? ' [☁️ CF]' : (hp.isLocal ? ' [🏢 LAN]' : ' [🎯 DIR IP]'));
        const text = `🎯 ${mainIp}${cfSuffix} (${hp.country || (hp.isLocal ? 'Red Local' : 'Remoto')}) [HTTP ${hp.status_code || 200}]`;
        const boxW = text.length * 6.5 + 16;
        const boxX = Math.min(this.width - boxW - 6, Math.max(6, hp.screenX + 12));
        const boxY = Math.max(6, hp.screenY - 26);

        ctx.fillStyle = 'rgba(8, 13, 25, 0.94)';
        ctx.strokeStyle = hp.isThreat ? '#ff2a5f' : (hp.isLocal ? '#c084fc' : (hp.isCloudflare ? '#f6821f' : '#f87171'));
        ctx.lineWidth = 1.2;
        ctx.fillRect(boxX, boxY, boxW, 22);
        ctx.strokeRect(boxX, boxY, boxW, 22);

        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 10px monospace';
        ctx.fillText(text, boxX + 7, boxY + 14);
      }
      ctx.restore();
    }

    requestAnimationFrame(this.render);
  }
}

/**
 * MITHRIL SIEM - 2D Tactical Paraguay Map (Exclusivo para Tráfico Nacional de Paraguay y LAN)
 * - Soporta Zoom interactivo (1x a 18x con rueda del ratón o botones) y Paneo (Click & Drag)
 * - Modo de enfoque directo en Gran Asunción / Departamento Central (🎯 Capital)
 * - Marcadores de origen explícitos (◎ + Etiqueta 📍 Zona/Ciudad) anclados geográficamente
 */
class TacticalParaguayMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d', { alpha: false });

    this.bgCanvas = document.createElement('canvas');
    this.bgCtx = this.bgCanvas.getContext('2d', { alpha: false });

    // Límites geográficos de Paraguay con margen táctico
    this.bounds = {
      minLat: -28.0,
      maxLat: -18.8,
      minLon: -63.1,
      maxLon: -53.8,
    };

    // Estado de cámara interactiva (Zoom & Pan)
    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.isDragging = false;
    this.dragStart = { x: 0, y: 0 };

    this.points = [];
    this.pulses = [];
    this.arcs = [];
    this.nodes = [
      { id: 'default', name: 'Proxy Principal', status: 'ONLINE', latitude: -25.2820, longitude: -57.6350 }
    ];
    this.threatCursorIdx = 0;
    this.mouse = { x: -100, y: -100, active: false };
    this.hoverPoint = null;

    this.showPublic = true;
    this.showLocal = true;
    this.initFilterToggles();
    this.initCameraControls();

    // Zonas de Gran Asunción / Central y ciudades departamentales para distribuir IPs nacionales con separación clara del Nodo Proxy
    this.pyZones = [
      { name: 'Villa Morra (Asunción)', lat: -25.2940, lon: -57.5800 },
      { name: 'Sajonia (Asunción)', lat: -25.2760, lon: -57.6620 },
      { name: 'Lambaré', lat: -25.3460, lon: -57.6060 },
      { name: 'Fernando de la Mora', lat: -25.3210, lon: -57.5520 },
      { name: 'San Lorenzo', lat: -25.3440, lon: -57.5080 },
      { name: 'Luque', lat: -25.2667, lon: -57.4850 },
      { name: 'Mariano Roque Alonso', lat: -25.2080, lon: -57.5320 },
      { name: 'Capiatá', lat: -25.3550, lon: -57.4450 },
      { name: 'Ñemby', lat: -25.3950, lon: -57.5440 },
      { name: 'Limpio', lat: -25.1660, lon: -57.4850 },
      { name: 'Ciudad del Este', lat: -25.5097, lon: -54.6111 },
      { name: 'Encarnación', lat: -27.3306, lon: -55.8667 },
      { name: 'Coronel Oviedo', lat: -25.4444, lon: -56.4406 },
      { name: 'Pedro Juan Caballero', lat: -22.5472, lon: -55.7333 },
      { name: 'Concepción', lat: -23.4064, lon: -57.4344 },
      { name: 'Villarrica', lat: -25.7806, lon: -56.4486 },
      { name: 'Caacupé', lat: -25.3861, lon: -57.1408 },
      { name: 'Pilar', lat: -26.8681, lon: -58.2953 },
      { name: 'Salto del Guairá', lat: -24.0625, lon: -54.3069 },
      { name: 'San Ignacio (Misiones)', lat: -26.8833, lon: -57.0333 },
      { name: 'Filadelfia (Chaco)', lat: -22.3500, lon: -60.0333 },
    ];

    this.resize();
    window.addEventListener('resize', () => this.resize());

    setInterval(() => this.emitActiveVectors(), 2000);

    this.render = this.render.bind(this);
    requestAnimationFrame(this.render);
  }

  initFilterToggles() {
    const pubToggle = document.getElementById('pyMapTogglePublic');
    const locToggle = document.getElementById('pyMapToggleLocal');

    const savedPub = localStorage.getItem('mithril_py_map_show_public');
    if (savedPub !== null) {
      this.showPublic = (savedPub === 'true');
      if (pubToggle) pubToggle.checked = this.showPublic;
    } else if (pubToggle) {
      this.showPublic = pubToggle.checked;
    }

    const savedLoc = localStorage.getItem('mithril_py_map_show_local');
    if (savedLoc !== null) {
      this.showLocal = (savedLoc === 'true');
      if (locToggle) locToggle.checked = this.showLocal;
    } else if (locToggle) {
      this.showLocal = locToggle.checked;
    }

    if (pubToggle) {
      pubToggle.addEventListener('change', () => {
        this.showPublic = pubToggle.checked;
        localStorage.setItem('mithril_py_map_show_public', this.showPublic ? 'true' : 'false');
      });
    }
    if (locToggle) {
      locToggle.addEventListener('change', () => {
        this.showLocal = locToggle.checked;
        localStorage.setItem('mithril_py_map_show_local', this.showLocal ? 'true' : 'false');
      });
    }
  }

  initCameraControls() {
    // Zoom con rueda del ratón centrado en la posición del cursor
    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.28 : (1 / 1.28);
      this.zoomAt(mx, my, factor);
    }, { passive: false });

    // Arrastrar (Pan) con clic izquierdo
    this.canvas.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      this.isDragging = true;
      this.dragStart.x = e.clientX - this.panX;
      this.dragStart.y = e.clientY - this.panY;
      this.canvas.style.cursor = 'grabbing';
    });

    window.addEventListener('mouseup', () => {
      if (this.isDragging) {
        this.isDragging = false;
        if (this.canvas) this.canvas.style.cursor = 'grab';
      }
    });

    this.canvas.addEventListener('mousemove', (e) => {
      if (this.isDragging) {
        this.panX = e.clientX - this.dragStart.x;
        this.panY = e.clientY - this.dragStart.y;
        this.clampPan();
        this.renderStaticBackground();
      }
      this.handleMouseMove(e);
    }, { passive: true });

    this.canvas.addEventListener('mouseleave', () => {
      this.mouse.active = false;
      this.hoverPoint = null;
    });

    // Doble clic para acercar al punto deseado
    this.canvas.addEventListener('dblclick', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.zoomAt(e.clientX - rect.left, e.clientY - rect.top, 2.0);
    });

    const zoomInBtn = document.getElementById('pyMapZoomInBtn');
    const zoomOutBtn = document.getElementById('pyMapZoomOutBtn');
    const focusCapBtn = document.getElementById('pyMapFocusCapitalBtn');
    const resetBtn = document.getElementById('pyMapResetViewBtn');

    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', () => this.zoomAt(this.width / 2, this.height / 2, 1.45));
    }
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', () => this.zoomAt(this.width / 2, this.height / 2, 1 / 1.45));
    }
    if (focusCapBtn) {
      focusCapBtn.addEventListener('click', () => this.focusOnGeo(-25.305, -57.545, 5.2));
    }
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        this.zoom = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.renderStaticBackground();
      });
    }
  }

  zoomAt(cx, cy, factor) {
    const geoBefore = this.canvasToGeo(cx, cy);
    this.zoom = Math.max(1.0, Math.min(18.0, this.zoom * factor));
    if (this.zoom <= 1.02) {
      this.zoom = 1.0;
      this.panX = 0;
      this.panY = 0;
    } else {
      const afterPos = this.geoToCanvas(geoBefore.lat, geoBefore.lon);
      this.panX += (cx - afterPos.x);
      this.panY += (cy - afterPos.y);
      this.clampPan();
    }
    this.renderStaticBackground();
  }

  focusOnGeo(lat, lon, targetZoom = 5.0) {
    this.zoom = Math.max(1.0, Math.min(18.0, targetZoom));
    this.panX = 0;
    this.panY = 0;
    const pos = this.geoToCanvas(lat, lon);
    this.panX = (this.width / 2) - pos.x;
    this.panY = (this.height / 2) - pos.y;
    this.clampPan();
    this.renderStaticBackground();
  }

  clampPan() {
    const maxPanX = this.width * (this.zoom - 0.5);
    const maxPanY = this.height * (this.zoom - 0.5);
    this.panX = Math.max(-maxPanX, Math.min(maxPanX, this.panX));
    this.panY = Math.max(-maxPanY, Math.min(maxPanY, this.panY));
  }

  resize() {
    const parent = this.canvas.parentElement;
    if (!parent) return;

    this.width = parent.clientWidth || 420;
    this.height = parent.clientHeight || 440;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.canvas.width = Math.floor(this.width * dpr);
    this.canvas.height = Math.floor(this.height * dpr);
    this.ctx.setTransform(1, 0, 0, 1, 0, 0);
    this.ctx.scale(dpr, dpr);

    this.bgCanvas.width = Math.floor(this.width * dpr);
    this.bgCanvas.height = Math.floor(this.height * dpr);
    this.bgCtx.setTransform(1, 0, 0, 1, 0, 0);
    this.bgCtx.scale(dpr, dpr);
    this.renderStaticBackground();
  }

  getBaseProjection() {
    const padX = 24;
    const padY = 24;
    const availW = Math.max(100, this.width - padX * 2);
    const availH = Math.max(100, this.height - padY * 2);
    const lonSpan = this.bounds.maxLon - this.bounds.minLon;
    const latSpan = this.bounds.maxLat - this.bounds.minLat;
    const baseScale = Math.min(availW / lonSpan, availH / latSpan);
    const mapW = lonSpan * baseScale;
    const mapH = latSpan * baseScale;
    const offsetX = (this.width - mapW) / 2;
    const offsetY = (this.height - mapH) / 2;
    return { lonSpan, latSpan, mapW, mapH, offsetX, offsetY };
  }

  geoToCanvas(lat, lon) {
    const { lonSpan, latSpan, mapW, mapH, offsetX, offsetY } = this.getBaseProjection();
    const baseX = offsetX + ((lon - this.bounds.minLon) / lonSpan) * mapW;
    const baseY = offsetY + ((this.bounds.maxLat - lat) / latSpan) * mapH;
    const cx = this.width / 2;
    const cy = this.height / 2;
    return {
      x: cx + (baseX - cx) * this.zoom + this.panX,
      y: cy + (baseY - cy) * this.zoom + this.panY
    };
  }

  canvasToGeo(x, y) {
    const { lonSpan, latSpan, mapW, mapH, offsetX, offsetY } = this.getBaseProjection();
    const cx = this.width / 2;
    const cy = this.height / 2;
    const baseX = (x - this.panX - cx) / this.zoom + cx;
    const baseY = (y - this.panY - cy) / this.zoom + cy;
    const lon = this.bounds.minLon + ((baseX - offsetX) / mapW) * lonSpan;
    const lat = this.bounds.maxLat - ((baseY - offsetY) / mapH) * latSpan;
    return { lat, lon };
  }

  hashIp(ipStr) {
    let h = 2166136261;
    const s = String(ipStr || '');
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return Math.abs(h);
  }

  resolveParaguayCoords(lat, lon, ipStr, isLocal) {
    // El backend aplica un jitter de ±0.28° sobre el centroide de PY (-25.2637, -57.5759).
    // Si cae en ese radio genérico, asignamos determinísticamente a una zona/ciudad real bien diferenciada del Nodo Proxy.
    const isGenericCentroid = (Math.abs(lat - (-25.2637)) < 0.36 && Math.abs(lon - (-57.5759)) < 0.36) || (!lat && !lon);
    if (!isGenericCentroid && lat >= -27.8 && lat <= -19.2 && lon >= -62.7 && lon <= -54.2) {
      return { lat, lon, zoneName: 'Paraguay' };
    }
    const h = this.hashIp(ipStr || 'py');
    const zone = this.pyZones[h % this.pyZones.length];
    const jitterLat = (((h >> 4) % 100) - 50) * 0.0022;
    const jitterLon = (((h >> 11) % 100) - 50) * 0.0022;
    return {
      lat: zone.lat + jitterLat,
      lon: zone.lon + jitterLon,
      zoneName: isLocal ? `LAN • ${zone.name}` : zone.name
    };
  }

  isParaguayEvent(lat, lon, countryCode, countryName, isLocal, isProbe) {
    if (isProbe) return false;
    if (isLocal) return true;
    const cc = String(countryCode || '').toUpperCase().trim();
    const cn = String(countryName || '').toLowerCase().trim();
    if (cc === 'PY' || cc === 'LAN' || cn.includes('paraguay') || cn.includes('asunción') || cn.includes('asuncion') || cn.includes('local')) {
      return true;
    }
    if (lat >= -27.7 && lat <= -19.2 && lon >= -62.7 && lon <= -54.2) {
      return true;
    }
    return false;
  }

  getNodeGeo(nodeName = '') {
    let idx = 0;
    if (nodeName && this.nodes.length > 1) {
      const found = this.nodes.findIndex(n => n.name === nodeName);
      if (found !== -1) idx = found;
    }
    // Base defensiva en Microcentro Asunción (-25.2820, -57.6350)
    return {
      lat: -25.2820 + (idx * 0.06),
      lon: -57.6350 - (idx * 0.06)
    };
  }

  syncFromMapData(data) {
    if (!data) return;
    if (data.nodes && Array.isArray(data.nodes) && data.nodes.length > 0) {
      this.nodes = data.nodes;
    }
    if (data.points && Array.isArray(data.points)) {
      const hadNoPoints = this.points.length === 0;
      const pyPoints = [];
      const seenIps = new Set();
      for (const p of data.points) {
        const lat = parseFloat(p.latitude) || 0;
        const lon = parseFloat(p.longitude) || 0;
        const isLoc = Boolean(p.is_local);
        const isPrb = Boolean(p.is_probe) || (Boolean(p.is_cloudflare) && !p.real_client_ip);
        if (!this.isParaguayEvent(lat, lon, p.country_code, p.country_name, isLoc, isPrb)) {
          continue;
        }
        const mainIp = p.real_client_ip || p.client_ip || '';
        const resolved = this.resolveParaguayCoords(lat, lon, mainIp, isLoc);
        const isThr = Boolean(p.is_threat) || (p.status_code >= 400);
        if (seenIps.has(mainIp)) {
          const ex = pyPoints.find(item => (item.realClientIp || item.ip) === mainIp);
          if (ex && isThr) {
            ex.isThreat = true;
            ex.status_code = p.status_code || 403;
          }
          continue;
        }
        seenIps.add(mainIp);
        pyPoints.push({
          lat: resolved.lat,
          lon: resolved.lon,
          zoneName: resolved.zoneName,
          ip: p.client_ip || '',
          realClientIp: p.real_client_ip || '',
          nodeName: p.node_name || '',
          isThreat: isThr,
          isCloudflare: Boolean(p.is_cloudflare),
          isLocal: isLoc,
          status_code: p.status_code || 200
        });
      }
      if (pyPoints.length > 0) {
        this.points = pyPoints.slice(0, 60);
        if (hadNoPoints) {
          this.emitActiveVectors();
        }
      }
    }
  }

  addLivePulse(lat, lon, isThreat = false, clientIp = '', isCloudflare = false, realClientIp = '', isLocal = false, isProbe = false, nodeName = '', countryCode = '', countryName = '') {
    if (!this.isParaguayEvent(lat, lon, countryCode, countryName, isLocal, isProbe)) {
      return;
    }
    if (isLocal && !this.showLocal) return;
    if (!isLocal && !this.showPublic) return;

    const mainIp = realClientIp || clientIp || 'PY';
    const resolved = this.resolveParaguayCoords(lat, lon, mainIp, isLocal);
    const nodeGeo = this.getNodeGeo(nodeName);
    const color = isThreat ? '#ff2a5f' : (isLocal ? '#c084fc' : '#00e5ff');

    if (this.pulses.length >= 25) this.pulses.shift();
    this.pulses.push({
      lat: resolved.lat,
      lon: resolved.lon,
      radius: 2,
      maxRadius: isThreat ? 26 : 16,
      alpha: 1.0,
      color,
      isThreat,
      isLocal
    });

    const prefix = isThreat ? '🚨 ' : (isLocal ? '🏢 ' : '🎯 ');
    const label = `${prefix}${mainIp} (${resolved.zoneName})`;
    this.spawnGeoArc(resolved.lat, resolved.lon, nodeGeo.lat, nodeGeo.lon, color, isThreat, label, isLocal);

    const existingIdx = this.points.findIndex(pt => (pt.realClientIp || pt.ip) === mainIp);
    if (existingIdx !== -1) {
      if (isThreat) {
        this.points[existingIdx].isThreat = true;
        this.points[existingIdx].status_code = 403;
      }
    } else {
      this.points.unshift({
        lat: resolved.lat,
        lon: resolved.lon,
        zoneName: resolved.zoneName,
        ip: clientIp,
        realClientIp: realClientIp,
        nodeName: nodeName,
        isThreat: isThreat,
        isCloudflare: isCloudflare,
        isLocal: isLocal,
        status_code: isThreat ? 403 : 200
      });
      if (this.points.length > 60) this.points.pop();
    }
  }

  spawnGeoArc(startLat, startLon, endLat, endLon, color, isThreat, label, isLocal) {
    if (this.arcs.length >= 16) this.arcs.shift();
    this.arcs.push({
      startLat,
      startLon,
      endLat,
      endLon,
      progress: 0.0,
      speed: isThreat ? 0.019 : 0.025,
      color,
      isThreat,
      isLocal: Boolean(isLocal),
      label: label || ''
    });
  }

  emitActiveVectors() {
    if (!this.points || this.points.length === 0) return;
    const visible = this.points.filter(p => (p.isLocal ? this.showLocal : this.showPublic));
    if (visible.length === 0) return;
    const threats = visible.filter(p => p.isThreat);
    const pool = threats.length > 0 ? threats.slice(0, 6) : visible.slice(0, 4);
    const pt = pool[this.threatCursorIdx % pool.length];
    this.threatCursorIdx += 1;

    const nodeGeo = this.getNodeGeo(pt.nodeName);
    const color = pt.isThreat ? '#ff2a5f' : (pt.isLocal ? '#c084fc' : '#00e5ff');
    const mainIp = pt.realClientIp || pt.ip || 'PY';
    const prefix = pt.isThreat ? '🚨 ' : (pt.isLocal ? '🏢 ' : '🎯 ');
    const label = `${prefix}${mainIp} (${pt.zoneName || 'PY'})`;
    this.spawnGeoArc(pt.lat, pt.lon, nodeGeo.lat, nodeGeo.lon, color, pt.isThreat, label, pt.isLocal);
    if (this.pulses.length < 20) {
      this.pulses.push({
        lat: pt.lat,
        lon: pt.lon,
        radius: 2,
        maxRadius: pt.isThreat ? 22 : 14,
        alpha: 0.9,
        color,
        isThreat: pt.isThreat,
        isLocal: pt.isLocal
      });
    }
  }

  handleMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    this.mouse.x = e.clientX - rect.left;
    this.mouse.y = e.clientY - rect.top;
    this.mouse.active = true;

    this.hoverPoint = null;
    for (let i = 0; i < this.points.length; i++) {
      const pt = this.points[i];
      if (pt.isLocal && !this.showLocal) continue;
      if (!pt.isLocal && !this.showPublic) continue;
      const { x, y } = this.geoToCanvas(pt.lat, pt.lon);
      if (Math.hypot(x - this.mouse.x, y - this.mouse.y) < 12) {
        this.hoverPoint = { ...pt, screenX: x, screenY: y };
        break;
      }
    }
  }

  renderStaticBackground() {
    const ctx = this.bgCtx;
    const w = this.width;
    const h = this.height;

    const bgGrad = ctx.createRadialGradient(w * 0.5, h * 0.5, 20, w * 0.5, h * 0.5, Math.max(w, h) * 0.75);
    bgGrad.addColorStop(0, '#091426');
    bgGrad.addColorStop(1, '#040811');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, w, h);

    // Retícula táctica de coordenadas de Paraguay
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.06)';
    ctx.lineWidth = 0.6;
    ctx.font = '8px monospace';
    ctx.fillStyle = 'rgba(100, 116, 139, 0.45)';
    const gridStep = this.zoom >= 3.0 ? 0.25 : 2;
    for (let lat = -27; lat <= -19; lat += gridStep) {
      const { y } = this.geoToCanvas(lat, this.bounds.minLon);
      if (y < 0 || y > h) continue;
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
      ctx.fillText(`${lat.toFixed(gridStep < 1 ? 2 : 0)}°S`, 6, y - 3);
    }
    for (let lon = -62; lon <= -54; lon += gridStep) {
      const { x } = this.geoToCanvas(this.bounds.maxLat, lon);
      if (x < 0 || x > w) continue;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }

    // Contorno nacional de Paraguay de alta precisión (Chaco + Región Oriental)
    const pyBorder = [
      [-22.23, -62.64], [-20.55, -62.25], [-19.90, -61.92], [-19.62, -60.60],
      [-19.29, -59.97], [-19.65, -58.85], [-19.85, -58.18], [-20.17, -58.16],
      [-21.04, -57.87], [-21.68, -57.89], [-22.09, -57.95], [-22.12, -57.15],
      [-22.28, -56.40], [-22.54, -55.73], [-23.25, -55.52], [-23.88, -55.45],
      [-24.06, -54.31], [-24.75, -54.35], [-25.51, -54.61], [-26.05, -54.68],
      [-26.55, -54.92], [-27.10, -55.45], [-27.33, -55.87], [-27.55, -56.40],
      [-27.28, -56.72], [-27.38, -57.62], [-27.29, -58.60], [-26.87, -58.30],
      [-26.15, -58.18], [-25.28, -57.64], [-25.05, -57.85], [-24.65, -58.80],
      [-23.90, -60.20], [-23.10, -61.35], [-22.23, -62.64]
    ];

    ctx.save();
    ctx.beginPath();
    pyBorder.forEach(([lat, lon], idx) => {
      const { x, y } = this.geoToCanvas(lat, lon);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.closePath();

    const landGrad = ctx.createLinearGradient(0, 0, w, h);
    landGrad.addColorStop(0, '#10243e');
    landGrad.addColorStop(1, '#0b182c');
    ctx.fillStyle = landGrad;
    ctx.fill();

    ctx.shadowColor = 'rgba(0, 229, 255, 0.45)';
    ctx.shadowBlur = 8;
    ctx.strokeStyle = 'rgba(0, 229, 255, 0.72)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.restore();

    // Río Paraguay (División Región Occidental / Chaco y Región Oriental)
    const rioParaguay = [
      [-20.17, -58.16], [-21.04, -57.87], [-22.09, -57.95], [-22.80, -57.70],
      [-23.41, -57.44], [-24.15, -57.18], [-25.09, -57.52], [-25.28, -57.64],
      [-25.85, -57.75], [-26.87, -58.30], [-27.29, -58.60]
    ];
    ctx.save();
    ctx.beginPath();
    rioParaguay.forEach(([lat, lon], idx) => {
      const { x, y } = this.geoToCanvas(lat, lon);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.42)';
    ctx.lineWidth = 1.3;
    ctx.setLineDash([4, 3]);
    ctx.stroke();
    ctx.restore();

    // Ciudades de referencia nacional y localidades de Gran Asunción al acercar el zoom
    const refCities = [
      { name: 'Asunción', lat: -25.2820, lon: -57.6350, capital: true, minZoom: 1.0 },
      { name: 'Ciudad del Este', lat: -25.5097, lon: -54.6111, minZoom: 1.0 },
      { name: 'Encarnación', lat: -27.3306, lon: -55.8667, minZoom: 1.0 },
      { name: 'Pedro Juan Caballero', lat: -22.5472, lon: -55.7333, minZoom: 1.0 },
      { name: 'Concepción', lat: -23.4064, lon: -57.4344, minZoom: 1.0 },
      { name: 'Cnel. Oviedo', lat: -25.4444, lon: -56.4406, minZoom: 1.0 },
      { name: 'Villarrica', lat: -25.7806, lon: -56.4486, minZoom: 1.4 },
      { name: 'Pilar', lat: -26.8681, lon: -58.2953, minZoom: 1.0 },
      { name: 'Filadelfia (Chaco)', lat: -22.3500, lon: -60.0333, minZoom: 1.0 },
      { name: 'Caacupé', lat: -25.3861, lon: -57.1408, minZoom: 1.8 },
      // Sub-zonas de Gran Asunción / Central visibles al acercar el zoom
      { name: 'Villa Morra', lat: -25.2940, lon: -57.5800, minZoom: 2.2 },
      { name: 'Sajonia', lat: -25.2760, lon: -57.6620, minZoom: 2.5 },
      { name: 'Lambaré', lat: -25.3460, lon: -57.6060, minZoom: 2.0 },
      { name: 'Fdo. de la Mora', lat: -25.3210, lon: -57.5520, minZoom: 2.2 },
      { name: 'San Lorenzo', lat: -25.3440, lon: -57.5080, minZoom: 1.8 },
      { name: 'Luque', lat: -25.2667, lon: -57.4850, minZoom: 1.8 },
      { name: 'M. R. Alonso', lat: -25.2080, lon: -57.5320, minZoom: 2.2 },
      { name: 'Limpio', lat: -25.1660, lon: -57.4850, minZoom: 2.2 },
      { name: 'Capiatá', lat: -25.3550, lon: -57.4450, minZoom: 2.0 },
      { name: 'Ñemby', lat: -25.3950, lon: -57.5440, minZoom: 2.2 },
    ];

    ctx.save();
    refCities.forEach(c => {
      if (this.zoom < (c.minZoom || 1.0)) return;
      const { x, y } = this.geoToCanvas(c.lat, c.lon);
      if (x < -20 || x > w + 20 || y < -20 || y > h + 20) return;
      ctx.fillStyle = c.capital ? 'rgba(0, 230, 118, 0.85)' : 'rgba(148, 163, 184, 0.55)';
      ctx.beginPath();
      ctx.arc(x, y, c.capital ? 2.8 : 1.8, 0, Math.PI * 2);
      ctx.fill();

      ctx.font = c.capital ? 'bold 9px monospace' : '8px monospace';
      ctx.fillStyle = c.capital ? 'rgba(226, 232, 240, 0.9)' : 'rgba(148, 163, 184, 0.68)';
      ctx.fillText(c.name, x + 5, y + 3);
    });
    ctx.restore();
  }

  render() {
    const ctx = this.ctx;
    ctx.drawImage(this.bgCanvas, 0, 0, this.width, this.height);

    // 1. Puntos de origen en Paraguay (con marcador tipo diana ◎ y etiqueta de origen explícita)
    let labelsDrawn = 0;
    for (let i = 0; i < this.points.length; i++) {
      const p = this.points[i];
      if (p.isLocal && !this.showLocal) continue;
      if (!p.isLocal && !this.showPublic) continue;

      const { x, y } = this.geoToCanvas(p.lat, p.lon);
      if (x < -30 || x > this.width + 30 || y < -30 || y > this.height + 30) continue;
      const ptColor = p.isThreat ? '#ff2a5f' : (p.isLocal ? '#c084fc' : '#00e5ff');

      ctx.save();
      // Anillo exterior de origen (permite distinguir claramente de dónde nace la flecha)
      ctx.beginPath();
      ctx.arc(x, y, p.isThreat ? 8.5 : 6.5, 0, Math.PI * 2);
      ctx.strokeStyle = ptColor;
      ctx.lineWidth = p.isThreat ? 1.5 : 1.1;
      ctx.globalAlpha = 0.75;
      ctx.stroke();

      // Punto central de origen
      ctx.globalAlpha = 1.0;
      ctx.beginPath();
      ctx.arc(x, y, p.isThreat ? 4.2 : 3.2, 0, Math.PI * 2);
      ctx.fillStyle = ptColor;
      ctx.shadowColor = ptColor;
      ctx.shadowBlur = p.isThreat ? 10 : 6;
      ctx.fill();

      // Mostrar etiqueta de origen junto al punto para amenazas o al acercar el zoom
      if ((p.isThreat || this.zoom >= 1.8 || labelsDrawn < 4) && labelsDrawn < 10) {
        labelsDrawn += 1;
        const mainIp = p.realClientIp || p.ip || '';
        const pinText = `📍 ${p.zoneName || 'PY'}: ${mainIp}`;
        ctx.font = 'bold 8.5px monospace';
        const tw = ctx.measureText(pinText).width;
        const bx = Math.min(this.width - tw - 8, Math.max(4, x - tw / 2));
        const by = Math.max(14, y - 12);
        ctx.fillStyle = 'rgba(6, 11, 22, 0.88)';
        ctx.strokeStyle = ptColor;
        ctx.lineWidth = 0.85;
        ctx.fillRect(bx - 3, by - 9, tw + 6, 12);
        ctx.strokeRect(bx - 3, by - 9, tw + 6, 12);
        ctx.fillStyle = '#f8fafc';
        ctx.fillText(pinText, bx, by);
      }
      ctx.restore();
    }

    // 2. Flechas de trayectoria en Paraguay (calculadas dinámicamente desde las coordenadas reales de origen -> destino)
    for (let i = this.arcs.length - 1; i >= 0; i--) {
      const arc = this.arcs[i];
      if (arc.isLocal && !this.showLocal) {
        arc.progress += arc.speed;
        if (arc.progress >= 1.0) this.arcs.splice(i, 1);
        continue;
      }
      if (!arc.isLocal && !this.showPublic) {
        arc.progress += arc.speed;
        if (arc.progress >= 1.0) this.arcs.splice(i, 1);
        continue;
      }

      const startPos = this.geoToCanvas(arc.startLat, arc.startLon);
      const endPos = this.geoToCanvas(arc.endLat, arc.endLon);
      const dist = Math.hypot(endPos.x - startPos.x, endPos.y - startPos.y);
      const lift = Math.min(75, Math.max(18, dist * 0.30));
      const midX = (startPos.x + endPos.x) / 2;
      const midY = Math.min(startPos.y, endPos.y) - lift;

      const t = arc.progress;
      const tailT = Math.max(0, t - 0.38);

      const getPos = (u) => {
        const inv = 1 - u;
        return {
          x: inv * inv * startPos.x + 2 * inv * u * midX + u * u * endPos.x,
          y: inv * inv * startPos.y + 2 * inv * u * midY + u * u * endPos.y
        };
      };

      const head = getPos(t);
      const prev = getPos(Math.max(0, t - 0.03));
      const angle = Math.atan2(head.y - prev.y, head.x - prev.x);

      // Línea guía punteada desde el origen hasta el destino para ver siempre de dónde viene la flecha
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(startPos.x, startPos.y);
      ctx.quadraticCurveTo(midX, midY, endPos.x, endPos.y);
      ctx.strokeStyle = arc.color;
      ctx.globalAlpha = 0.24;
      ctx.lineWidth = 1.0;
      ctx.setLineDash([3, 3]);
      ctx.stroke();
      ctx.restore();

      ctx.save();
      ctx.beginPath();
      const steps = 12;
      for (let s = 0; s <= steps; s++) {
        const u = tailT + (t - tailT) * (s / steps);
        const pt = getPos(u);
        if (s === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      }
      ctx.strokeStyle = arc.color;
      ctx.lineWidth = arc.isThreat ? 2.1 : 1.6;
      ctx.shadowColor = arc.color;
      ctx.shadowBlur = 6;
      ctx.stroke();

      ctx.translate(head.x, head.y);
      ctx.rotate(angle);
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.moveTo(6, 0);
      ctx.lineTo(-4, -3.5);
      ctx.lineTo(-2, 0);
      ctx.lineTo(-4, 3.5);
      ctx.closePath();
      ctx.fill();
      ctx.restore();

      arc.progress += arc.speed;
      if (arc.progress >= 1.0) {
        this.arcs.splice(i, 1);
      }
    }

    // 3. Nodos Proxy en Paraguay
    const now = Date.now();
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const nodeGeo = this.getNodeGeo(node.name);
      const { x, y } = this.geoToCanvas(nodeGeo.lat, nodeGeo.lon);
      const isOnline = node.status === 'ONLINE';
      const nodeColor = isOnline ? '#00e676' : '#ff9900';

      ctx.save();
      const ringRadius = ((now / 22) % 22) + 5;
      const ringAlpha = 1 - (ringRadius - 5) / 22;
      ctx.beginPath();
      ctx.arc(x, y, ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = nodeColor;
      ctx.lineWidth = 1.4;
      ctx.globalAlpha = ringAlpha * 0.75;
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

      ctx.font = 'bold 9.5px monospace';
      ctx.fillStyle = '#00e676';
      ctx.fillText(`🛡️ ${node.name}`, x + 9, y + 3);
      ctx.restore();
    }

    // 4. Ondas sónicas ancladas a coordenadas geográficas
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      const pos = this.geoToCanvas(p.lat, p.lon);
      ctx.save();
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, p.radius, 0, Math.PI * 2);
      ctx.strokeStyle = p.color;
      ctx.lineWidth = p.isThreat ? 2.0 : 1.3;
      ctx.globalAlpha = p.alpha;
      ctx.stroke();
      ctx.restore();

      p.radius += 0.55;
      p.alpha -= 0.03;
      if (p.alpha <= 0 || p.radius >= p.maxRadius) {
        this.pulses.splice(i, 1);
      }
    }

    // 5. Indicador de nivel de Zoom en esquina superior izquierda
    if (this.zoom > 1.01) {
      ctx.save();
      ctx.font = 'bold 9px monospace';
      ctx.fillStyle = 'rgba(0, 229, 255, 0.85)';
      ctx.fillText(`🔍 ZOOM: ${this.zoom.toFixed(1)}x`, 10, 16);
      ctx.restore();
    }

    // 6. HUD bajo el cursor
    if (this.mouse.active && this.hoverPoint) {
      const hp = this.hoverPoint;
      const mainIp = hp.realClientIp || hp.ip || '';
      const cfSuffix = hp.isCloudflare ? ' [☁️ CF]' : (hp.isLocal ? ' [🏢 LAN]' : ' [🇵🇾 WAN]');
      const text = `🎯 ${mainIp}${cfSuffix} • Origen: ${hp.zoneName || 'Paraguay'} [HTTP ${hp.status_code || 200}]`;
      ctx.save();
      ctx.font = 'bold 9.5px monospace';
      const boxW = ctx.measureText(text).width + 14;
      const boxX = Math.min(this.width - boxW - 6, Math.max(6, hp.screenX + 10));
      const boxY = Math.max(6, hp.screenY - 24);

      ctx.fillStyle = 'rgba(8, 13, 25, 0.95)';
      ctx.strokeStyle = hp.isThreat ? '#ff2a5f' : (hp.isLocal ? '#c084fc' : '#00e5ff');
      ctx.lineWidth = 1.2;
      ctx.fillRect(boxX, boxY, boxW, 20);
      ctx.strokeRect(boxX, boxY, boxW, 20);

      ctx.fillStyle = '#ffffff';
      ctx.fillText(text, boxX + 7, boxY + 13);
      ctx.restore();
    }

    requestAnimationFrame(this.render);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.mithrilParaguayMap = new TacticalParaguayMap('paraguayMapCanvas');
  window.mithrilMap = new TacticalWorldMap('tacticalMapCanvas');
});
