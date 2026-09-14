/**
 * Smart AI NIDS - 3D Cybersecurity Network Topology Visualization
 * 
 * Conceptual Pipeline Architecture:
 * 
 *                  [INGRESS TRAFFIC GATEWAY]
 *                             │
 *                             ▼
 *                    [SPECIALIST ROUTER]
 *                   /   /     |     \   \
 *                  /   /      |      \   \
 *                 ▼   ▼       ▼       ▼   ▼
 *             IDS2018 CICIoT ARP_Spf IP_Spf DNS_Tunneling
 *                 \   \       |       /   /
 *                  \   \      |      /   /
 *                   └───┴─────┼──────┴───┘
 *                             │
 *                             ▼
 *                   [UNIFIEDNIDS AI CORE]
 *                             │
 *                             ▼
 *                   [13-CLASS VERDICT ARC]
 * 
 * Features:
 * - Three.js WebGL scene with OrbitControls, perspective camera, and responsive resizing.
 * - Dynamic animated particle packets traveling along real inference paths.
 * - Layered, pulsing UnifiedNIDS AI Decision Core.
 * - Interactive raycasting: tooltips on node hover, path highlighting on node click.
 * - Three visual security states: BENIGN (calm emerald), SUSPICIOUS (amber pulse), CRITICAL (intense crimson).
 * - Zero references to excluded attack classes.
 */

class Pipeline3D {
  constructor(containerId = "pipeline3d-canvas-container") {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Pipeline3D: Container #${containerId} not found.`);
      return;
    }

    this.width = this.container.clientWidth || 800;
    this.height = this.container.clientHeight || 500;

    // Three.js primitives
    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.controls = null;
    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2();

    // Node objects & collections
    this.nodes = {};
    this.connectionLines = [];
    this.activePackets = [];
    this.interactiveObjects = [];

    // Animation state
    this.clock = new THREE.Clock();
    this.animating = true;
    this.currentState = "BENIGN"; // "BENIGN" | "SUSPICIOUS" | "CRITICAL"

    // Canonical 13-Class Definition
    this.canonicalClasses = [
      { id: 0,  name: "Benign",            color: 0x10b981 },
      { id: 1,  name: "DDoS",              color: 0xef4444 },
      { id: 2,  name: "DoS",               color: 0xf43f5e },
      { id: 3,  name: "Botnet",            color: 0xa855f7 },
      { id: 4,  name: "Infiltration",      color: 0xf59e0b },
      { id: 5,  name: "Brute Force",       color: 0xf97316 },
      { id: 6,  name: "Web Attack",        color: 0xfb923c },
      { id: 7,  name: "DNS Spoofing",      color: 0xeab308 },
      { id: 8,  name: "IP Spoofing",       color: 0xf97316 },
      { id: 9,  name: "ARP Spoofing",      color: 0xd946ef },
      { id: 10, name: "Recon / Port Scan", color: 0x06b6d4 },
      { id: 11, name: "MITM",              color: 0x3b82f6 },
      { id: 12, name: "DNS Tunneling",     color: 0x8b5cf6 },
    ];

    // 5 Specialist Specifications
    this.specialists = [
      { id: "IDS2018",       label: "IDS2018 (Enterprise)",  x: -16, y: 3, z: 0, color: 0x38bdf8 },
      { id: "CICIoT2023",    label: "CICIoT2023 (IoT Flow)", x: -8,  y: 3, z: 2, color: 0x06b6d4 },
      { id: "ARP_Spoofing",  label: "ARP Specialist",        x: 0,   y: 3, z: 3, color: 0xd946ef },
      { id: "IP_Spoofing",   label: "5G / IP Specialist",    x: 8,   y: 3, z: 2, color: 0xf97316 },
      { id: "DNS_Tunneling", label: "DNS Tunneling",         x: 16,  y: 3, z: 0, color: 0x8b5cf6 },
    ];

    this.init();
  }

  init() {
    // 1. Scene setup
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x060b13);
    this.scene.fog = new THREE.FogExp2(0x060b13, 0.015);

    // 2. Camera setup
    this.camera = new THREE.PerspectiveCamera(45, this.width / this.height, 0.1, 1000);
    this.defaultCameraPos = new THREE.Vector3(0, -2, 48);
    this.camera.position.copy(this.defaultCameraPos);

    // 3. Renderer setup
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.renderer.setSize(this.width, this.height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.container.appendChild(this.renderer.domElement);

    // 4. OrbitControls
    if (typeof THREE.OrbitControls !== "undefined") {
      this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
      this.controls.enableDamping = true;
      this.controls.dampingFactor = 0.05;
      this.controls.maxDistance = 80;
      this.controls.minDistance = 15;
      this.controls.maxPolarAngle = Math.PI / 2 + 0.1;
    }

    // 5. Lighting
    const ambientLight = new THREE.AmbientLight(0x384252, 1.2);
    this.scene.add(ambientLight);

    const dirLight1 = new THREE.DirectionalLight(0x38bdf8, 1.5);
    dirLight1.position.set(10, 20, 20);
    this.scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0x818cf8, 1.0);
    dirLight2.position.set(-15, -10, 15);
    this.scene.add(dirLight2);

    // 6. Build Topology
    this._buildBackgroundGrid();
    this._buildGateway();
    this._buildRouter();
    this._buildSpecialistNodes();
    this._buildUnifiedCore();
    this._buildVerdictNodes();
    this._buildConnectionLines();

    // 7. Event listeners
    window.addEventListener("resize", () => this.onResize());
    this.container.addEventListener("mousemove", (e) => this.onMouseMove(e));
    this.container.addEventListener("click", (e) => this.onClick(e));

    // 8. Tooltip element
    this._createTooltip();

    // 9. Start animation loop
    this.animate();
  }

  _createTooltip() {
    this.tooltip = document.createElement("div");
    this.tooltip.className = "cyber-3d-tooltip";
    this.tooltip.style.display = "none";
    this.tooltip.style.position = "absolute";
    this.tooltip.style.pointerEvents = "none";
    this.tooltip.style.zIndex = "100";
    this.container.appendChild(this.tooltip);
  }

  _buildBackgroundGrid() {
    const grid = new THREE.GridHelper(80, 40, 0x1e293b, 0x0f172a);
    grid.position.y = -22;
    grid.material.transparent = true;
    grid.material.opacity = 0.4;
    this.scene.add(grid);
  }

  _buildGateway() {
    // Top Traffic Gateway: Hexagonal cylinder with glowing wireframe
    const geom = new THREE.CylinderGeometry(3.5, 3.5, 1.2, 6);
    const mat = new THREE.MeshStandardMaterial({
      color: 0x0284c7,
      emissive: 0x0369a1,
      emissiveIntensity: 0.5,
      metalness: 0.8,
      roughness: 0.2,
      wireframe: false,
    });
    const gateway = new THREE.Mesh(geom, mat);
    gateway.position.set(0, 16, 0);

    const wireGeom = new THREE.CylinderGeometry(3.6, 3.6, 1.25, 6);
    const wireMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, wireframe: true });
    const wire = new THREE.Mesh(wireGeom, wireMat);
    gateway.add(wire);

    gateway.userData = {
      type: "gateway",
      name: "Traffic Ingress Gateway",
      detail: "Monitors and receives raw network packet & flow streams.",
    };
    this.nodes["gateway"] = gateway;
    this.scene.add(gateway);
    this.interactiveObjects.push(gateway);
  }

  _buildRouter() {
    // Intermediate Specialist Router: Octahedron
    const geom = new THREE.OctahedronGeometry(2.0, 0);
    const mat = new THREE.MeshStandardMaterial({
      color: 0x6366f1,
      emissive: 0x4338ca,
      emissiveIntensity: 0.6,
      metalness: 0.7,
      roughness: 0.3,
    });
    const router = new THREE.Mesh(geom, mat);
    router.position.set(0, 9.5, 0);

    const wireMat = new THREE.MeshBasicMaterial({ color: 0x818cf8, wireframe: true });
    router.add(new THREE.Mesh(geom, wireMat));

    router.userData = {
      type: "router",
      name: "Specialist Schema Router",
      detail: "Evaluates signature feature indicators and dispatches traffic to the designated specialist.",
    };
    this.nodes["router"] = router;
    this.scene.add(router);
    this.interactiveObjects.push(router);
  }

  _buildSpecialistNodes() {
    this.nodes.specialists = {};
    const geom = new THREE.BoxGeometry(2.8, 1.8, 2.0);

    this.specialists.forEach((spec) => {
      const mat = new THREE.MeshStandardMaterial({
        color: spec.color,
        emissive: spec.color,
        emissiveIntensity: 0.3,
        metalness: 0.5,
        roughness: 0.4,
      });
      const node = new THREE.Mesh(geom, mat);
      node.position.set(spec.x, spec.y, spec.z);

      // Edge outline
      const edges = new THREE.EdgesGeometry(geom);
      const line = new THREE.LineSegments(edges, new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.6 }));
      node.add(line);

      // Status light beacon
      const beaconGeom = new THREE.SphereGeometry(0.35, 12, 12);
      const beaconMat = new THREE.MeshBasicMaterial({ color: spec.color });
      const beacon = new THREE.Mesh(beaconGeom, beaconMat);
      beacon.position.set(0, 1.3, 0);
      node.add(beacon);

      node.userData = {
        type: "specialist",
        id: spec.id,
        name: spec.label,
        color: spec.color,
        detail: `Specialist pipeline for ${spec.id}. Processes features with dedicated preprocessor & classifier.`,
      };

      this.nodes.specialists[spec.id] = node;
      this.scene.add(node);
      this.interactiveObjects.push(node);
    });
  }

  _buildUnifiedCore() {
    // Central UnifiedNIDS AI Decision Core: Concentric rings + pulsating central sphere
    const coreGroup = new THREE.Group();
    coreGroup.position.set(0, -6, 0);

    // Inner glowing sphere
    const sphereGeom = new THREE.IcosahedronGeometry(2.4, 2);
    const sphereMat = new THREE.MeshStandardMaterial({
      color: 0x06b6d4,
      emissive: 0x0891b2,
      emissiveIntensity: 0.8,
      metalness: 0.9,
      roughness: 0.1,
      wireframe: false,
    });
    this.coreSphere = new THREE.Mesh(sphereGeom, sphereMat);
    coreGroup.add(this.coreSphere);

    // Outer gyro-ring 1
    const ring1Geom = new THREE.TorusGeometry(3.6, 0.12, 8, 48);
    const ring1Mat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.8 });
    this.ring1 = new THREE.Mesh(ring1Geom, ring1Mat);
    coreGroup.add(this.ring1);

    // Outer gyro-ring 2
    const ring2Geom = new THREE.TorusGeometry(4.2, 0.1, 8, 48);
    const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x818cf8, transparent: true, opacity: 0.7 });
    this.ring2 = new THREE.Mesh(ring2Geom, ring2Mat);
    this.ring2.rotation.x = Math.PI / 2.5;
    coreGroup.add(this.ring2);

    coreGroup.userData = {
      type: "core",
      name: "UnifiedNIDS AI Decision Core",
      detail: "Aggregates specialist output, calibrates confidence, projects into 13-class canonical space.",
    };

    this.nodes["core"] = coreGroup;
    this.scene.add(coreGroup);
    this.interactiveObjects.push(this.coreSphere);
  }

  _buildVerdictNodes() {
    this.nodes.verdicts = {};
    const total = this.canonicalClasses.length; // 13
    const radiusX = 22;
    const radiusZ = 6;
    const yLevel = -16;

    this.canonicalClasses.forEach((cls, i) => {
      // Symmetrical horizontal arc
      const normIdx = (i - (total - 1) / 2) / ((total - 1) / 2); // -1.0 to +1.0
      const x = normIdx * radiusX;
      const z = Math.cos(normIdx * (Math.PI / 2.8)) * radiusZ - radiusZ;

      const geom = new THREE.SphereGeometry(0.85, 16, 16);
      const mat = new THREE.MeshStandardMaterial({
        color: cls.color,
        emissive: cls.color,
        emissiveIntensity: 0.25,
        metalness: 0.4,
        roughness: 0.6,
      });
      const node = new THREE.Mesh(geom, mat);
      node.position.set(x, yLevel, z);

      // Thin halo ring
      const ringGeom = new THREE.RingGeometry(0.95, 1.15, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color: cls.color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.5,
      });
      const ring = new THREE.Mesh(ringGeom, ringMat);
      ring.rotation.x = Math.PI / 2;
      node.add(ring);

      node.userData = {
        type: "verdict",
        id: cls.id,
        name: cls.name,
        color: cls.color,
        detail: `Canonical Class [ID ${cls.id}]: ${cls.name}`,
      };

      this.nodes.verdicts[cls.id] = node;
      this.scene.add(node);
      this.interactiveObjects.push(node);
    });
  }

  _buildConnectionLines() {
    const lineMaterial = new THREE.LineBasicMaterial({
      color: 0x334155,
      transparent: true,
      opacity: 0.4,
    });

    const addLine = (p1, p2, key) => {
      const geom = new THREE.BufferGeometry().setFromPoints([p1, p2]);
      const line = new THREE.Line(geom, lineMaterial.clone());
      this.scene.add(line);
      this.connectionLines.push({ line, p1, p2, key });
    };

    // 1. Gateway -> Router
    addLine(this.nodes.gateway.position, this.nodes.router.position, "gw_router");

    // 2. Router -> Each Specialist
    Object.keys(this.nodes.specialists).forEach((specId) => {
      addLine(this.nodes.router.position, this.nodes.specialists[specId].position, `router_${specId}`);
    });

    // 3. Each Specialist -> Core
    Object.keys(this.nodes.specialists).forEach((specId) => {
      addLine(this.nodes.specialists[specId].position, this.nodes.core.position, `${specId}_core`);
    });

    // 4. Core -> Each Verdict Node
    Object.keys(this.nodes.verdicts).forEach((cid) => {
      addLine(this.nodes.core.position, this.nodes.verdicts[cid].position, `core_verdict_${cid}`);
    });
  }

  /**
   * Spawn an animated particle packet through the exact prediction path.
   * Path: Gateway -> Router -> Selected Specialist -> UnifiedNIDS Core -> Selected Verdict.
   * 
   * @param {string} specialist - Specialist identifier
   * @param {number} predictedClassId - Canonical class ID (0 to 12)
   * @param {number} confidence - Confidence score
   */
  dispatchPacket(specialist, predictedClassId, confidence = 1.0) {
    const specNode = this.nodes.specialists[specialist];
    const verdictNode = this.nodes.verdicts[predictedClassId];

    if (!specNode || !verdictNode) {
      console.warn(`Pipeline3D.dispatchPacket: Unknown specialist '${specialist}' or class ID '${predictedClassId}'.`);
      return;
    }

    const waypoints = [
      this.nodes.gateway.position.clone(),
      this.nodes.router.position.clone(),
      specNode.position.clone(),
      this.nodes.core.position.clone(),
      verdictNode.position.clone(),
    ];

    // Determine packet color based on verdict
    const clsInfo = this.canonicalClasses.find((c) => c.id === predictedClassId) || { color: 0x38bdf8 };
    const packetColor = clsInfo.color;

    // Visual State
    if (predictedClassId === 0) {
      this.setSecurityState("BENIGN");
    } else if ([1, 2, 3, 4].includes(predictedClassId)) {
      this.setSecurityState("CRITICAL");
    } else {
      this.setSecurityState("SUSPICIOUS");
    }

    // Create 3D Packet
    const pGeom = new THREE.SphereGeometry(0.45, 12, 12);
    const pMat = new THREE.MeshBasicMaterial({ color: packetColor });
    const packetMesh = new THREE.Mesh(pGeom, pMat);
    packetMesh.position.copy(waypoints[0]);
    this.scene.add(packetMesh);

    this.activePackets.push({
      mesh: packetMesh,
      waypoints,
      currentSegment: 0,
      segmentProgress: 0.0,
      speed: 1.8 + Math.min(confidence, 1.0) * 0.8,
      specialist,
      predictedClassId,
    });
  }

  setSecurityState(state) {
    this.currentState = state;
    if (state === "CRITICAL") {
      this.coreSphere.material.color.setHex(0xef4444);
      this.coreSphere.material.emissive.setHex(0xb91c1c);
    } else if (state === "SUSPICIOUS") {
      this.coreSphere.material.color.setHex(0xf59e0b);
      this.coreSphere.material.emissive.setHex(0xd97706);
    } else {
      this.coreSphere.material.color.setHex(0x06b6d4);
      this.coreSphere.material.emissive.setHex(0x0891b2);
    }
  }

  highlightVerdictNode(classId) {
    const node = this.nodes.verdicts[classId];
    if (!node) return;

    node.material.emissiveIntensity = 1.0;
    node.scale.set(1.4, 1.4, 1.4);

    setTimeout(() => {
      if (node) {
        node.material.emissiveIntensity = 0.25;
        node.scale.set(1.0, 1.0, 1.0);
      }
    }, 1500);
  }

  highlightSpecialistNode(specId) {
    const node = this.nodes.specialists[specId];
    if (!node) return;

    node.material.emissiveIntensity = 0.9;
    node.scale.set(1.15, 1.15, 1.15);

    setTimeout(() => {
      if (node) {
        node.material.emissiveIntensity = 0.3;
        node.scale.set(1.0, 1.0, 1.0);
      }
    }, 1500);
  }

  resetCamera() {
    if (this.controls) {
      this.controls.reset();
    }
    this.camera.position.copy(this.defaultCameraPos);
  }

  onResize() {
    if (!this.container) return;
    this.width = this.container.clientWidth;
    this.height = this.container.clientHeight;
    this.camera.aspect = this.width / this.height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(this.width, this.height);
  }

  onMouseMove(e) {
    const rect = this.container.getBoundingClientRect();
    this.mouse.x = ((e.clientX - rect.left) / this.width) * 2 - 1;
    this.mouse.y = -((e.clientY - rect.top) / this.height) * 2 + 1;

    this.raycaster.setFromCamera(this.mouse, this.camera);
    const intersects = this.raycaster.intersectObjects(this.interactiveObjects, true);

    if (intersects.length > 0) {
      let obj = intersects[0].object;
      while (obj.parent && !obj.userData?.type && obj !== this.scene) {
        obj = obj.parent;
      }

      if (obj.userData && obj.userData.name) {
        this.container.style.cursor = "pointer";
        this.tooltip.style.display = "block";
        this.tooltip.style.left = `${e.clientX - rect.left + 15}px`;
        this.tooltip.style.top = `${e.clientY - rect.top + 15}px`;
        this.tooltip.innerHTML = `
          <div class="tooltip-title">${obj.userData.name}</div>
          <div class="tooltip-body">${obj.userData.detail || ""}</div>
        `;
        return;
      }
    }

    this.container.style.cursor = "default";
    this.tooltip.style.display = "none";
  }

  onClick(e) {
    this.raycaster.setFromCamera(this.mouse, this.camera);
    const intersects = this.raycaster.intersectObjects(this.interactiveObjects, true);

    if (intersects.length > 0) {
      let obj = intersects[0].object;
      while (obj.parent && !obj.userData?.type && obj !== this.scene) {
        obj = obj.parent;
      }

      if (obj.userData?.type === "specialist") {
        this.highlightSpecialistNode(obj.userData.id);
      } else if (obj.userData?.type === "verdict") {
        this.highlightVerdictNode(obj.userData.id);
      }
    }
  }

  animate() {
    if (!this.animating) return;
    requestAnimationFrame(() => this.animate());

    const delta = this.clock.getDelta();
    const elapsed = this.clock.getElapsedTime();

    // 1. Subtle core gyro rotations
    if (this.nodes.core) {
      this.coreSphere.rotation.y += 0.015;
      this.ring1.rotation.z += 0.02;
      this.ring2.rotation.y += 0.012;
      this.ring2.rotation.x += 0.008;
    }

    // 2. Gateway subtle rotation
    if (this.nodes.gateway) {
      this.nodes.gateway.rotation.y += 0.008;
    }

    // 3. Router pulse
    if (this.nodes.router) {
      this.nodes.router.rotation.x += 0.01;
      this.nodes.router.rotation.y += 0.015;
    }

    // 4. Update active packets
    for (let i = this.activePackets.length - 1; i >= 0; i--) {
      const pkt = this.activePackets[i];
      pkt.segmentProgress += delta * pkt.speed;

      if (pkt.segmentProgress >= 1.0) {
        pkt.segmentProgress = 0.0;
        pkt.currentSegment++;

        // Trigger pulse on reaching intermediate nodes
        if (pkt.currentSegment === 2) {
          this.highlightSpecialistNode(pkt.specialist);
        } else if (pkt.currentSegment === 3) {
          // Reached core
          this.coreSphere.scale.set(1.15, 1.15, 1.15);
          setTimeout(() => this.coreSphere.scale.set(1.0, 1.0, 1.0), 300);
        } else if (pkt.currentSegment >= pkt.waypoints.length - 1) {
          // Reached final verdict node
          this.highlightVerdictNode(pkt.predictedClassId);
          this.scene.remove(pkt.mesh);
          pkt.mesh.geometry.dispose();
          pkt.mesh.material.dispose();
          this.activePackets.splice(i, 1);
          continue;
        }
      }

      const pStart = pkt.waypoints[pkt.currentSegment];
      const pEnd = pkt.waypoints[pkt.currentSegment + 1];
      if (pStart && pEnd) {
        pkt.mesh.position.lerpVectors(pStart, pEnd, pkt.segmentProgress);
      }
    }

    // 5. Update controls
    if (this.controls) {
      this.controls.update();
    }

    // 6. Render
    this.renderer.render(this.scene, this.camera);
  }

  destroy() {
    this.animating = false;
    window.removeEventListener("resize", () => this.onResize());
    if (this.renderer && this.renderer.domElement) {
      this.container.removeChild(this.renderer.domElement);
      this.renderer.dispose();
    }
  }
}

// Attach to window
window.Pipeline3D = Pipeline3D;
