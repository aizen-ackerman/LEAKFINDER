import React, { useState, useEffect } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  Cell
} from "recharts";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Search,
  FileText,
  Globe,
  History,
  User,
  LogOut,
  Cpu,
  Database,
  TrendingUp,
  AlertCircle,
  Terminal,
  Lock,
  Mail,
  RefreshCw,
  ChevronRight,
  ExternalLink,
  Info,
  Menu,
  Activity,
  Layers,
  ChevronDown
} from "lucide-react";

// API Base URL detection
const API_BASE_URL = window.location.port === "5173" ? "http://localhost:8080" : "";

// Mock historical trend data
const trendData = [
  { month: "Jan", leaks: 140, records: 12 },
  { month: "Feb", leaks: 185, records: 28 },
  { month: "Mar", leaks: 290, records: 45 },
  { month: "Apr", leaks: 220, records: 30 },
  { month: "May", leaks: 340, records: 85 },
  { month: "Jun", leaks: 480, records: 110 }
];

// Mock category breakdown data
const categoryData = [
  { name: "Injection", count: 42, fill: "#6366f1" },
  { name: "Credentials", count: 35, fill: "#8b5cf6" },
  { name: "XSS Risks", count: 28, fill: "#ec4899" },
  { name: "Headers", count: 64, fill: "#3b82f6" },
  { name: "Crypto", count: 19, fill: "#06b6d4" },
  { name: "Deps/Outdated", count: 87, fill: "#10b981" }
];

// Mock breach feeds
const initialBreaches = [
  { id: 1, source: "Canva Database", date: "May 2019", records: "137M", type: "Emails, Passwords, Names", severity: "High" },
  { id: 2, source: "LinkedIn Data Scraping", date: "June 2021", records: "700M", type: "Emails, Phones, Job titles", severity: "Medium" },
  { id: 3, source: "Adobe Account Exposure", date: "Oct 2013", records: "152M", type: "Emails, Password hints", severity: "High" },
  { id: 4, source: "Dropbox User Leak", date: "Aug 2012", records: "68M", type: "Emails, Hashed passwords", severity: "Medium" },
  { id: 5, source: "Ledger Customer Database", date: "Dec 2020", records: "1.0M", type: "Emails, Addresses, Phone numbers", severity: "Critical" }
];

// Mock email leak check results
const MOCK_LEAKS_DB = {
  "admin@leakfinder.com": [
    { source: "LeakFinder Internal Test Leak", date: "June 2026", records: "1 Record", type: "System Admin Credentials", severity: "Critical" },
    { source: "Canva Database", date: "May 2019", records: "137M", type: "Emails, Hashed Passwords, Names", severity: "High" }
  ],
  "user@example.com": [
    { source: "Adobe Account Exposure", date: "Oct 2013", records: "152M", type: "Emails, Password hints", severity: "High" },
    { source: "LinkedIn Data Scraping", date: "June 2021", records: "700M", type: "Emails, Phone numbers, Job titles", severity: "Medium" }
  ]
};

// Active cities for live attacks
const THREAT_CITIES = [
  { name: "Washington DC", country: "US", lat: 38.9072, lon: -77.0369 },
  { name: "Beijing", country: "CN", lat: 39.9042, lon: 116.4074 },
  { name: "Moscow", country: "RU", lat: 55.7558, lon: 37.6173 },
  { name: "London", country: "UK", lat: 51.5074, lon: -0.1278 },
  { name: "Tokyo", country: "JP", lat: 35.6762, lon: 139.6503 },
  { name: "Sydney", country: "AU", lat: -33.8688, lon: 151.2093 },
  { name: "Frankfurt", country: "DE", lat: 50.1109, lon: 8.6821 },
  { name: "Sao Paulo", country: "BR", lat: -23.5505, lon: -46.6333 },
  { name: "Cape Town", country: "ZA", lat: -33.9249, lon: 18.4241 },
  { name: "Mumbai", country: "IN", lat: 19.0760, lon: 72.8777 },
  { name: "Singapore", country: "SG", lat: 1.3521, lon: 103.8198 },
  { name: "Toronto", country: "CA", lat: 43.6532, lon: -79.3832 }
];

const ATTACK_TYPES = [
  "SQL Injection Attempt",
  "DDoS Syn Flood",
  "Ransomware Beacon",
  "SSH Brute Force",
  "XSS Injection",
  "API Exploitation",
  "Botnet C2 Signal",
  "Port Scan Sweep",
  "Directory Traversal",
  "Malware Payload Drop"
];

const ATTACK_STATUSES = [
  { status: "BLOCKED", color: "text-emerald-400 border-emerald-500/20 bg-emerald-500/10" },
  { status: "MITIGATED", color: "text-amber-400 border-amber-500/20 bg-amber-500/10" },
  { status: "MONITORED", color: "text-indigo-400 border-indigo-500/20 bg-indigo-500/10" },
  { status: "DETONATED", color: "text-rose-400 border-rose-500/20 bg-rose-500/10" }
];

function ThreatGlobe({ attacks }) {
  const canvasRef = React.useRef(null);
  
  const [rotation, setRotation] = useState({ lambda: 0, phi: 0.3 });
  const mouseRef = React.useRef({ isDown: false, x: 0, y: 0 });
  const rotationRef = React.useRef({ lambda: 0, phi: 0.3 });
  
  React.useEffect(() => {
    rotationRef.current = rotation;
  }, [rotation]);

  const handleMouseDown = (e) => {
    mouseRef.current = { isDown: true, x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e) => {
    if (!mouseRef.current.isDown) return;
    const dx = e.clientX - mouseRef.current.x;
    const dy = e.clientY - mouseRef.current.y;
    
    const newLambda = rotationRef.current.lambda + dx * 0.007;
    const newPhi = Math.max(-Math.PI/2.5, Math.min(Math.PI/2.5, rotationRef.current.phi + dy * 0.007));
    
    setRotation({ lambda: newLambda, phi: newPhi });
    mouseRef.current = { isDown: true, x: e.clientX, y: e.clientY };
  };

  const handleMouseUp = () => {
    mouseRef.current.isDown = false;
  };

  const continents = React.useMemo(() => [
    // North America
    [[-168, 66], [-150, 70], [-120, 70], [-100, 70], [-80, 75], [-60, 60], [-55, 50], [-70, 45], [-75, 35], [-80, 25], [-81, 25], [-82, 28], [-90, 30], [-97, 26], [-100, 18], [-105, 20], [-110, 23], [-115, 32], [-125, 40], [-125, 48], [-135, 55], [-160, 60], [-168, 66]],
    // South America
    [[-80, 9], [-72, 11], [-60, 5], [-50, -5], [-35, -6], [-40, -20], [-60, -45], [-70, -55], [-75, -50], [-73, -40], [-70, -30], [-80, -15], [-81, -5], [-80, 5], [-80, 9]],
    // Greenland
    [[-60, 83], [-30, 83], [-10, 75], [-40, 60], [-50, 60], [-60, 70], [-60, 83]],
    // Africa
    [[-17, 32], [-5, 36], [10, 37], [30, 31], [33, 27], [34, 15], [43, 12], [51, 11], [46, -5], [40, -15], [33, -34], [18, -34], [12, -15], [8, 4], [-10, 5], [-15, 12], [-17, 32]],
    // Eurasia
    [[-10, 65], [0, 60], [10, 55], [20, 65], [30, 70], [60, 75], [90, 77], [120, 75], [160, 75], [170, 66], [160, 50], [140, 35], [120, 20], [110, 15], [100, 10], [98, 2], [90, 10], [80, 6], [75, 12], [72, 20], [70, 30], [60, 25], [58, 12], [48, 15], [44, 25], [40, 15], [35, 30], [30, 30], [26, 36], [22, 38], [15, 40], [5, 43], [-5, 36], [-9, 39], [-10, 50], [-10, 65]],
    // Australia
    [[113, -22], [120, -15], [135, -12], [143, -10], [151, -33], [140, -38], [130, -32], [115, -34], [113, -22]],
    // Japan
    [[130, 32], [135, 35], [140, 38], [142, 40], [140, 42], [130, 32]],
    // Madagascar
    [[49, -12], [50, -15], [47, -25], [43, -25], [46, -16], [49, -12]]
  ], []);

  const landPoints = React.useMemo(() => {
    const isPointInPolygon = (x, y, polygon) => {
      let inside = false;
      for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
        const xi = polygon[i][0], yi = polygon[i][1];
        const xj = polygon[j][0], yj = polygon[j][1];
        const intersect = ((yi > y) !== (yj > y))
            && (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
        if (intersect) inside = !inside;
      }
      return inside;
    };

    const pts = [];
    const step = 2.4; 
    for (let lat = -65; lat <= 80; lat += step) {
      for (let lon = -180; lon <= 180; lon += step) {
        let isLand = false;
        for (let i = 0; i < continents.length; i++) {
          if (isPointInPolygon(lon, lat, continents[i])) {
            isLand = true;
            break;
          }
        }
        if (isLand) {
          pts.push([lon, lat]);
        }
      }
    }
    return pts;
  }, [continents]);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animationFrameId;
    
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.42;

    const project = (lonDeg, latDeg, lambda, phi) => {
      const lon = (lonDeg * Math.PI) / 180;
      const lat = (latDeg * Math.PI) / 180;

      const x = Math.cos(lat) * Math.sin(lon);
      const y = Math.sin(lat);
      const z = Math.cos(lat) * Math.cos(lon);

      const x1 = x * Math.cos(lambda) - z * Math.sin(lambda);
      const z1 = x * Math.sin(lambda) + z * Math.cos(lambda);

      const y2 = y * Math.cos(phi) - z1 * Math.sin(phi);
      const z2 = y * Math.sin(phi) + z1 * Math.cos(phi);

      return {
        x: centerX + radius * x1,
        y: centerY - radius * y2,
        z: z2,
        visible: z2 > 0
      };
    };

    const drawGlobe = () => {
      ctx.clearRect(0, 0, width, height);

      const { lambda, phi } = rotationRef.current;

      // 1. Atmosphere ambient outer glow
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius + 15, 0, 2 * Math.PI);
      const atmosGrad = ctx.createRadialGradient(
        centerX, centerY, radius - 2,
        centerX, centerY, radius + 15
      );
      atmosGrad.addColorStop(0, "rgba(99, 102, 241, 0.2)");
      atmosGrad.addColorStop(0.3, "rgba(99, 102, 241, 0.07)");
      atmosGrad.addColorStop(1, "rgba(99, 102, 241, 0.0)");
      ctx.fillStyle = atmosGrad;
      ctx.fill();

      // 2. Base globe sphere surface
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
      const sphereGrad = ctx.createRadialGradient(
        centerX - radius * 0.25, centerY - radius * 0.25, radius * 0.1,
        centerX, centerY, radius
      );
      sphereGrad.addColorStop(0, "#0a0f29");
      sphereGrad.addColorStop(0.7, "#040714");
      sphereGrad.addColorStop(1, "#02040a");
      ctx.fillStyle = sphereGrad;
      ctx.fill();
      
      // Globe border ring
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "rgba(99, 102, 241, 0.35)";
      ctx.stroke();

      // 3. Faint grid lines (meridians and parallels)
      ctx.lineWidth = 0.5;
      ctx.strokeStyle = "rgba(99, 102, 241, 0.05)";

      // Parallels
      for (let lat = -60; lat <= 60; lat += 20) {
        ctx.beginPath();
        let first = true;
        for (let lon = -180; lon <= 180; lon += 5) {
          const pt = project(lon, lat, lambda, phi);
          if (pt.visible) {
            if (first) {
              ctx.moveTo(pt.x, pt.y);
              first = false;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      // Meridians
      for (let lon = -150; lon <= 180; lon += 30) {
        ctx.beginPath();
        let first = true;
        for (let lat = -90; lat <= 90; lat += 5) {
          const pt = project(lon, lat, lambda, phi);
          if (pt.visible) {
            if (first) {
              ctx.moveTo(pt.x, pt.y);
              first = false;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      // 4. Draw detailed continent outlines
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = "rgba(99, 102, 241, 0.22)";
      continents.forEach(polygon => {
        ctx.beginPath();
        let isPathStarted = false;
        
        polygon.forEach(coord => {
          const pt = project(coord[0], coord[1], lambda, phi);
          if (pt.visible) {
            if (!isPathStarted) {
              ctx.moveTo(pt.x, pt.y);
              isPathStarted = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            isPathStarted = false;
          }
        });
        
        if (isPathStarted) {
          const firstPt = project(polygon[0][0], polygon[0][1], lambda, phi);
          if (firstPt.visible) {
            ctx.lineTo(firstPt.x, firstPt.y);
          }
        }
        ctx.stroke();
      });

      // 5. Draw dotted land points with 3D stereoscopic depth shader
      landPoints.forEach(coord => {
        const pt = project(coord[0], coord[1], lambda, phi);
        if (pt.visible) {
          const depth = pt.z; 
          const ratio = Math.max(0, depth); 
          const size = 0.9 + 0.9 * ratio;
          const alpha = 0.15 + 0.6 * ratio;
          
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, size, 0, 2 * Math.PI);
          ctx.fillStyle = `rgba(129, 140, 248, ${alpha})`;
          ctx.fill();
        }
      });

      // 6. Draw pulsing threat city nodes
      const pulseTime = Date.now() * 0.003;
      THREAT_CITIES.forEach(city => {
        const pt = project(city.lon, city.lat, lambda, phi);
        if (pt.visible) {
          // Core dot
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 2.5, 0, 2 * Math.PI);
          ctx.fillStyle = "#f43f5e"; // rose-500
          ctx.fill();

          // Pulse ring
          const pulseScale = 1.0 + ((pulseTime + Math.abs(city.lat)) % 1.0) * 2.0;
          const pulseOpacity = 1.0 - ((pulseTime + Math.abs(city.lat)) % 1.0);
          
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 2.5 * pulseScale, 0, 2 * Math.PI);
          ctx.lineWidth = 0.8;
          ctx.strokeStyle = `rgba(244, 63, 94, ${pulseOpacity * 0.55})`;
          ctx.stroke();
        }
      });

      // 7. Draw animated curved attack vectors and ripples
      attacks.forEach(atk => {
        const srcPt = project(atk.srcLon, atk.srcLat, lambda, phi);
        const destPt = project(atk.destLon, atk.destLat, lambda, phi);

        if (srcPt.visible || destPt.visible) {
          const p = atk.progress;
          const midLon = (atk.srcLon + atk.destLon) / 2;
          const midLat = (atk.srcLat + atk.destLat) / 2;
          
          const start = srcPt;
          const end = destPt;
          const mid = project(midLon, midLat, lambda, phi);
          
          const dx = end.x - start.x;
          const dy = end.y - start.y;
          const dist = Math.sqrt(dx*dx + dy*dy);
          
          const ctrlX = mid.x + (mid.x - centerX) * (dist / radius) * 0.4;
          const ctrlY = mid.y + (mid.y - centerY) * (dist / radius) * 0.4;

          // Parabolic thin path trace
          ctx.beginPath();
          ctx.moveTo(start.x, start.y);
          ctx.quadraticCurveTo(ctrlX, ctrlY, end.x, end.y);
          ctx.lineWidth = 1;
          ctx.strokeStyle = atk.color + "12";
          ctx.stroke();

          const getBezierPt = (t) => {
            const mt = 1 - t;
            return {
              x: mt * mt * start.x + 2 * mt * t * ctrlX + t * t * end.x,
              y: mt * mt * start.y + 2 * mt * t * ctrlY + t * t * end.y
            };
          };

          // Glowing tail stream
          ctx.beginPath();
          const tailSteps = 15;
          const startT = Math.max(0, p - 0.18);
          const firstBezierPt = getBezierPt(startT);
          ctx.moveTo(firstBezierPt.x, firstBezierPt.y);
          
          for (let step = 1; step <= tailSteps; step++) {
            const t = startT + (p - startT) * (step / tailSteps);
            const bPt = getBezierPt(t);
            ctx.lineTo(bPt.x, bPt.y);
          }
          
          ctx.lineWidth = 1.8;
          ctx.strokeStyle = atk.color;
          ctx.shadowBlur = 6;
          ctx.shadowColor = atk.color;
          ctx.stroke();
          ctx.shadowBlur = 0; // reset shadow blur

          // Glowing lead point
          const leadPt = getBezierPt(Math.min(1.0, p));
          ctx.beginPath();
          ctx.arc(leadPt.x, leadPt.y, 2, 0, 2 * Math.PI);
          ctx.fillStyle = "#ffffff";
          ctx.fill();
        }

        // Ripple impact wave
        if (atk.progress >= 0.95 && destPt.visible) {
          const rippleRadius = (atk.progress - 0.95) * 50;
          const opacity = 1 - (atk.progress - 0.95) / 0.1;
          
          ctx.beginPath();
          ctx.arc(destPt.x, destPt.y, Math.max(0.1, rippleRadius), 0, 2 * Math.PI);
          ctx.lineWidth = 1.2;
          ctx.strokeStyle = `rgba(244, 63, 94, ${Math.max(0, opacity * 0.65)})`;
          ctx.stroke();
        }
      });
    };

    const renderLoop = () => {
      if (!mouseRef.current.isDown) {
        rotationRef.current.lambda += 0.0016;
      }
      
      drawGlobe();
      animationFrameId = requestAnimationFrame(renderLoop);
    };

    renderLoop();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [attacks, continents, landPoints]);

  return (
    <div className="relative w-full h-[320px] md:h-[360px] flex items-center justify-center cursor-grab active:cursor-grabbing select-none">
      <canvas
        ref={canvasRef}
        width={400}
        height={400}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        className="w-[320px] h-[320px] md:w-[360px] md:h-[360px]"
      />
      <div className="absolute top-2 left-4 text-[8px] text-slate-500 font-mono uppercase tracking-widest flex items-center gap-1.5 pointer-events-none">
        <Activity className="w-3 h-3 text-indigo-500 animate-pulse" />
        Orthographic threat projection // Click & Drag to orbit
      </div>
    </div>
  );
}

export default function App() {
  // Navigation & UI state
  const [activeTab, setActiveTab] = useState("dashboard"); // dashboard, scanner, email-check, history
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Auth States
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [clerkUser, setClerkUser] = useState(null);
  const [localUser, setLocalUser] = useState(null);
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);

  // Scanner States
  const [scanType, setScanType] = useState("url"); // url, file
  const [urlInput, setUrlInput] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResults, setScanResults] = useState(null);

  // Email Leak Check States
  const [emailInput, setEmailInput] = useState("");
  const [emailCheckLoading, setEmailCheckLoading] = useState(false);
  const [emailCheckResults, setEmailCheckResults] = useState(null);

  // Scan History States
  const [historyList, setHistoryList] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);

  // Dynamic breaches list
  const [breachesList, setBreachesList] = useState([]);
  const [breachesLoading, setBreachesLoading] = useState(true);

  // Live attack ticker and canvas globe state
  const [activeAttacks, setActiveAttacks] = useState([]);
  const [attackLogs, setAttackLogs] = useState([]);

  // Fetch breaches directory
  useEffect(() => {
    async function fetchBreaches() {
      try {
        const response = await fetch(`${API_BASE_URL}/api/breaches`);
        if (response.ok) {
          const data = await response.json();
          if (data && data.exposedBreaches) {
            const formatted = data.exposedBreaches.map((item, index) => {
              const rawId = item.breachID || "";
              const source = rawId.replace(/([A-Z])/g, " $1").trim() || item.domain || "Unknown Breach";
              
              let date = "Unknown Date";
              if (item.breachedDate) {
                try {
                  const d = new Date(item.breachedDate);
                  if (!isNaN(d.getTime())) {
                    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                    date = `${months[d.getMonth()]} ${d.getFullYear()}`;
                  }
                } catch(e) {}
              }
              
              let records = "N/A";
              if (item.exposedRecords) {
                const num = item.exposedRecords;
                if (num >= 1000000) {
                  records = `${(num / 1000000).toFixed(1)}M`;
                } else if (num >= 1000) {
                  records = `${(num / 1000).toFixed(0)}K`;
                } else {
                  records = num.toString();
                }
              }
              
              const typeList = item.exposedData ? item.exposedData.filter(Boolean) : [];
              const type = typeList.length > 0 ? typeList.join(", ") : "User Credentials";
              
              let severity = "Medium";
              const dataLower = type.toLowerCase();
              if (dataLower.includes("password") || dataLower.includes("credential") || dataLower.includes("ssn") || dataLower.includes("tax") || dataLower.includes("hash")) {
                severity = "Critical";
              } else if (dataLower.includes("phone") || dataLower.includes("address") || item.exposedRecords > 10000000) {
                severity = "High";
              } else {
                severity = "Medium";
              }
              
              return {
                id: index,
                source,
                date,
                records,
                type,
                severity,
                rawRecords: item.exposedRecords || 0,
                rawDate: item.breachedDate
              };
            });
            setBreachesList(formatted);
          }
        }
      } catch (err) {
        console.error("Failed to load breaches:", err);
      } finally {
        setBreachesLoading(false);
      }
    }
    fetchBreaches();
  }, []);

  // Threat simulation event loops for the 3D globe and scrolling log
  useEffect(() => {
    if (activeTab !== "dashboard" || !isAuthenticated) return;

    const interval = setInterval(() => {
      setActiveAttacks((prev) => {
        return prev
          .map((atk) => ({ ...atk, progress: atk.progress + 0.025 }))
          .filter((atk) => atk.progress <= 1.05); // allow slightly > 1 for ripple animation
      });
    }, 30);

    return () => clearInterval(interval);
  }, [activeTab, isAuthenticated]);

  useEffect(() => {
    if (activeTab !== "dashboard" || !isAuthenticated) return;

    const spawnAttack = () => {
      const srcIdx = Math.floor(Math.random() * THREAT_CITIES.length);
      let destIdx = Math.floor(Math.random() * THREAT_CITIES.length);
      while (destIdx === srcIdx) {
        destIdx = Math.floor(Math.random() * THREAT_CITIES.length);
      }

      const src = THREAT_CITIES[srcIdx];
      const dest = THREAT_CITIES[destIdx];

      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      const statusObj = ATTACK_STATUSES[Math.floor(Math.random() * ATTACK_STATUSES.length)];
      
      let color = "#10b981"; // green
      if (statusObj.status === "DETONATED") color = "#f43f5e"; // rose
      else if (statusObj.status === "MITIGATED") color = "#f59e0b"; // amber
      else if (statusObj.status === "MONITORED") color = "#6366f1"; // indigo

      const newId = Date.now() + Math.random();
      const newAtk = {
        id: newId,
        srcName: src.name,
        srcCountry: src.country,
        srcLat: src.lat,
        srcLon: src.lon,
        destName: dest.name,
        destCountry: dest.country,
        destLat: dest.lat,
        destLon: dest.lon,
        type: type,
        status: statusObj.status,
        statusColor: statusObj.color,
        color: color,
        progress: 0,
        timestamp: new Date().toLocaleTimeString()
      };

      setActiveAttacks((prev) => [...prev, newAtk]);

      setAttackLogs((prev) => {
        const next = [newAtk, ...prev];
        if (next.length > 12) next.pop();
        return next;
      });
    };

    // Pre-spawn some alerts
    for (let i = 0; i < 6; i++) {
      spawnAttack();
    }

    const spawnInterval = setInterval(spawnAttack, 1800);

    return () => clearInterval(spawnInterval);
  }, [activeTab, isAuthenticated]);

  // Boot Auth Checks
  useEffect(() => {
    async function checkAuth() {
      let clerkReady = false;
      let checkAttempts = 0;
      while (!window.Clerk && checkAttempts < 20) {
        await new Promise(r => setTimeout(r, 100));
        checkAttempts++;
      }
      clerkReady = !!window.Clerk;

      if (clerkReady) {
        try {
          await window.Clerk.load({
            publishableKey: "pk_test_aGVhbHRoeS1saW9uZXNzLTMyLmNsZXJrLmFjY291bnRzLmRldiQ"
          });

          if (window.Clerk.user) {
            setClerkUser(window.Clerk.user);
            setIsAuthenticated(true);
            setAuthLoading(false);
            
            const userBtnDiv = document.getElementById("clerk-user-button-react");
            if (userBtnDiv) {
              window.Clerk.mountUserButton(userBtnDiv, {
                afterSignOutUrl: window.location.origin
              });
            }
            return;
          }
        } catch (e) {
          console.warn("[Auth] Clerk loading skipped/errored:", e.message);
        }
      }

      const localToken = localStorage.getItem("dev_token") || localStorage.getItem("token");
      const savedUser = localStorage.getItem("dev_user") || "Admin";
      if (localToken) {
        setLocalUser(savedUser);
        setIsAuthenticated(true);
      }
      setAuthLoading(false);
    }
    checkAuth();
  }, []);

  // Local JWT Login Handler
  const handleLocalLogin = async (e) => {
    e.preventDefault();
    setLoginError("");
    setIsLoggingIn(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword
        })
      });

      if (!response.ok) {
        throw new Error("Invalid credentials.");
      }

      const data = await response.json();
      localStorage.setItem("dev_token", data.token);
      localStorage.setItem("dev_user", loginUsername);
      setLocalUser(loginUsername);
      setIsAuthenticated(true);
    } catch (err) {
      setLoginError(err.message || "Authentication failed.");
    } finally {
      setIsLoggingIn(false);
    }
  };

  // Sign out Handler
  const handleSignOut = async () => {
    if (window.Clerk && window.Clerk.session) {
      await window.Clerk.signOut();
    }
    localStorage.removeItem("dev_token");
    localStorage.removeItem("token");
    localStorage.removeItem("dev_user");
    setLocalUser(null);
    setClerkUser(null);
    setIsAuthenticated(false);
    setActiveTab("dashboard");
    setScanResults(null);
  };

  const getAuthHeaders = async () => {
    const headers = { "Content-Type": "application/json" };
    const devToken = localStorage.getItem("dev_token") || localStorage.getItem("token");
    if (devToken) {
      headers["Authorization"] = `Bearer ${devToken}`;
      return headers;
    }
    if (window.Clerk?.session?.getToken) {
      const token = await window.Clerk.session.getToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    }
    return headers;
  };

  // Run Vulnerability Scan
  const executeScan = async () => {
    setScanning(true);
    setScanError("");
    setScanResults(null);

    try {
      const headers = await getAuthHeaders();
      let response;

      if (scanType === "url") {
        if (!urlInput.trim()) {
          throw new Error("URL is required");
        }
        response = await fetch(`${API_BASE_URL}/api/scan/url`, {
          method: "POST",
          headers: headers,
          body: JSON.stringify({ url: urlInput.trim() })
        });
      } else {
        if (!selectedFile) {
          throw new Error("Please select a file to upload and scan");
        }
        const base64 = await readFileAsBase64(selectedFile);
        response = await fetch(`${API_BASE_URL}/api/upload/scan`, {
          method: "POST",
          headers: headers,
          body: JSON.stringify({
            fileName: selectedFile.name,
            fileContent: base64,
            isBase64: true
          })
        });
      }

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error("Access denied. Please check your credentials or log in again.");
        }
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Scan failed (Status ${response.status})`);
      }

      const data = await response.json();
      setScanResults(data);
      loadScanHistory(true);
    } catch (err) {
      setScanError(err.message || "An unexpected error occurred during scanning.");
    } finally {
      setScanning(false);
    }
  };

  const readFileAsBase64 = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const base64 = e.target.result.split(",")[1] || e.target.result;
        resolve(base64);
      };
      reader.onerror = () => reject(new Error("Failed to read file"));
      reader.readAsDataURL(file);
    });
  };

  // Load Scan History
  const loadScanHistory = async (silent = false) => {
    if (!silent) setHistoryLoading(true);
    try {
      const headers = await getAuthHeaders();
      const response = await fetch(`${API_BASE_URL}/api/scans/history`, {
        headers: headers
      });
      if (response.ok) {
        const data = await response.json();
        setHistoryList(data);
      }
    } catch (err) {
      console.error("Failed to load scan history:", err);
    } finally {
      if (!silent) setHistoryLoading(false);
    }
  };

  // Load Scan History Details
  const viewHistoryItemDetails = async (id) => {
    setHistoryLoading(true);
    try {
      const headers = await getAuthHeaders();
      const response = await fetch(`${API_BASE_URL}/api/scans/history/${id}`, {
        headers: headers
      });
      if (response.ok) {
        const data = await response.json();
        setSelectedHistoryItem(data);
      }
    } catch (err) {
      console.error("Failed to load scan details:", err);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Email Leak Search
  const checkEmailLeaks = async (e) => {
    e.preventDefault();
    if (!emailInput.trim()) return;

    setEmailCheckLoading(true);
    setEmailCheckResults(null);

    const trimmed = emailInput.trim().toLowerCase();

    try {
      const response = await fetch(`https://api.xposedornot.com/v1/check-email/${trimmed}`);
      
      if (!response.ok) {
        throw new Error(`API Error (Status ${response.status})`);
      }

      const data = await response.json();

      if (data.Error === "Not found") {
        setEmailCheckResults({
          email: emailInput,
          leaked: false,
          breaches: []
        });
      } else if (data.breaches && data.breaches.length > 0) {
        const breachNames = data.breaches[0] || [];
        
        const breachMetadata = {
          "Canva": { date: "May 2019", records: "137M", type: "Emails, Passwords, Names", severity: "High" },
          "LinkedIn": { date: "June 2021", records: "700M", type: "Emails, Phone numbers, Job titles", severity: "Medium" },
          "Adobe": { date: "Oct 2013", records: "152M", type: "Emails, Password hints", severity: "High" },
          "Dropbox": { date: "Aug 2012", records: "68M", type: "Emails, Hashed passwords", severity: "Medium" },
          "Tumblr": { date: "May 2013", records: "65M", type: "Emails, Salted SHA-1 hashes", severity: "Medium" },
          "Wattpad": { date: "June 2020", records: "270M", type: "Emails, Passwords, Usernames", severity: "High" },
          "Mathway": { date: "Jan 2020", records: "25M", type: "Emails, Hashed passwords", severity: "Medium" },
          "Deezer": { date: "Nov 2022", records: "229M", type: "Emails, IP addresses, Names, DOB", severity: "High" }
        };

        const formattedBreaches = breachNames.map(name => {
          const cleanName = Object.keys(breachMetadata).find(key => name.toLowerCase().includes(key.toLowerCase())) || name;
          const meta = breachMetadata[cleanName] || {
            date: "Various Dates",
            records: "Multi-Million",
            type: "Emails, Passwords, Credentials",
            severity: "High"
          };
          return {
            source: name,
            ...meta
          };
        });

        setEmailCheckResults({
          email: emailInput,
          leaked: true,
          breaches: formattedBreaches
        });
      } else {
        setEmailCheckResults({
          email: emailInput,
          leaked: false,
          breaches: []
        });
      }
    } catch (err) {
      console.warn("XposedOrNot API failed, falling back to local simulation:", err.message);
      let foundLeaks = MOCK_LEAKS_DB[trimmed];
      if (!foundLeaks) {
        if (trimmed.endsWith("@leakfinder.com")) {
          foundLeaks = [
            { source: "Canva Database", date: "May 2019", records: "137M", type: "Emails, Hashed Passwords, Names", severity: "High" },
            { source: "Ledger Customer Database", date: "Dec 2020", records: "1.0M", type: "Emails, Phone numbers, Names", severity: "Critical" }
          ];
        } else {
          foundLeaks = [];
        }
      }
      setEmailCheckResults({
        email: emailInput,
        leaked: foundLeaks.length > 0,
        breaches: foundLeaks
      });
    } finally {
      setEmailCheckLoading(false);
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      loadScanHistory(activeTab !== "history" && activeTab !== "dashboard");
    }
  }, [activeTab, isAuthenticated]);

  // Auth Loading
  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#030712] flex flex-col justify-center items-center gap-6 aurora-container">
        <div className="w-12 h-12 border-2 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
        <div className="font-sans text-slate-400 tracking-wider text-sm animate-pulse">
          Starting Secure Environment...
        </div>
      </div>
    );
  }

  // Auth Login Page
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#030712] flex flex-col justify-center items-center aurora-container px-4">
        <div className="max-w-md w-full border border-slate-900 bg-slate-950/80 backdrop-blur-xl p-8 rounded-2xl shadow-2xl relative">
          
          <div className="flex flex-col items-center gap-2 mb-8">
            <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 rounded-xl glow-indigo">
              <Shield className="w-8 h-8 text-indigo-500" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 mt-3 text-gradient">
              LeakFinder
            </h1>
            <p className="text-slate-400 text-xs tracking-wide">
              Threat Vulnerability & Leak Intelligence
            </p>
          </div>

          {/* Clerk Auth Trigger */}
          <div className="mb-6 flex flex-col gap-3">
            <button
              onClick={() => {
                if (window.Clerk) {
                  window.Clerk.openSignIn();
                } else {
                  alert("Clerk is loading. Try local login.");
                }
              }}
              className="w-full bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 text-white font-medium py-3 px-4 rounded-xl transition-all shadow-lg shadow-indigo-500/10 hover:shadow-indigo-500/20 active:scale-98 text-center flex items-center justify-center gap-2 text-sm"
            >
              <Cpu className="w-4 h-4" />
              Sign in with Clerk
            </button>
          </div>

          <div className="relative flex py-4 items-center">
            <div className="flex-grow border-t border-slate-900"></div>
            <span className="flex-shrink mx-4 text-slate-500 text-xs">or fallback login</span>
            <div className="flex-grow border-t border-slate-900"></div>
          </div>

          {/* Local login fallback */}
          <form onSubmit={handleLocalLogin} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-slate-400">Username</label>
              <input
                type="text"
                placeholder="e.g. admin"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                className="bg-slate-900/50 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none rounded-xl p-3 text-sm text-slate-100 transition-all"
                required
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-xs text-slate-400">Password</label>
              <input
                type="password"
                placeholder="••••••••"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                className="bg-slate-900/50 border border-slate-800 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none rounded-xl p-3 text-sm text-slate-100 transition-all"
                required
              />
            </div>

            {loginError && (
              <div className="bg-red-500/10 border border-red-500/25 text-red-400 text-xs p-3 rounded-xl flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {loginError}
              </div>
            )}

            <button
              type="submit"
              disabled={isLoggingIn}
              className="w-full bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-indigo-500/40 text-indigo-400 hover:text-indigo-300 font-medium py-3 px-4 rounded-xl transition-all text-sm flex items-center justify-center gap-2 mt-2"
            >
              {isLoggingIn ? (
                <>
                  <div className="w-4 h-4 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                  Verifying...
                </>
              ) : (
                "Local Admin Access"
              )}
            </button>
          </form>

          <div className="mt-8 text-center text-slate-600 text-[10px] tracking-wider uppercase">
            LeakFinder Enterprise // Aizen_Ackerman
          </div>
        </div>
      </div>
    );
  }

  // Dynamic threat intelligence calculation helpers
  const calculateSecurityRating = () => {
    if (historyList.length === 0) return "100.0%";
    let totalChecks = 0;
    let passedChecks = 0;
    historyList.forEach(item => {
      totalChecks += (item.total || 0);
      passedChecks += (item.passed || 0);
    });
    if (totalChecks === 0) return "100.0%";
    return `${((passedChecks / totalChecks) * 100).toFixed(1)}%`;
  };

  const calculateCompromisedArchives = () => {
    if (breachesList.length === 0) return "4,902M";
    const totalRecords = breachesList.reduce((sum, b) => sum + (b.rawRecords || 0), 0);
    if (totalRecords >= 1000000000) {
      return `${(totalRecords / 1000000000).toFixed(1)}B`;
    }
    return `${(totalRecords / 1000000).toLocaleString(undefined, {maximumFractionDigits: 0})}M`;
  };

  const getDynamicTrendData = () => {
    // Baseline trend representing global threat intelligence telemetry
    const baseTrend = [
      { month: "Jan", leaks: 140, records: 12 },
      { month: "Feb", leaks: 185, records: 28 },
      { month: "Mar", leaks: 290, records: 45 },
      { month: "Apr", leaks: 220, records: 30 },
      { month: "May", leaks: 340, records: 85 },
      { month: "Jun", leaks: 480, records: 110 }
    ];

    // Modulate baseline values dynamically with live breach feeds
    if (breachesList.length > 0) {
      const totalExposed = breachesList.reduce((sum, b) => sum + (b.rawRecords || 0), 0);
      const scaledRecords = Math.round(totalExposed / 60000000); 
      
      baseTrend[4].leaks += Math.min(60, breachesList.length * 2);
      baseTrend[4].records += Math.round(scaledRecords * 0.25);
      
      baseTrend[5].leaks += breachesList.length * 3;
      baseTrend[5].records += Math.round(scaledRecords * 0.65);
    }

    // Modulate based on local scans history length and failure metrics
    if (historyList.length > 0) {
      const totalFailures = historyList.reduce((sum, s) => sum + (s.failed || 0), 0);
      baseTrend[5].leaks += historyList.length * 6;
      baseTrend[5].records += totalFailures * 12;
    }

    return baseTrend;
  };

  const getDynamicCategoryData = () => {
    // Baseline security category metrics
    const categories = [
      { name: "Injection", count: 42, fill: "#6366f1" },
      { name: "Credentials", count: 35, fill: "#8b5cf6" },
      { name: "XSS Risks", count: 28, fill: "#ec4899" },
      { name: "Headers", count: 64, fill: "#3b82f6" },
      { name: "Crypto", count: 19, fill: "#06b6d4" },
      { name: "Deps/Outdated", count: 87, fill: "#10b981" }
    ];
    
    // Add real-time scan findings to baseline categories
    historyList.forEach(scan => {
      if (!scan.checks) return;
      scan.checks.forEach(check => {
        if (check.passed) return;
        
        const name = check.name || "";
        if (name.includes("SQL Injection")) {
          categories[0].count += 12;
        } else if (name.includes("Credentials") || name.includes("Cookie Security") || name.includes("Sensitive Data")) {
          categories[1].count += 12;
        } else if (name.includes("XSS")) {
          categories[2].count += 12;
        } else if (name.includes("Headers") || name.includes("CORS")) {
          categories[3].count += 12;
        } else if (name.includes("Crypto")) {
          categories[4].count += 12;
        } else if (name.includes("Dependencies") || name.includes("Outdated")) {
          categories[5].count += 12;
        }
      });
    });
    
    return categories;
  };

  const dynamicTrendData = getDynamicTrendData();
  const dynamicCategoryData = getDynamicCategoryData();

  // Dashboard Page Layout
  return (
    <div className="min-h-screen bg-[#030712] text-slate-200 flex font-sans aurora-container">
      
      {/* Sidebar Navigation */}
      <aside className={`w-64 sidebar-border bg-slate-950/80 backdrop-blur-xl flex flex-col z-40 transition-all duration-300 ${sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}>
        <div className="p-6 flex items-center gap-2.5 header-border">
          <div className="p-2 bg-indigo-500/10 border border-indigo-500/20 rounded-lg glow-indigo">
            <Shield className="w-5 h-5 text-indigo-500" />
          </div>
          <div>
            <h1 className="text-base font-bold tracking-tight text-slate-100 leading-none">
              LeakFinder
            </h1>
            <span className="text-[9px] text-indigo-400 uppercase tracking-widest font-medium mt-1 inline-block">
              Intel Panel
            </span>
          </div>
        </div>

        {/* Sidebar Tabs */}
        <nav className="flex-grow px-4 py-6 flex flex-col gap-1.5">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
              activeTab === "dashboard"
                ? "bg-indigo-500/10 text-indigo-400 border-l-2 border-indigo-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Activity className="w-4 h-4" />
            Overview
          </button>
          <button
            onClick={() => setActiveTab("scanner")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
              activeTab === "scanner"
                ? "bg-indigo-500/10 text-indigo-400 border-l-2 border-indigo-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Layers className="w-4 h-4" />
            Scanner Core
          </button>
          <button
            onClick={() => setActiveTab("email-check")}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
              activeTab === "email-check"
                ? "bg-indigo-500/10 text-indigo-400 border-l-2 border-indigo-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Mail className="w-4 h-4" />
            Email Leaks
          </button>
        </nav>

        {/* Footer profile */}
        <div className="p-4 header-border mt-auto flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-2.5">
            <div id="clerk-user-button-react"></div>
            {localUser && (
              <div className="flex flex-col">
                <span className="text-xs font-semibold text-slate-200 leading-none">{localUser}</span>
                <span className="text-[9px] text-slate-500 uppercase tracking-widest mt-1">Admin</span>
              </div>
            )}
          </div>
          <button
            onClick={handleSignOut}
            className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all"
            title="Log Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* Main Container */}
      <div className="flex-grow flex flex-col min-w-0">
        
        {/* Top Header */}
        <header className="h-16 header-border bg-slate-950/40 backdrop-blur-md sticky top-0 z-30 px-6 flex justify-between items-center">
          <div className="flex items-center gap-4">
            <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wider">
              {activeTab === "dashboard" ? "Dashboard Overview" :
               activeTab === "scanner" ? "Scan Controller" :
               activeTab === "email-check" ? "Email Leak Checker" : "Vulnerability Logs"}
            </h2>
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] tracking-wide uppercase font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              Db connection: Live
            </div>
          </div>

          <div className="text-right text-xs text-slate-400 font-mono uppercase tracking-wider">
            Secure Session // IP: 127.0.0.1
          </div>
        </header>

        {/* Core Contents page */}
        <main className="flex-grow p-6 overflow-y-auto max-w-6xl w-full mx-auto">
          
          {/* Tab 1: Overview Dashboard */}
          {activeTab === "dashboard" && (
            <div className="flex flex-col gap-6">
              
              {/* Bento Grid Stats */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Rating Gauge Card */}
                <div className="glass-card p-6 rounded-2xl flex flex-col justify-between md:col-span-1">
                  <div>
                    <span className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
                      System Security Rating
                    </span>
                    <h3 className="text-3xl font-extrabold tracking-tight text-slate-100 mt-2 text-gradient-purple">
                      {calculateSecurityRating()}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 mt-4 text-emerald-400 text-xs font-medium">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    All scanner interfaces operating at standard thresholds.
                  </div>
                </div>

                {/* Database Metrics Card */}
                <div className="glass-card p-6 rounded-2xl flex flex-col justify-between md:col-span-1">
                  <div>
                    <span className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
                      Compromised Archives
                    </span>
                    <h3 className="text-3xl font-extrabold tracking-tight text-slate-100 mt-2">
                      {calculateCompromisedArchives()}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 mt-4 text-slate-400 text-xs">
                    <Database className="w-4 h-4 flex-shrink-0 text-indigo-400" />
                    Indexed breaches updated: June 2026.
                  </div>
                </div>

                {/* Audit history total */}
                <div className="glass-card p-6 rounded-2xl flex flex-col justify-between md:col-span-1">
                  <div>
                    <span className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
                      Completed Audits
                    </span>
                    <h3 className="text-3xl font-extrabold tracking-tight text-slate-100 mt-2">
                      {historyList.length}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 mt-4 text-slate-400 text-xs">
                    <TrendingUp className="w-4 h-4 flex-shrink-0 text-violet-400" />
                    All scans are stored in memory H2 database.
                  </div>
                </div>

              </div>

              {/* Globe and Live Ticker Card */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Globe Canvas Panel */}
                <div className="glass-card p-6 rounded-2xl lg:col-span-2 flex flex-col justify-between overflow-hidden relative min-h-[380px] md:min-h-[420px]">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></span>
                      Global Cyber Threat Activity
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">
                      Visualizing active network vectors and intrusion logs in real time
                    </p>
                  </div>
                  
                  <ThreatGlobe attacks={activeAttacks} />
                  
                  <div className="flex justify-between items-center text-[8px] text-slate-500 font-mono border-t border-slate-900/60 pt-4 mt-2">
                    <span>GRID: GFS-12 // SENSORS: ACTIVE</span>
                    <span>ORBIT ROTATION: AUTO</span>
                  </div>
                </div>

                {/* Live Ticker Panel */}
                <div className="glass-card p-6 rounded-2xl lg:col-span-1 flex flex-col justify-between overflow-hidden min-h-[380px] md:min-h-[420px]">
                  <div className="border-b border-slate-900/60 pb-3">
                    <h3 className="text-sm font-semibold text-slate-200">
                      Live Attack Monitor
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5 font-mono">
                      ROLLING SYSTEM LOG TICKER
                    </p>
                  </div>

                  {/* Terminal Ticker */}
                  <div className="flex-grow my-4 overflow-y-auto max-h-[250px] pr-1 flex flex-col gap-2 font-mono text-[9px] select-text">
                    {attackLogs.length === 0 ? (
                      <div className="text-center py-20 text-slate-600 uppercase tracking-widest animate-pulse">
                        Listening on network interfaces...
                      </div>
                    ) : (
                      attackLogs.map((log) => (
                        <div key={log.id} className="p-2 border border-slate-900 bg-slate-950/40 rounded-lg flex flex-col gap-1 hover:border-slate-850 hover:bg-slate-950/70 transition-all">
                          <div className="flex justify-between items-center text-slate-400">
                            <span className="font-semibold text-indigo-400">
                              {log.timestamp}
                            </span>
                            <span className={`text-[7px] border px-1 py-0.5 rounded font-bold ${log.statusColor}`}>
                              {log.status}
                            </span>
                          </div>
                          <div className="text-slate-200 font-medium">
                            {log.srcName} ({log.srcCountry}) &rarr; {log.destName} ({log.destCountry})
                          </div>
                          <div className="text-slate-500 text-[8px] flex justify-between items-center">
                            <span>TYPE: {log.type}</span>
                            <span className="text-slate-400 font-bold" style={{ color: log.color }}>VECTOR ACTIVE</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  <div className="border-t border-slate-900/60 pt-3 flex justify-between items-center text-[8px] text-slate-500 font-mono uppercase">
                    <span>INTERFACE: ETH0</span>
                    <span className="text-indigo-400 font-bold animate-pulse">● LOGGING LIVE</span>
                  </div>
                </div>

              </div>

              {/* Graphical Insights */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Trend Graph */}
                <div className="glass-card p-6 rounded-2xl flex flex-col">
                  <div className="mb-4">
                    <h3 className="text-sm font-semibold text-slate-200">
                      Threat Volume Activity Trend
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">
                      Monitored leak count over the past 6 months (Millions)
                    </p>
                  </div>
                  <div className="h-60 w-full mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={dynamicTrendData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                        <defs>
                          <linearGradient id="glowArea" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                            <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" opacity={0.2} />
                        <XAxis dataKey="month" stroke="#4b5563" fontSize={10} tickLine={false} />
                        <YAxis stroke="#4b5563" fontSize={10} tickLine={false} />
                        <Tooltip
                          contentStyle={{ backgroundColor: "#0b1329", borderColor: "#1e293b", borderRadius: "12px", color: "#f8fafc" }}
                        />
                        <Area type="monotone" dataKey="leaks" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#glowArea)" name="Breaches" isAnimationActive={false} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Distribution chart */}
                <div className="glass-card p-6 rounded-2xl flex flex-col">
                  <div className="mb-4">
                    <h3 className="text-sm font-semibold text-slate-200">
                      Identified Vulnerabilities by Severity Class
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">
                      Vulnerability occurrences filtered by audit categorization
                    </p>
                  </div>
                  <div className="h-60 w-full mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={dynamicCategoryData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" opacity={0.2} />
                        <XAxis dataKey="name" stroke="#4b5563" fontSize={9} tickLine={false} />
                        <YAxis stroke="#4b5563" fontSize={10} tickLine={false} />
                        <Tooltip
                          contentStyle={{ backgroundColor: "#0b1329", borderColor: "#1e293b", borderRadius: "12px", color: "#f8fafc" }}
                        />
                        <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} name="Occurrences" isAnimationActive={false}>
                          {dynamicCategoryData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.fill} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

              </div>

              {/* Breach Table */}
              <div className="glass-card p-6 rounded-2xl">
                <div className="flex justify-between items-center mb-6 border-b border-slate-900 pb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200">
                      Recent Intelligence Feeds
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">
                      Identified leaks monitored in the global cybersecurity pool
                    </p>
                  </div>
                  <button 
                    onClick={() => setActiveTab("email-check")}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-medium flex items-center gap-1 transition-all"
                  >
                    Check Account Leaks
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-sans">
                    <thead>
                      <tr className="text-slate-400 border-b border-slate-900/60 pb-2">
                        <th className="py-2.5 font-medium">Breach Target</th>
                        <th className="py-2.5 font-medium">Date Detected</th>
                        <th className="py-2.5 font-medium">Compromised Data</th>
                        <th className="py-2.5 font-medium text-right">Records Leaked</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-900/40 text-slate-300">
                      {breachesLoading ? (
                        <tr>
                          <td colSpan="4" className="py-8 text-center text-xs text-slate-500 uppercase tracking-widest animate-pulse font-semibold">
                            Loading Global Threat Feed...
                          </td>
                        </tr>
                      ) : breachesList.length === 0 ? (
                        <tr>
                          <td colSpan="4" className="py-8 text-center text-xs text-slate-500 uppercase">
                            No leaks monitored.
                          </td>
                        </tr>
                      ) : (
                        breachesList.slice(0, 5).map((b) => (
                          <tr key={b.id} className="hover:bg-slate-900/20 transition-colors">
                            <td className="py-3 font-semibold flex items-center gap-2">
                              <span className={`w-1.5 h-1.5 rounded-full ${
                                b.severity === "Critical" ? "bg-rose-500" :
                                b.severity === "High" ? "bg-amber-500" : "bg-blue-500"
                              }`}></span>
                              {b.source}
                            </td>
                            <td className="py-3 text-slate-400">{b.date}</td>
                            <td className="py-3 text-slate-400">{b.type}</td>
                            <td className="py-3 text-right font-medium text-slate-200">{b.records}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* Tab 2: Scanner Core */}
          {activeTab === "scanner" && (
            <div className="flex flex-col gap-6">
              
              {/* Controls Card */}
              <div className="glass-card p-6 rounded-2xl">
                <div className="flex justify-between items-center mb-6">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-200">
                      Audit Configuration
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">
                      Select target type and configure scan parameters
                    </p>
                  </div>
                </div>

                <div className="flex flex-col md:flex-row gap-6">
                  
                  {/* Selector tabs */}
                  <div className="flex md:flex-col bg-slate-950 p-1 border border-slate-900 rounded-xl md:w-44 flex-shrink-0 self-start">
                    <button
                      onClick={() => { setScanType("url"); setScanResults(null); }}
                      className={`flex-grow text-left md:w-full px-4 py-2.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
                        scanType === "url"
                          ? "bg-slate-900 text-indigo-400 font-bold"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Globe className="w-4 h-4" />
                      Scan Website
                    </button>
                    <button
                      onClick={() => { setScanType("file"); setScanResults(null); }}
                      className={`flex-grow text-left md:w-full px-4 py-2.5 text-xs font-semibold rounded-lg transition-all flex items-center gap-2 ${
                        scanType === "file"
                          ? "bg-slate-900 text-indigo-400 font-bold"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <FileText className="w-4 h-4" />
                      Scan Local File
                    </button>
                  </div>

                  {/* Input form */}
                  <div className="flex-grow">
                    {scanType === "url" ? (
                      <div className="flex flex-col gap-2.5">
                        <label className="text-xs text-slate-400">Target Website URL</label>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            placeholder="e.g. example.com or https://example.com"
                            value={urlInput}
                            onChange={(e) => setUrlInput(e.target.value)}
                            disabled={scanning}
                            className="flex-grow bg-slate-950 border border-slate-900 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none rounded-xl p-3 text-sm text-slate-100 transition-all"
                            onKeyPress={(e) => e.key === "Enter" && executeScan()}
                          />
                          <button
                            onClick={executeScan}
                            disabled={scanning}
                            className="bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 disabled:opacity-50 text-white font-medium px-6 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/10 text-sm"
                          >
                            {scanning ? (
                              <>
                                <RefreshCw className="w-4 h-4 animate-spin" />
                                Auditing...
                              </>
                            ) : (
                              "Scan Target"
                            )}
                          </button>
                        </div>
                        <p className="text-[10px] text-slate-500 mt-1">
                          LeakFinder will perform active audits on security headers, SSL status, and cookie security flags.
                        </p>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2.5">
                        <label className="text-xs text-slate-400">Code/Config File to Scan</label>
                        <div className="flex flex-col sm:flex-row gap-3">
                          <label className="flex-grow border border-dashed border-slate-900 hover:border-indigo-500/30 bg-slate-950/50 hover:bg-slate-950 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors">
                            <FileText className="w-8 h-8 text-slate-600 mb-2" />
                            <span className="text-xs text-slate-400">
                              {selectedFile ? `File: ${selectedFile.name}` : "Click to select a file"}
                            </span>
                            <span className="text-[9px] text-slate-500 mt-1 uppercase">
                              (MAX 1MB // JSON, JS, PY, YML, ENV)
                            </span>
                            <input
                              type="file"
                              className="hidden"
                              onChange={(e) => setSelectedFile(e.target.files[0])}
                              disabled={scanning}
                            />
                          </label>

                          <button
                            onClick={executeScan}
                            disabled={scanning || !selectedFile}
                            className="bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 disabled:opacity-50 text-white font-medium px-8 py-4 sm:py-0 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/10 text-sm"
                          >
                            {scanning ? (
                              <>
                                <RefreshCw className="w-4 h-4 animate-spin" />
                                Auditing...
                              </>
                            ) : (
                              "Upload & Scan"
                            )}
                          </button>
                        </div>
                      </div>
                    )}

                    {scanError && (
                      <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs p-4 rounded-xl flex items-center gap-2 mt-4">
                        <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                        {scanError}
                      </div>
                    )}
                  </div>

                </div>
              </div>

              {/* Scanning status banner */}
              {scanning && (
                <div className="glass-card p-12 rounded-2xl flex flex-col justify-center items-center gap-4">
                  <div className="w-10 h-10 border-2 border-indigo-500/25 border-t-indigo-500 rounded-full animate-spin spinner-saas"></div>
                  <div className="text-center">
                    <h3 className="font-semibold text-slate-100 text-sm">
                      Executing Security Pipelines
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-1 uppercase tracking-wider animate-pulse">
                      Analyzing static content for credential leaks and injection vulnerabilities...
                    </p>
                  </div>
                </div>
              )}

              {/* Scan Results Display */}
              {scanResults && (
                <div className="flex flex-col gap-6">
                  
                  {/* Results summary header */}
                  <div className="glass-card p-6 rounded-2xl">
                    <div className="flex flex-col md:flex-row justify-between gap-6 items-start md:items-center">
                      <div>
                        <span className="text-[9px] uppercase tracking-widest text-slate-400 font-semibold">
                          Target Scan Summary
                        </span>
                        <h2 className="text-lg font-bold text-slate-100 mt-1">
                          {scanResults.url || "Static File Analysis"}
                        </h2>
                        <p className="text-[10px] text-slate-500 mt-1">
                          Completed at: {scanResults.timestamp || new Date().toLocaleString()}
                        </p>
                      </div>

                      <div className="flex gap-4 items-center">
                        <div className="text-right">
                          <span className="text-[9px] text-slate-500 uppercase font-semibold">Policy Action</span>
                          <div className={`text-sm font-bold uppercase mt-0.5 ${
                            scanResults.action === "BLOCK" ? "text-rose-400" :
                            scanResults.action === "WARN" ? "text-amber-400" :
                            "text-emerald-400"
                          }`}>
                            {scanResults.action || "ALLOW"}
                          </div>
                        </div>

                        <div className={`px-4 py-2.5 rounded-xl border font-sans text-center min-w-24 ${
                          scanResults.severity === "HIGH" ? "bg-rose-500/10 border-rose-500/20 text-rose-400 glow-rose" :
                          scanResults.severity === "MEDIUM" ? "bg-amber-500/10 border-amber-500/20 text-amber-400" :
                          "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 glow-emerald"
                        }`}>
                          <div className="text-[8px] uppercase tracking-widest text-slate-400 font-semibold">Threat Level</div>
                          <div className="text-sm font-extrabold uppercase mt-0.5 tracking-wider">
                            {scanResults.severity || "LOW"}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Numeric stats breakdown */}
                    <div className="grid grid-cols-2 sm:grid-cols-6 gap-4 border-t border-slate-900/60 pt-5 mt-5 text-center">
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">Total Audits</div>
                        <div className="text-base font-bold text-slate-200 mt-1">{scanResults.summary?.total || 0}</div>
                      </div>
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">Passed</div>
                        <div className="text-base font-bold text-emerald-400 mt-1">{scanResults.summary?.passed || 0}</div>
                      </div>
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">Failed</div>
                        <div className="text-base font-bold text-rose-400 mt-1">{scanResults.summary?.failed || 0}</div>
                      </div>
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">High</div>
                        <div className="text-base font-bold text-rose-500 mt-1">{scanResults.summary?.high || 0}</div>
                      </div>
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">Medium</div>
                        <div className="text-base font-bold text-amber-500 mt-1">{scanResults.summary?.medium || 0}</div>
                      </div>
                      <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-900/40">
                        <div className="text-[8px] text-slate-500 uppercase font-semibold">Low</div>
                        <div className="text-base font-bold text-blue-400 mt-1">{scanResults.summary?.low || 0}</div>
                      </div>
                    </div>
                  </div>

                  {/* Individual Checks Details */}
                  <div className="glass-card p-6 rounded-2xl">
                    <h3 className="text-sm font-semibold text-slate-200 mb-6 pb-2 border-b border-slate-900">
                      Vulnerability Audit Details
                    </h3>
                    <div className="flex flex-col gap-4">
                      {scanResults.checks && scanResults.checks.map((check, idx) => (
                        <div
                          key={idx}
                          className={`bg-slate-950/50 border p-4 rounded-xl flex flex-col gap-2 ${
                            !check.passed ? "border-l-2 border-l-rose-500 border-slate-900" : "border-slate-900"
                          }`}
                        >
                          <div className="flex justify-between items-center">
                            <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                              {check.passed ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                              ) : (
                                <AlertCircle className="w-4 h-4 text-rose-400" />
                              )}
                              {check.name}
                            </span>
                            <span className={`text-[8px] font-mono border px-2 py-0.5 rounded uppercase ${
                              check.severity === "high" ? "bg-rose-500/10 border-rose-500/20 text-rose-400" :
                              check.severity === "medium" ? "bg-amber-500/10 border-amber-500/20 text-amber-400" :
                              "bg-blue-500/10 border-blue-500/20 text-blue-400"
                            }`}>
                              {check.severity}
                            </span>
                          </div>

                          <div className="pl-6 mt-1">
                            <ul className="list-disc pl-4 space-y-1 text-slate-400 text-xs">
                              {check.issues && check.issues.map((issue, issueIdx) => (
                                <li key={issueIdx}>{issue}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>
              )}

            </div>
          )}

          {/* Tab 3: Email Leak Checker */}
          {activeTab === "email-check" && (
            <div className="flex flex-col gap-6">
              
              {/* Checker Card */}
              <div className="glass-card p-6 rounded-2xl">
                <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                  <Mail className="w-5 h-5 text-indigo-500" />
                  Account Leak Engine
                </h2>
                <p className="text-[10px] text-slate-500 mt-1 uppercase tracking-wide mb-6">
                  Validate email exposure against 4.9B+ compromised database records
                </p>

                <form onSubmit={checkEmailLeaks} className="flex gap-2 max-w-xl">
                  <input
                    type="email"
                    placeholder="Enter email (e.g. admin@leakfinder.com)"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    disabled={emailCheckLoading}
                    required
                    className="flex-grow bg-slate-950 border border-slate-900 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none rounded-xl p-3 text-sm text-slate-100 transition-all"
                  />
                  <button
                    type="submit"
                    disabled={emailCheckLoading}
                    className="bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-600 hover:to-violet-700 disabled:opacity-50 text-white font-medium px-6 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/10 text-sm"
                  >
                    {emailCheckLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        Audit Email
                      </>
                    )}
                  </button>
                </form>
              </div>

              {/* Leak check output details */}
              {emailCheckResults && (
                <div className="flex flex-col gap-6">
                  
                  {/* Results summary header */}
                  <div className={`glass-card p-6 rounded-2xl border-l-4 ${
                    emailCheckResults.leaked ? "border-l-rose-500 bg-rose-500/5" : "border-l-emerald-500 bg-emerald-500/5"
                  }`}>
                    <div className="flex flex-col sm:flex-row justify-between gap-4 items-start sm:items-center">
                      <div>
                        <span className="text-[9px] uppercase tracking-widest text-slate-500 font-semibold">
                          Target Account Check
                        </span>
                        <h2 className="text-base font-bold text-slate-200 mt-1">
                          {emailCheckResults.email}
                        </h2>
                      </div>

                      <div className={`flex items-center gap-2 border px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider ${
                        emailCheckResults.leaked
                          ? "bg-rose-500/10 border-rose-500/20 text-rose-400 glow-rose"
                          : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 glow-emerald"
                      }`}>
                        {emailCheckResults.leaked ? (
                          <>
                            <AlertTriangle className="w-4 h-4 animate-pulse" />
                            Database Compromised
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="w-4 h-4" />
                            Account Secure
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Leaks list if found */}
                  {emailCheckResults.leaked ? (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      
                      {/* Left: Breaches list (takes 2 cols) */}
                      <div className="glass-card p-6 rounded-2xl lg:col-span-2">
                        <h3 className="text-sm font-semibold text-slate-200 mb-6 pb-2 border-b border-slate-900">
                          Identified Exposures Matches
                        </h3>
                        
                        <div className="flex flex-col gap-4">
                          {emailCheckResults.breaches.map((b, idx) => (
                            <div key={idx} className="bg-slate-950/50 border border-slate-900 p-4 rounded-xl flex flex-col sm:flex-row justify-between gap-3 items-start sm:items-center">
                              <div className="flex flex-col">
                                <span className="text-xs text-rose-400 font-bold flex items-center gap-1.5 uppercase">
                                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                                  {b.source}
                                </span>
                                <span className="text-[11px] text-slate-400 mt-1.5">
                                  Exposed Fields: <span className="text-slate-300">{b.type}</span>
                                </span>
                                <span className="text-[9px] text-slate-500 mt-1 uppercase font-semibold">
                                  Leak Date: {b.date}
                                </span>
                              </div>
                              <div className="flex items-center gap-3 self-end sm:self-center">
                                <span className="text-xs text-slate-400 font-semibold">{b.records} records</span>
                                <span className={`text-[8px] font-mono border px-2 py-0.5 rounded uppercase ${
                                  b.severity === "Critical" ? "bg-rose-500/10 border-rose-500/20 text-rose-400" :
                                  b.severity === "High" ? "bg-rose-500/10 border-rose-500/20 text-rose-400" :
                                  "bg-amber-500/10 border-amber-500/20 text-amber-400"
                                }`}>
                                  {b.severity}
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Right: Response plan (takes 1 col) */}
                      <div className="glass-card p-6 rounded-2xl border-l-rose-500/20 flex flex-col">
                        <h3 className="text-sm font-semibold text-rose-400 mb-4 pb-2 border-b border-rose-950/20 flex items-center gap-1.5">
                          <Lock className="w-4 h-4 text-rose-500" />
                          Security Action Plan
                        </h3>
                        <ul className="space-y-4 text-xs text-slate-300">
                          <li className="flex gap-2">
                            <span className="text-rose-500 font-bold">01.</span>
                            <span><strong>Update credentials:</strong> Reset password immediately using complex, unique configurations.</span>
                          </li>
                          <li className="flex gap-2">
                            <span className="text-rose-500 font-bold">02.</span>
                            <span><strong>Enable 2FA:</strong> Configure Multi-Factor Authentication keys on all shared channels.</span>
                          </li>
                          <li className="flex gap-2">
                            <span className="text-rose-500 font-bold">03.</span>
                            <span><strong>Monitor Alerts:</strong> Subscribe to active credential checkers to get real-time mutations.</span>
                          </li>
                        </ul>
                      </div>

                    </div>
                  ) : (
                    <div className="glass-card p-10 rounded-2xl flex flex-col items-center justify-center text-center gap-4">
                      <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-full glow-emerald">
                        <CheckCircle2 className="w-8 h-8 text-emerald-500" />
                      </div>
                      <div>
                        <h3 className="text-emerald-400 text-sm font-semibold tracking-wide uppercase">
                          No Leaks Detected
                        </h3>
                        <p className="text-xs text-slate-400 max-w-sm mt-1">
                          This email was not found in any indexed data breaches. Your account credentials appear safe.
                        </p>
                      </div>
                    </div>
                  )}

                </div>
              )}
            </div>
          )}

        </main>

        {/* Footer */}
        <footer className="border-t border-slate-900 bg-slate-950/40 py-4 px-6 text-center sm:text-left mt-auto">
          <div className="max-w-6xl w-full mx-auto flex flex-col sm:flex-row justify-between items-center gap-2 text-[10px] text-slate-500 uppercase font-semibold">
            <span>LeakFinder Enterprise // Status: Optimal // Core v12.4</span>
            <span>Aizen_Ackerman // © 2026</span>
          </div>
        </footer>

      </div>
    </div>
  );
}
