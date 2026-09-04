/**
 * RealTimeContext.jsx
 * Global Socket.IO connection shared across all pages.
 * Provides live system metrics, attack events, and timeline data.
 */
import { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from './AuthContext';

const RealTimeContext = createContext(null);

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 
                   (import.meta.env.VITE_API_URL && import.meta.env.VITE_API_URL !== '/api' ? import.meta.env.VITE_API_URL.replace(/\/api$/, '') : '') || 
                   (import.meta.env.DEV ? 'http://localhost:10000' : window.location.origin);
const MAX_FEED_EVENTS = 60; // Rolling window of last 60 attacks
const MAX_TIMELINE_BUCKETS = 24;

export function RealTimeProvider({ children }) {
  const { token } = useAuth();
  const socketRef = useRef(null);
  const [connected, setConnected] = useState(false);

  // ── Shared Real-Time State ──
  const [systemMetrics, setSystemMetrics] = useState(null);       // CPU, RAM, threat score
  const [attackFeed, setAttackFeed] = useState([]);               // Rolling live attack events
  const [timeline, setTimeline] = useState([]);                   // 24-bucket attack volume chart
  const [linkedDevices, setLinkedDevices] = useState([]);         // Real network adapters
  const [systemFindings, setSystemFindings] = useState([]);       // Security findings
  const [criticalAlert, setCriticalAlert] = useState(null);       // Latest critical alert
  const [blockedCount, setBlockedCount] = useState(0);            // Cumulative blocked counter
  const [attacksPerMinute, setAttacksPerMinute] = useState(0);    // Rolling APM
  const [liveAttackCount, setLiveAttackCount] = useState(0);      // Cumulative live attacks
  const [intelStatus, setIntelStatus] = useState(null);           // Live threat intel source info
  const [listeningPorts, setListeningPorts] = useState([]);        // Real open ports on this machine

  const [latencyMs, setLatencyMs] = useState(12);

  const [soundEnabled, setSoundEnabled] = useState(false);

  function playCyberAlertBeep() {
    if (!soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.005, ctx.currentTime + 0.15);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.16);
    } catch (e) {
      // Audio context may be restricted by autoplay policy
    }
  }

  const blockIp = useCallback((ip) => {
    if (socketRef.current) {
      socketRef.current.emit('attack:block_ip', { ip });
    }
    setAttackFeed(prev => prev.map(a => a.sourceIp === ip ? { ...a, blocked: true } : a));
    setBlockedCount(prev => prev + 1);
  }, []);

  const simulateAttackWave = useCallback((count = 3) => {
    if (socketRef.current) {
      socketRef.current.emit('attack:simulate', { count });
    }
  }, []);

  // Track attacks per minute using a sliding window
  const attackTimestamps = useRef([]);
  const updateApm = useCallback(() => {
    const now = Date.now();
    attackTimestamps.current = attackTimestamps.current.filter(t => now - t < 60000);
    setAttacksPerMinute(attackTimestamps.current.length);
  }, []);

  useEffect(() => {
    // Only connect when authenticated
    if (!token) return;

    let socket = null;
    let active = true;
    let pingInterval = null;

    const initSocket = async () => {
      let resolvedUrl = SOCKET_URL;

      // If we don't have a static VITE_SOCKET_URL, and VITE_API_URL is '/api' or empty (meaning we proxy),
      // we can try to fetch the server's public URL dynamically from /api/health.
      if (!import.meta.env.VITE_SOCKET_URL && 
          (!import.meta.env.VITE_API_URL || import.meta.env.VITE_API_URL === '/api')) {
        try {
          const response = await fetch('/api/health');
          if (response.ok && active) {
            const data = await response.json();
            if (data.websocketUrl) {
              resolvedUrl = data.websocketUrl;
              console.log('[WS] Discovered dynamic WebSocket URL:', resolvedUrl);
            }
          }
        } catch (err) {
          console.warn('[WS] Failed to fetch dynamic WebSocket URL, using fallback:', err);
        }
      }

      if (!active) return;

      socket = io(resolvedUrl, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
      });
      socketRef.current = socket;

      socket.on('connect', () => {
        setConnected(true);
        console.log('[WS] Connected to real-time engine');

        // Measure live round-trip latency every 3 seconds
        pingInterval = setInterval(() => {
          const start = Date.now();
          socket.emit('custom:ping', () => {
            const rtt = Date.now() - start;
            setLatencyMs(rtt);
          });
        }, 3000);
      });

      socket.on('disconnect', () => {
        setConnected(false);
        if (pingInterval) clearInterval(pingInterval);
        console.log('[WS] Disconnected — attempting reconnect...');
      });

      // ── REAL-TIME EVENTS ──

      // Initial attack history on connect
      socket.on('attack:history', (history) => {
        if (Array.isArray(history)) {
          setAttackFeed(history);
        }
      });

      // System metrics: CPU, RAM, threat score, network health, live counters — every 2s
      socket.on('system:metrics', (data) => {
        setSystemMetrics(data);
        if (data.liveAttackCount !== undefined) {
          setLiveAttackCount(data.liveAttackCount);
        }
        if (data.blockedToday !== undefined) {
          setBlockedCount(data.blockedToday);
        }
      });

      // New attack event
      socket.on('attack:event', (attack) => {
        attackTimestamps.current.push(Date.now());
        updateApm();
        if (attack.severity === 'CRITICAL') {
          playCyberAlertBeep();
        }
        setAttackFeed(prev => {
          const updated = [attack, ...prev.filter(a => a.id !== attack.id)].slice(0, MAX_FEED_EVENTS);
          return updated;
        });
        setLiveAttackCount(prev => prev + 1);
        if (attack.blocked) {
          setBlockedCount(prev => prev + 1);
        }
      });

      // IP blocked broadcast
      socket.on('attack:ip_blocked', ({ ip, blockedCount: newBlocked }) => {
        setAttackFeed(prev => prev.map(a => a.sourceIp === ip ? { ...a, blocked: true } : a));
        if (newBlocked !== undefined) {
          setBlockedCount(newBlocked);
        }
      });

      // Full timeline on initial connect
      socket.on('timeline:full', (data) => {
        setTimeline(data.slice(-MAX_TIMELINE_BUCKETS));
      });

      // Rolling timeline update — every 30s
      socket.on('timeline:update', ({ timeline: newTimeline }) => {
        setTimeline(newTimeline.slice(-MAX_TIMELINE_BUCKETS));
      });

      // Real network adapters — every 10s
      socket.on('linked:devices', (devices) => {
        setLinkedDevices(devices);
      });

      // Security findings from OS scan
      socket.on('system:findings', (findings) => {
        setSystemFindings(findings);
      });

      // Live threat intelligence status — emitted on connect
      socket.on('intel:status', (status) => {
        setIntelStatus(status);
        console.log('[WS] Threat intel source:', status.source, '| IOCs:', status.iocCount);
      });

      // Real listening ports on this machine
      socket.on('system:ports', ({ listeningPorts: ports, connectionCount }) => {
        if (Array.isArray(ports)) setListeningPorts(ports);
      });

      // Critical alert (threatScore >= 60 + high severity finding)
      socket.on('alert:critical', (alert) => {
        setCriticalAlert(alert);
        playCyberAlertBeep();
        // Auto-clear after 8 seconds
        setTimeout(() => setCriticalAlert(null), 8000);
      });
    };

    initSocket();

    return () => {
      active = false;
      if (pingInterval) clearInterval(pingInterval);
      if (socket) {
        socket.disconnect();
      }
      socketRef.current = null;
      setConnected(false);
    };
  }, [token, updateApm, soundEnabled]);

  // APM decay timer
  useEffect(() => {
    const interval = setInterval(updateApm, 5000);
    return () => clearInterval(interval);
  }, [updateApm]);

  const value = {
    connected,
    latencyMs,
    systemMetrics,
    attackFeed,
    timeline,
    linkedDevices,
    systemFindings,
    criticalAlert,
    blockedCount,
    attacksPerMinute,
    liveAttackCount,
    intelStatus,
    listeningPorts,
    soundEnabled,
    setSoundEnabled,
    blockIp,
    simulateAttackWave,
  };

  return (
    <RealTimeContext.Provider value={value}>
      {children}
    </RealTimeContext.Provider>
  );
}

export function useRealTime() {
  const ctx = useContext(RealTimeContext);
  if (!ctx) throw new Error('useRealTime must be used inside RealTimeProvider');
  return ctx;
}
