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
                   (import.meta.env.VITE_API_URL ? import.meta.env.VITE_API_URL.replace(/\/api$/, '') : '') || 
                   (import.meta.env.DEV ? 'http://localhost:5000' : window.location.origin);
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

    const socket = io(SOCKET_URL, {
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
    });

    socket.on('disconnect', () => {
      setConnected(false);
      console.log('[WS] Disconnected — attempting reconnect...');
    });

    // ── REAL-TIME EVENTS ──

    // System metrics: CPU, RAM, threat score, network health — every 2s
    socket.on('system:metrics', (data) => {
      setSystemMetrics(data);
      if (data.liveAttackCount !== undefined) {
        setLiveAttackCount(data.liveAttackCount);
      }
    });

    // New attack event — every 3–7s
    socket.on('attack:event', (attack) => {
      attackTimestamps.current.push(Date.now());
      updateApm();
      setAttackFeed(prev => {
        const updated = [attack, ...prev].slice(0, MAX_FEED_EVENTS);
        return updated;
      });
      setLiveAttackCount(prev => prev + 1);
      if (attack.blocked) {
        setBlockedCount(prev => prev + 1);
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

    // Critical alert (threatScore >= 60 + high severity finding)
    socket.on('alert:critical', (alert) => {
      setCriticalAlert(alert);
      // Auto-clear after 8 seconds
      setTimeout(() => setCriticalAlert(null), 8000);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
      setConnected(false);
    };
  }, [token, updateApm]);

  // APM decay timer
  useEffect(() => {
    const interval = setInterval(updateApm, 5000);
    return () => clearInterval(interval);
  }, [updateApm]);

  const value = {
    connected,
    systemMetrics,
    attackFeed,
    timeline,
    linkedDevices,
    systemFindings,
    criticalAlert,
    blockedCount,
    attacksPerMinute,
    liveAttackCount,
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
