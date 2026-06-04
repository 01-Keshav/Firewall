// Network packet simulation engine for Custom Firewall Demo

export const DEFAULT_RULES = [
  {
    id: "rule_1",
    name: "Allow Ping (ICMP) from anywhere",
    protocol: "ICMP",
    srcIp: "*",
    dstIp: "10.0.0.5",
    dstPort: "*",
    action: "ALLOW",
    active: true
  },
  {
    id: "rule_2",
    name: "Block SSH from Malicious Range",
    protocol: "TCP",
    srcIp: "198.51.100.0/24",
    dstIp: "10.0.0.5",
    dstPort: "22",
    action: "DENY",
    active: true
  },
  {
    id: "rule_3",
    name: "Block SSDP DDoS Vector",
    protocol: "UDP",
    srcIp: "*",
    dstIp: "*",
    dstPort: "1900",
    action: "DENY",
    active: true
  },
  {
    id: "rule_4",
    name: "Allow HTTP/HTTPS Web Traffic",
    protocol: "TCP",
    srcIp: "*",
    dstIp: "10.0.0.10",
    dstPort: "443",
    action: "ALLOW",
    active: true
  },
  {
    id: "rule_5",
    name: "Allow HTTP Web Traffic (Alt)",
    protocol: "TCP",
    srcIp: "*",
    dstIp: "10.0.0.10",
    dstPort: "80",
    action: "ALLOW",
    active: true
  },
  {
    id: "rule_6",
    name: "Block Database Port from External WAN",
    protocol: "TCP",
    srcIp: "203.0.113.0/24",
    dstIp: "10.0.0.20",
    dstPort: "5432",
    action: "DENY",
    active: true
  }
];

// Helper to check if IP matches rule pattern
export function ipMatches(ip, pattern) {
  if (!pattern || pattern === "*" || pattern === "any" || pattern === "") return true;
  
  if (pattern.includes("/")) {
    const [subnet, mask] = pattern.split("/");
    const maskBits = parseInt(mask, 10);
    
    // Simple helper matching for common CIDR block simulations
    if (maskBits === 24) {
      const ipParts = ip.split(".");
      const subParts = subnet.split(".");
      return ipParts[0] === subParts[0] && ipParts[1] === subParts[1] && ipParts[2] === subParts[2];
    }
    if (maskBits === 16) {
      const ipParts = ip.split(".");
      const subParts = subnet.split(".");
      return ipParts[0] === subParts[0] && ipParts[1] === subParts[1];
    }
    if (maskBits === 8) {
      return ip.split(".")[0] === subnet.split(".")[0];
    }
    return ip === subnet;
  }
  
  return ip === pattern;
}

// Evaluate a packet against the active firewall rules
export function evaluatePacket(packet, rules) {
  // Check rules in order
  for (const rule of rules) {
    if (!rule.active) continue;

    // Match Protocol
    const protoMatch = rule.protocol === "ANY" || rule.protocol === packet.protocol;
    if (!protoMatch) continue;

    // Match Src IP
    const srcIpMatch = ipMatches(packet.srcIp, rule.srcIp);
    if (!srcIpMatch) continue;

    // Match Dst IP
    const dstIpMatch = ipMatches(packet.dstIp, rule.dstIp);
    if (!dstIpMatch) continue;

    // Match Dst Port
    const dstPortMatch = rule.dstPort === "*" || rule.dstPort === "" || String(rule.dstPort) === String(packet.dstPort);
    if (!dstPortMatch) continue;

    // First match wins
    return {
      action: rule.action,
      matchedRuleId: rule.id,
      matchedRuleName: rule.name
    };
  }

  // Default Deny Rule if no rule matched
  return {
    action: "DENY",
    matchedRuleId: "default_deny",
    matchedRuleName: "Default Drop Rule"
  };
}

const COMMON_THREATS = [
  { payload: "SELECT * FROM users WHERE admin = '1' -- SQLi", signature: "SQL Injection Attack", category: "exploit" },
  { payload: "<script>alert(document.cookie)</script> - XSS", signature: "Cross-Site Scripting (XSS)", category: "exploit" },
  { payload: "../../../../etc/passwd - Directory Traversal", signature: "Directory Traversal", category: "exploit" },
  { payload: "SSH brute-force attempt, password try #14", signature: "Brute Force Attack", category: "brute_force" },
  { payload: "SSDP Search Request (SSDP amplification reflection)", signature: "SSDP Flood DDoS Vector", category: "ddos" }
];

const MALICIOUS_IPS = [
  "198.51.100.45",
  "198.51.100.99",
  "203.0.113.12",
  "203.0.113.254",
  "185.220.101.4", // Tor Exit Nodes
  "45.227.254.12",
  "89.248.165.71"
];

const SAFE_IPS = [
  "192.168.1.15",
  "192.168.1.100",
  "12.130.45.10",
  "8.8.8.8",
  "1.1.1.1",
  "64.233.160.0",
  "10.0.0.2"
];

const DESTINATIONS = [
  { ip: "10.0.0.5", label: "SSH / Jump Server" },
  { ip: "10.0.0.10", label: "Web Portal" },
  { ip: "10.0.0.20", label: "Production database" }
];

// Generate a random network packet
export function generateRandomPacket(forceThreat = false) {
  const isThreat = forceThreat || Math.random() < 0.25;
  const protocol = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"][Math.floor(Math.random() * 6)];
  
  let srcIp;
  if (isThreat) {
    srcIp = MALICIOUS_IPS[Math.floor(Math.random() * MALICIOUS_IPS.length)];
  } else {
    srcIp = SAFE_IPS[Math.floor(Math.random() * SAFE_IPS.length)];
  }

  const destObj = DESTINATIONS[Math.floor(Math.random() * DESTINATIONS.length)];
  const dstIp = destObj.ip;

  let dstPort;
  let payload = "";
  let threatSignature = null;
  let threatCategory = null;

  if (protocol === "ICMP") {
    dstPort = "*";
    payload = "Echo Request (ping)";
  } else if (protocol === "UDP") {
    // 50% chance of SSDP, 50% random high port
    if (Math.random() < 0.5) {
      dstPort = 1900;
      payload = "SSDP Discovery Query";
      if (isThreat) {
        payload = "SSDP Search Request (SSDP amplification reflection)";
        threatSignature = "SSDP Flood DDoS Vector";
        threatCategory = "ddos";
      }
    } else {
      dstPort = [53, 123, 161][Math.floor(Math.random() * 3)];
      payload = dstPort === 53 ? "DNS Query" : dstPort === 123 ? "NTP Time Sync" : "SNMP Query";
    }
  } else { // TCP
    // Ports: 80, 443, 22, 5432
    if (dstIp === "10.0.0.5") {
      dstPort = 22; // SSH
      payload = "SSH connection request";
      if (isThreat) {
        const threat = COMMON_THREATS[3]; // SSH brute force
        payload = threat.payload;
        threatSignature = threat.signature;
        threatCategory = threat.category;
      }
    } else if (dstIp === "10.0.0.20") {
      dstPort = 5432; // Database
      payload = "SQL client connect request";
      if (isThreat) {
        const threat = COMMON_THREATS[0]; // SQLi
        payload = threat.payload;
        threatSignature = threat.signature;
        threatCategory = threat.category;
      }
    } else { // Web Portal 10.0.0.10
      dstPort = Math.random() < 0.3 ? 80 : 443;
      payload = `GET /index.html HTTP/1.1\r\nHost: portal.internal`;
      if (isThreat) {
        // SQLi, XSS, or Traversal
        const threat = COMMON_THREATS[Math.floor(Math.random() * 3)];
        payload = threat.payload;
        threatSignature = threat.signature;
        threatCategory = threat.category;
      }
    }
  }

  const srcPort = Math.floor(Math.random() * 64511) + 1024;
  const size = Math.floor(Math.random() * 1400) + 64;

  return {
    id: `pkt_${Math.random().toString(36).substring(2, 9)}`,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    protocol,
    payload,
    size,
    isThreat: threatSignature !== null,
    threatSignature,
    threatCategory,
    timestamp: new Date().toISOString()
  };
}

// Generate the final SIEM log format for a processed packet
export function createSiemLog(packet, evaluation) {
  let severity = "low";
  
  if (evaluation.action === "DENY") {
    if (packet.isThreat) {
      severity = "critical";
    } else if (packet.dstPort === 22 || packet.dstPort === 5432) {
      severity = "high";
    } else {
      severity = "medium";
    }
  } else {
    // Traffic allowed, but if threat is bypassed (bad rules!)
    if (packet.isThreat) {
      severity = "critical"; // VERY critical - alert that threat bypass happened!
    } else {
      severity = "low";
    }
  }

  return {
    id: `log_${Math.random().toString(36).substring(2, 9)}`,
    timestamp: packet.timestamp,
    event_type: "firewall_filter",
    src_ip: packet.srcIp,
    src_port: packet.srcPort,
    dest_ip: packet.dstIp,
    dest_port: packet.dstPort,
    protocol: packet.protocol,
    action: evaluation.action,
    rule_id: evaluation.matchedRuleId,
    rule_name: evaluation.matchedRuleName,
    payload: packet.payload,
    packet_size: packet.size,
    threat_detected: packet.isThreat,
    threat_signature: packet.threatSignature,
    threat_category: packet.threatCategory,
    severity
  };
}
