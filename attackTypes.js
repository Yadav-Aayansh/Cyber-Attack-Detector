const ATTACK_TYPES = [
    {
      name: "SQL Injection",
      description: "Attempts to inject malicious SQL code into database queries",
      severity: "high",
      color: "#DC2626",
      endpoint: "sql-injection"
    },
    {
      name: "Path Traversal",
      description: "Attempts to access files outside the web root directory",
      severity: "high",
      color: "#EA580C",
      endpoint: "path-traversal"
    },
    {
      name: "Bot Detection",
      description: "Automated bot and crawler activity detection",
      severity: "medium",
      color: "#CA8A04",
      endpoint: "bots"
    },
    {
      name: "LFI/RFI Attacks",
      description: "Local and Remote File Inclusion attack attempts",
      severity: "high",
      color: "#DC2626",
      endpoint: "lfi-rfi"
    },
    {
      name: "WordPress Probes",
      description: "WordPress-specific vulnerability scanning attempts",
      severity: "medium",
      color: "#7C3AED",
      endpoint: "wp-probe"
    },
    {
      name: "Brute Force",
      description: "Password brute force and credential stuffing attacks",
      severity: "high",
      color: "#B91C1C",
      endpoint: "brute-force"
    },
    {
      name: "HTTP Errors",
      description: "Suspicious HTTP error patterns and responses",
      severity: "low",
      color: "#059669",
      endpoint: "errors"
    },
    {
      name: "Internal IP Access",
      description: "Unauthorized access attempts to internal IP ranges",
      severity: "medium",
      color: "#0284C7",
      endpoint: "internal-ip"
    }
  ];
  
  export default ATTACK_TYPES;