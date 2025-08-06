import re
import pandas as pd
from urllib.parse import unquote

class AdvancedSQLInjectionDetector:
    def __init__(self):
        # Common SQL injection patterns
        self.patterns = [
            # Union-based injections
            r"union\s+(all\s+)?select",
            r"select\s+.*\s+from",
            r"select\s+\*",
            
            # Boolean-based blind injections
            r"(and|or)\s+\d+\s*[=<>!]+\s*\d+",
            r"(and|or)\s+['\"]*[a-z]+['\"]*\s*[=<>!]+\s*['\"]*[a-z]+['\"]*",
            r"(and|or)\s+\d+\s*(and|or)\s+\d+",
            
            # Time-based blind injections
            r"(sleep|waitfor|delay)\s*\(\s*\d+\s*\)",
            r"benchmark\s*\(\s*\d+",
            r"pg_sleep\s*\(\s*\d+\s*\)",
            
            # Error-based injections
            r"(convert|cast|char)\s*\(",
            r"concat\s*\(",
            r"group_concat\s*\(",
            r"having\s+\d+\s*[=<>!]+\s*\d+",
            
            # Authentication bypass
            r"(admin|user|login)['\"]*\s*(=|like)\s*['\"]*\s*(or|and)",
            r"['\"]\s*(or|and)\s*['\"]*[^'\"]*['\"]*\s*(=|like)",
            r"['\"]\s*(or|and)\s*\d+\s*[=<>!]+\s*\d+",
            
            # SQL commands and functions
            r"(drop|delete|truncate|insert|update)\s+(table|from|into)",
            r"(exec|execute|sp_|xp_)\w*",
            r"(information_schema|sys\.|mysql\.|pg_)",
            r"(load_file|into\s+outfile|dumpfile)",
            
            # Comment patterns (SQL injection attempts often use comments)
            r"(--|#|\*\/|\*\*)",
            r"\/\*.*\*\/",
            
            # Special characters and encodings often used in SQLi
            r"(%27|%22|%2d%2d|%23)",  # URL encoded ', ", --, #
            r"(0x[0-9a-f]+)",          # Hex encoding
            r"(char\s*\(\s*\d+)",      # CHAR function
            
            # LDAP injection patterns
            r"(\*\)|(&\()|(\|\())",
            
            # XML injection
            r"(<script|<iframe|javascript:|vbscript:)",
            
            # Command injection
            r"(;|\|&|&&|\|\|).*(cat|ls|dir|type|echo|ping|nslookup|whoami)",
            
            # Path traversal that might be combined with SQLi
            r"(\.\./){2,}",
            
            # NoSQL injection patterns
            r"(\$ne|\$gt|\$lt|\$regex|\$where)",
        ]
        
        # Compile all patterns into a single regex
        self.sqli_regex = re.compile(
            '|'.join(f'({pattern})' for pattern in self.patterns),
            re.IGNORECASE | re.MULTILINE
        )
        
        # Keywords that are often legitimate in file paths
        self.whitelist_patterns = [
            r'^/[a-z]+mp3/',  # Music file paths
            r'^/blog/',       # Blog paths
            r'^/images/',     # Image paths
            r'^/css/',        # CSS paths
            r'^/js/',         # JavaScript paths
            r'^/api/v\d+/',   # API versioned paths
        ]
        
        self.whitelist_regex = re.compile(
            '|'.join(f'({pattern})' for pattern in self.whitelist_patterns),
            re.IGNORECASE
        )

    def decode_url(self, url):
        """Decode URL to catch encoded injection attempts"""
        try:
            return unquote(url)
        except:
            return url

    def is_suspicious_path(self, path):
        """Check if a path contains SQL injection patterns"""
        if pd.isna(path):
            return False
            
        # Decode URL first
        decoded_path = self.decode_url(path)
        
        # Check against whitelist first (reduce false positives)
        if self.whitelist_regex.search(path):
            # Even whitelisted paths can have injections, but be more strict
            # Look for obvious SQL injection patterns only
            obvious_patterns = [
                r"union\s+select",
                r"(and|or)\s+\d+\s*=\s*\d+",
                r"['\"]\s*or\s*['\"]*\d",
                r"drop\s+table",
                r"script\s*:",
                r"javascript\s*:",
            ]
            obvious_regex = re.compile('|'.join(obvious_patterns), re.IGNORECASE)
            return bool(obvious_regex.search(decoded_path))
        
        # For non-whitelisted paths, use full detection
        return bool(self.sqli_regex.search(decoded_path))

    def get_matched_patterns(self, path):
        """Return which specific patterns matched for analysis"""
        if pd.isna(path):
            return []
            
        decoded_path = self.decode_url(path)
        matches = []
        
        for i, pattern in enumerate(self.patterns):
            if re.search(pattern, decoded_path, re.IGNORECASE):
                matches.append(f"Pattern_{i+1}: {pattern}")
        
        return matches

def detect_sql_injection(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enhanced SQL injection detection function
    Compatible with your existing setup
    """
    if 'path' not in df.columns:
        return pd.DataFrame()  # No path column? Nothing to scan.
    
    detector = AdvancedSQLInjectionDetector()
    
    # Apply the detection function
    suspicious_mask = df['path'].apply(detector.is_suspicious_path)
    filtered = df[suspicious_mask]
    
    # Add a column showing which patterns matched (for debugging)
    if not filtered.empty:
        filtered = filtered.copy()
        filtered['matched_patterns'] = filtered['path'].apply(detector.get_matched_patterns)
    
    # Return the same columns as your original function
    required_columns = ["ip", "timestamp", "method", "path", "status", "user_agent"]
    available_columns = [col for col in required_columns if col in filtered.columns]
    
    if not filtered.empty and 'matched_patterns' in filtered.columns:
        available_columns.append('matched_patterns')
    
    return filtered[available_columns] if not filtered.empty else pd.DataFrame()
