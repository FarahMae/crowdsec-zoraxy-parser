# crowdsec-zoraxy-parser
### 🧪 CrowdSec Parser Test for Zoraxy Logs

---

## 🛠️ Setup Steps & Full Outputs

### 📁 Clone and Prepare Testing Environment
```bash
cd ~
git clone https://github.com/crowdsecurity/hub.git
cd hub
```

### 🔧 Create the Test Suite
```bash
sudo cscli hubtest create zoraxy-logs --type syslog
```
**Output:**
```
Test name                   :  zoraxy-logs
Test path                   :  /home/kali/hub/.tests/zoraxy-logs
Log file                    :  /home/kali/hub/.tests/zoraxy-logs/zoraxy-logs.log
Parser assertion file       :  /home/kali/hub/.tests/zoraxy-logs/parser.assert
Scenario assertion file     :  /home/kali/hub/.tests/zoraxy-logs/scenario.assert
Configuration File          :  /home/kali/hub/.tests/zoraxy-logs/config.yaml
```

### ✍️ Create the Parser
```bash
sudo mkdir -p parsers/s00-raw/custom
sudo nano parsers/s00-raw/custom/zoraxy-logs.yaml
```
**Content:**
```yaml
filter: "evt.Line.Raw contains \"HTTP\""
onsuccess: next_stage
name: custom/zoraxy-logs
description: Parse Zoraxy reverse proxy access logs
debug: false
nodes:
  - grok:
      pattern: "%{IPORHOST:remote_addr} - - \[%{HTTPDATE:timestamp}\] \"%{WORD:http_verb} %{URIPATHPARAM:http_path} HTTP/%{NUMBER:http_version}\" %{NUMBER:http_status} %{NUMBER:body_bytes_sent} \"-\" \"%{DATA:http_user_agent}\""
      apply_on: Line.Raw
statics:
  - meta: log_type
    value: zoraxy
  - target: evt.StrTime
    expression: evt.Parsed.timestamp
```

### 🧪 Sample Log Entry
```bash
sudo nano .tests/zoraxy-logs/zoraxy-logs.log
```
**Content:**
```
192.168.1.10 - - [18/Apr/2024:10:32:01 +0000] "GET /dashboard HTTP/1.1" 200 154 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### 🧪 Assertion File
```bash
sudo nano .tests/zoraxy-logs/parser.assert
```
**Content:**
```python
len(results) == 3
len(results["s00-raw"]["crowdsecurity/non-syslog"]) == 1
results["s00-raw"]["crowdsecurity/non-syslog"][0].Success == false
len(results["s00-raw"]["crowdsecurity/syslog-logs"]) == 1
results["s00-raw"]["crowdsecurity/syslog-logs"][0].Success == false
len(results["s00-raw"]["custom/zoraxy-logs"]) == 1
results["s00-raw"]["custom/zoraxy-logs"][0].Success == true
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["body_bytes_sent"] == "154"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["http_path"] == "/dashboard"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["http_status"] == "200"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["http_user_agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["http_verb"] == "GET"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["http_version"] == "1.1"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["remote_addr"] == "192.168.1.10"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Parsed["timestamp"] == "18/Apr/2024:10:32:01 +0000"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Meta["log_type"] == "zoraxy"
results["s00-raw"]["custom/zoraxy-logs"][0].Evt.Whitelisted == false
len(results["s02-enrich"]["crowdsecurity/dateparse-enrich"]) == 1
results["s02-enrich"]["crowdsecurity/dateparse-enrich"][0].Success == true
len(results["success"]) == 0
```

### ✅ Run the Test
```bash
sudo cscli hubtest run zoraxy-logs
```
**Output:**
```
Running test 'zoraxy-logs'
All tests passed, use --report-success for more details.
```

---

## 🚀 Deploy to Live Setup

```bash
sudo mkdir -p /etc/crowdsec/parsers/s00-raw/custom/
sudo cp parsers/s00-raw/custom/zoraxy-logs.yaml /etc/crowdsec/parsers/s00-raw/custom/
sudo systemctl restart crowdsec
```

### 🔍 Verify
```bash
sudo cscli parsers list | grep zoraxy
```
**Expected Output:**
```
custom/zoraxy-logs              🏠  enabled,local  /etc/crowdsec/parsers/s00-raw/custom/zoraxy-logs.yaml
```

### 📄 acquis.yaml
```bash
sudo nano /etc/crowdsec/acquis.yaml
```
**Add:**
```yaml
filenames:
  - /var/log/zoraxy/access.log
labels:
  type: zoraxy
```
```bash
sudo systemctl restart crowdsec
```

---

## 🔐 Brute-force Scenario Simulation

### 📁 Prepare Log File
```bash
sudo mkdir -p /var/log/zoraxy
sudo touch /var/log/zoraxy/access.log
sudo chmod 644 /var/log/zoraxy/access.log
```

### 🔁 Simulate Login Failures (Multiple Entries)
```bash
for i in {1..10}; do
  current_time=$(date +"%d/%b/%Y:%H:%M:%S +0000")
  echo "192.168.1.21 - - [$current_time] \"POST /dashboard/login HTTP/1.1\" 401 154 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"" | sudo tee -a /var/log/zoraxy/access.log
  sleep 2
done
```

### 📄 Sample Output:
```
192.168.1.21 - - [20/Apr/2025:18:45:34 +0000] ...
...
192.168.1.21 - - [20/Apr/2025:18:45:53 +0000] ...
```

### 🔍 Check for Alerts
```bash
sudo cscli alerts list
```
**Output:**
```
No active alerts
```

