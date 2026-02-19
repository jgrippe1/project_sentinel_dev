# Project Sentinel User Guide

## 📚 Table of Contents
1. [Overview](#overview)
2. [Advanced Configuration](#advanced-configuration)
3. [Hybrid CVE Analysis (LLM)](#hybrid-cve-analysis-llm)
4. [Troubleshooting](#troubleshooting)
5. [FAQ](#faq)

---

## 🔍 Overview
Project Sentinel bridges the gap between home network scanning and enterprise-grade risk management. It runs as a background service (Add-on) to scan your network, identify devices, and correlate them against the National Vulnerability Database (NVD).

---

## ⚙️ Advanced Configuration

Configuration is primarily handled via the Add-on "Configuration" tab in Home Assistant.

| Option | Description | Default |
| :--- | :--- | :--- |
| `subnets` | List of CIDR ranges to scan (e.g., `192.168.1.0/24`). | `[]` |
| `scan_interval` | Interval between scans in minutes. | `15` |
| `scan_threads` | Number of concurrent threads for scanning. | `20` |
| `nvd_api_key` | (Optional) Your NVD API Key for faster rate limits. | `""` |
| `verbose_logging` | Enable detailed debug logging (True/False). | `false` |

### Database Location
The database is stored at `/share/sentinel.db`. This allows both the Add-on (Scanner) and the Integration (Sensor) to access the same data. 
> [!IMPORTANT]
> Do not delete this file unless you want to reset your entire inventory history.

---

## 🤖 Hybrid CVE Analysis (LLM)

Project Sentinel uses a "Hybrid" approach to determine if a vulnerability impacts your specific device.
1. **Regex**: Fast, local pattern matching.
2. **LLM**: If Regex is unsure (<80% confidence), it asks an AI model to read the CVE description.

### Supported Providers

#### 1. OpenAI (Default)
```yaml
llm_enabled: true
llm_provider: "openai"
llm_api_key: "sk-..."
llm_model: "gpt-3.5-turbo"
```

#### 2. Google Gemini
Highly recommended for cost-efficiency.
```yaml
llm_enabled: true
llm_provider: "google"
llm_api_key: "AIzaSy..."
llm_model: "gemini-1.5-flash"
```

#### 3. Anthropic (Claude)
```yaml
llm_enabled: true
llm_provider: "anthropic"
llm_api_key: "sk-ant-..."
llm_model: "claude-3-haiku-20240307"
```

#### 4. Ollama (Local)
Run a local LLM server to keep data completely private.
```yaml
llm_enabled: true
llm_provider: "ollama"
llm_base_url: "http://homeassistant.local:11434/v1"
llm_model: "llama3"
```

---

## 🔧 Troubleshooting

### "Database is locked"
Since SQLite is file-based, if the Scanner is writing heavily while the Sensor tries to read, you might see this error. 
* **Fix**: The integration automatically retries. If it persists, restart the Add-on.

### "Rate Limit Exceeded" (403/429)
NVD imposes strict rate limits.
* **Fix**: Request an [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) and add it to your configuration. This increases your limit from ~5 requests/min to ~50 requests/min.

### "ReadTimeout" or LLM Errors
* **Fix**: Ensure your `llm_base_url` is reachable from within the Home Assistant container. For Docker/Add-ons, `localhost` refers to the container itself, not the host. Use `http://homeassistant.local:port` or the actual IP address.

---

## ❓ FAQ

**Q: Does this scan outside my network?**
A: No. It only scans the local subnets you define.

**Q: Is it safe to scan IoT devices?**
A: Yes. Sentinel uses non-intrusive service discovery requests (N-map service validation), similar to how your phone discovers a Chromecast. It does not exploit vulnerabilities.
