# Reddit Post Draft (r/homeassistant)

**Title:** [Showcase] Project Sentinel: Automated Home Network Vulnerability Scanning & Asset Management

**Body:**

Hey r/homeassistant!

I've been working on a new project called **Project Sentinel**, and I'm looking for some feedback and feature suggestions from the community.

**What is it?**
Project Sentinel is a local network governance tool designed to bridge the gap between simple device tracking and enterprise-grade risk management. It scans your network, identifies what's running on your devices, and checks them against the **National Vulnerability Database (NVD)** to let you know if you have any unpatched security risks.

It runs as a Home Assistant **Add-on** (the scanner) + **Integration** (the sensors/dashboard).

**Key Features:**
*   **Automated Discovery**: Maps devices on your network using `nmap` and regex banner grabbing to identify specific software versions (e.g., realizing that "Unknown Device" is actually running an old version of Dropbear SSH).
*   **Vulnerability Mapping**: Automatically cross-references your devices against real-time CVE data.
*   **"Hybrid" Analysis Engine**: (Optional) Uses a local regex engine first, but can fall back to an LLM (like OpenAI/Gemini/Ollama) to "read" complex CVE descriptions and determine if they actually apply to your specific device setup (reducing false positives).
*   **Local First**: All scanning logic happens on your network. The optional LLM features can even be run strictly locally using Ollama.

**Why I built it:**
I wanted a way to know if my IoT devices (cameras, smart plugs, routers) had known critical vulnerabilities without manually checking firmware revisions every week.

**Looking for feedback:**
I'd love to hear what features would make this more useful for your setups.
*   Would you use automated notifications for critical CVEs?
*   Do you care about tracking device history?
*   Any specific integrations (e.g., Unifi, router-specific) that would help with discovery?

Repo: https://github.com/jgrippe1/project_sentinel_dev

Thanks!
