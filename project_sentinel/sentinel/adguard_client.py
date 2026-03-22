"""AdGuard Client — Optional integration to query AdGuard Home DNS logs for device fingerprinting."""
import logging
import os
import requests
from collections import Counter
from urllib.parse import urlparse

logger = logging.getLogger("AdGuardClient")


# Domain patterns that indicate a specific platform or device type.
# Each entry maps a substring match to a (platform, device_type) tuple.
DOMAIN_FINGERPRINTS = {
    # Apple ecosystem
    "apple.com": ("Apple", None),
    "icloud.com": ("Apple", None),
    "mzstatic.com": ("Apple", None),
    "apple-dns.net": ("Apple", None),
    # Google / Chromecast
    "_googlecast._tcp": ("Google", "Media"),
    "clients3.google.com": ("Google", None),
    "connectivitycheck.gstatic.com": ("Google", None),
    "android.googleapis.com": ("Google", "Mobile"),
    # Amazon / Alexa / Echo
    "amazonalexa.com": ("Amazon", "Voice"),
    "device-metrics-us.amazon.com": ("Amazon", None),
    "arcus-uswest.amazon.com": ("Amazon", "Camera"),
    "unagi-na.amazon.com": ("Amazon", "Voice"),
    "kindle-time.amazon.com": ("Amazon", None),
    # Sonos
    "sonos.com": ("Sonos", "Media"),
    "ws.sonos.com": ("Sonos", "Media"),
    # Samsung SmartThings / TV
    "samsungcloudsolution.com": ("Samsung", "Media"),
    "samsungcloudsolution.net": ("Samsung", "Media"),
    "smartthings.com": ("Samsung", "IoT"),
    # Roku
    "roku.com": ("Roku", "Media"),
    # LG TV
    "lgtvsdp.com": ("LG", "Media"),
    "lgsmartad.com": ("LG", "Media"),
    # Shelly
    "shelly.cloud": ("Shelly", "IoT"),
    # Home Assistant
    "home-assistant.io": ("Home Assistant", "Server"),
    # Tuya / Smart Life
    "tuya.com": ("Tuya", "IoT"),
    "tuyaus.com": ("Tuya", "IoT"),
    # Ring
    "ring.com": ("Ring", "Camera"),
    # Nest / Google Home
    "nest.com": ("Google Nest", "Climate"),
    # Philips Hue
    "meethue.com": ("Philips Hue", "Light"),
    # TP-Link / Kasa
    "tplinkcloud.com": ("TP-Link", "IoT"),
    # Wyze
    "wyze.com": ("Wyze", "Camera"),
    # Printer indicators
    "print": (None, "Printer"),
    "cups": (None, "Printer"),
    # NTP (common for embedded IoT)
    "ntp.org": (None, "IoT"),
    "pool.ntp.org": (None, "IoT"),
}

# Domains to filter out (noise — ad trackers, CDNs, analytics, etc.)
NOISE_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "cloudflare.com", "cloudflare-dns.com",
    "akamaiedge.net", "akadns.net", "akamai.net",
    "amazonaws.com", "cloudfront.net",
    "google-analytics.com", "googletagmanager.com",
    "crashlytics.com", "app-measurement.com",
    "gstatic.com", "googleapis.com",
    "mozilla.org", "mozilla.com", "mozilla.net",
}


class AdGuardClient:
    """
    Client for the AdGuard Home REST API.

    Supports two connection modes:
    1. Direct: Provide a full URL (e.g., "http://192.168.1.1:3000") with optional basic auth.
    2. HA Add-on: Provide just the add-on slug (e.g., "a0d7b954_adguard").
       The client auto-discovers the add-on's internal IP via the HA Supervisor API.
    """

    def __init__(self, host, username="", password=""):
        """
        Initialize the AdGuard Home client.

        Args:
            host: Full URL (direct mode) OR add-on slug (HA add-on mode).
            username: AdGuard Home login username (direct mode only).
            password: AdGuard Home login password (direct mode only).
        """
        self.session = requests.Session()
        self.host = ""
        self.mode = None  # "direct" or "ha_addon"

        if not host:
            logger.warning("AdGuard: No host or slug provided.")
            return

        host = host.strip()

        # Detect mode: if it starts with http, it's a direct URL; otherwise treat as HA slug
        if host.startswith("http://") or host.startswith("https://"):
            self._init_direct(host, username, password)
        else:
            self._init_ha_addon(host)

    def _init_direct(self, host, username, password):
        """Initialize in direct connection mode with optional basic auth."""
        self.host = host.rstrip("/")
        self.mode = "direct"
        if username:
            self.session.auth = (username, password or "")

        # Validate URL scheme
        parsed = urlparse(self.host)
        if parsed.scheme not in ("http", "https"):
            logger.error(f"AdGuard: Invalid URL scheme: {self.host}")
            self.host = ""
            return

        logger.info(f"AdGuardClient (direct): {self.host} (auth={'yes' if username else 'no'})")

    def _init_ha_addon(self, slug):
        """
        Initialize in HA add-on mode by discovering internal IP via Supervisor API.

        The Supervisor API returns the add-on container's IP on the hassio network,
        which is reachable from host_network add-ons like Sentinel.
        """
        self.mode = "ha_addon"
        token = os.environ.get("SUPERVISOR_TOKEN")
        if not token:
            logger.error("AdGuard: HA add-on mode requires SUPERVISOR_TOKEN (not running inside HA?).")
            return

        try:
            # Query the Supervisor for the add-on's internal network info
            url = f"http://supervisor/addons/{slug}/info"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            info = response.json().get("data", {})
            addon_ip = info.get("ip_address")
            state = info.get("state", "unknown")

            if state != "started":
                logger.error(f"AdGuard: Add-on '{slug}' is not running (state: {state}).")
                return

            if not addon_ip:
                logger.error(f"AdGuard: Add-on '{slug}' has no IP address assigned.")
                return

            # AdGuard Home default web/API port inside the container is 3000
            self.host = f"http://{addon_ip}:3000"
            logger.info(f"AdGuardClient (HA add-on): Discovered {slug} at {self.host}")

        except requests.exceptions.ConnectionError:
            logger.error(f"AdGuard: Cannot reach Supervisor API to discover add-on '{slug}'.")
        except Exception as e:
            logger.error(f"AdGuard: Failed to discover HA add-on '{slug}': {e}")

    def get_query_log(self, client_ip, limit=500):
        """
        Fetch DNS query log entries for a specific client IP.

        Args:
            client_ip: The IP address to filter logs for.
            limit: Max number of log entries to retrieve (default 500).

        Returns:
            list[dict]: List of query log entries, or empty list on error.
        """
        if not self.host:
            logger.warning("AdGuard: Client not initialized (no host resolved).")
            return []

        url = f"{self.host}/control/querylog"
        params = {
            "search": client_ip,
            "limit": limit,
            "response_status": "all",
        }

        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            entries = data.get("data", [])
            logger.info(f"AdGuard: Retrieved {len(entries)} DNS log entries for {client_ip}")
            return entries
        except requests.exceptions.ConnectionError:
            logger.error(f"AdGuard: Cannot connect to {self.host}")
            return []
        except requests.exceptions.Timeout:
            logger.error(f"AdGuard: Request timed out for {client_ip}")
            return []
        except Exception as e:
            logger.error(f"AdGuard: Error fetching query log: {e}")
            return []

    def test_connection(self):
        """
        Test connectivity to AdGuard Home by querying its status endpoint.

        Returns:
            dict: {"connected": bool, "version": str|None, "mode": str}
        """
        result = {"connected": False, "version": None, "mode": self.mode or "unconfigured"}

        if not self.host:
            return result

        try:
            response = self.session.get(f"{self.host}/control/status", timeout=5)
            if response.status_code == 200:
                data = response.json()
                result["connected"] = True
                result["version"] = data.get("version", "unknown")
                logger.info(f"AdGuard: Connection OK (v{result['version']})")
            else:
                logger.warning(f"AdGuard: Status check returned {response.status_code}")
        except requests.exceptions.ConnectionError:
            logger.error(f"AdGuard: Cannot connect to {self.host}")
        except Exception as e:
            logger.error(f"AdGuard: Health check failed: {e}")

        return result

    def get_dns_fingerprint(self, client_ip, limit=500):
        """
        Analyze DNS query log for a client IP to extract a device fingerprint.

        Returns a structured summary of:
        - Top queried domains (noise-filtered, sorted by frequency)
        - Platform indicators (e.g., Apple, Google, Sonos)
        - Suggested device type based on domain patterns

        Args:
            client_ip: The IP address to investigate.
            limit: Max log entries to analyze.

        Returns:
            dict: Fingerprint analysis results.
        """
        entries = self.get_query_log(client_ip, limit=limit)

        if not entries:
            return {
                "domains": [],
                "indicators": {},
                "suggested_type": None,
                "suggested_vendor": None,
                "total_queries": 0,
                "unique_domains": 0,
                "status": "no_data",
            }

        # Extract queried domain names
        domain_counter = Counter()
        all_domains = []

        for entry in entries:
            question = entry.get("question", {})
            domain = question.get("name", "").rstrip(".")
            if domain:
                all_domains.append(domain)
                domain_counter[domain] += 1

        # Filter out noise domains
        filtered_domains = {}
        for domain, count in domain_counter.items():
            domain_lower = domain.lower()
            is_noise = any(noise in domain_lower for noise in NOISE_DOMAINS)
            if not is_noise:
                filtered_domains[domain] = count

        # Sort by frequency
        top_domains = sorted(filtered_domains.items(), key=lambda x: x[1], reverse=True)

        # Fingerprint matching
        platform_votes = Counter()
        type_votes = Counter()

        for domain, count in top_domains:
            domain_lower = domain.lower()
            for pattern, (platform, dev_type) in DOMAIN_FINGERPRINTS.items():
                if pattern in domain_lower:
                    if platform:
                        platform_votes[platform] += count
                    if dev_type:
                        type_votes[dev_type] += count

        # Determine best guesses
        suggested_vendor = platform_votes.most_common(1)[0][0] if platform_votes else None
        suggested_type = type_votes.most_common(1)[0][0] if type_votes else None

        # Build indicators summary
        indicators = {}
        if platform_votes:
            indicators["platforms"] = dict(platform_votes.most_common(5))
        if type_votes:
            indicators["device_types"] = dict(type_votes.most_common(3))

        return {
            "domains": [{"domain": d, "count": c} for d, c in top_domains[:30]],
            "indicators": indicators,
            "suggested_type": suggested_type,
            "suggested_vendor": suggested_vendor,
            "total_queries": len(all_domains),
            "unique_domains": len(set(all_domains)),
            "status": "ok",
        }
