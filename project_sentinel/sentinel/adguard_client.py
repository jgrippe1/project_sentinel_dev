"""AdGuard Client — Optional integration to query AdGuard Home DNS logs for device fingerprinting."""
import logging
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

    Uses HTTP Basic Authentication to query the DNS query log.
    Only initialized when adguard_host is configured — fully optional.
    """

    def __init__(self, host, username="", password=""):
        """
        Initialize the AdGuard Home client.

        Args:
            host: Full URL to AdGuard Home (e.g., "http://192.168.50.226:3000").
            username: AdGuard Home login username.
            password: AdGuard Home login password.
        """
        # Normalize: strip trailing slash
        self.host = host.rstrip("/") if host else ""
        self.username = username or ""
        self.password = password or ""
        self.session = requests.Session()
        if self.username:
            self.session.auth = (self.username, self.password)

        # Validate host URL
        parsed = urlparse(self.host)
        if parsed.scheme not in ("http", "https"):
            logger.error(f"AdGuard host URL has invalid scheme: {self.host}")
            self.host = ""

        logger.info(f"AdGuardClient initialized: {self.host} (auth={'yes' if self.username else 'no'})")

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
            logger.warning("AdGuard host not configured.")
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
