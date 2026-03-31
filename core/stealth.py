# core/stealth.py
# Stealth-scan helpers: randomisation, rate limiting, and jitter.
# These techniques reduce the chance of triggering IDS/IPS alerts.

import random
import time
from utils.config import STEALTH_MIN_DELAY, STEALTH_MAX_DELAY, SLOW_SCAN_DELAY
from utils.logger import get_logger

log = get_logger("stealth")


def randomise_ports(ports: list[int]) -> list[int]:
    """
    Return a shuffled copy of *ports*.
    Scanning in random order avoids sequential-port signatures in IDS rules.
    """
    shuffled = ports[:]
    random.shuffle(shuffled)
    log.debug("Port order randomised (%d ports).", len(shuffled))
    return shuffled


def jitter(slow: bool = False) -> None:
    """
    Sleep for a short random interval to introduce timing jitter.
    *slow* activates a longer fixed delay (ultra-stealth / slow-scan mode).
    """
    if slow:
        time.sleep(SLOW_SCAN_DELAY + random.uniform(0, 0.5))
    else:
        time.sleep(random.uniform(STEALTH_MIN_DELAY, STEALTH_MAX_DELAY))


def random_source_port() -> int:
    """Return a random ephemeral source port (1024 – 65535)."""
    return random.randint(1024, 65535)


def fragment_packet(pkt):
    """
    Fragment a Scapy packet into 8-byte IP fragments.
    Fragmentation can bypass some shallow-inspection firewalls.
    Returns a list of packet fragments, or [pkt] if Scapy is unavailable.
    """
    try:
        from scapy.all import fragment
        return fragment(pkt, fragsize=8)
    except ImportError:
        return [pkt]


class RateLimiter:
    """
    Token-bucket rate limiter.
    Ensures no more than *rate* scan attempts are made per second.
    """

    def __init__(self, rate: float = 100.0):
        self.rate      = rate          # tokens per second
        self.tokens    = rate
        self.last_time = time.monotonic()

    def acquire(self) -> None:
        """Block until a token is available."""
        while True:
            now    = time.monotonic()
            delta  = now - self.last_time
            self.last_time = now
            self.tokens   += delta * self.rate
            if self.tokens > self.rate:
                self.tokens = self.rate
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            time.sleep(0.01)
