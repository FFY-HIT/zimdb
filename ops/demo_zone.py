"""Seed LogicalZone for the ops desktop demo."""
from __future__ import annotations

from ops.vendor.checked_image.p1 import LogicalRRset, LogicalZone

ORIGIN = "example.com."


def seed_zone() -> LogicalZone:
    origin = ORIGIN
    rrsets = (
        LogicalRRset(
            origin,
            300,
            "SOA",
            ("ns1.example.com. hostmaster.example.com. 2026102801 7200 3600 1209600 300",),
        ),
        LogicalRRset(origin, 300, "NS", ("ns1.example.com.", "ns2.example.com.")),
        LogicalRRset("ns1.example.com.", 300, "A", ("192.0.2.53",)),
        LogicalRRset("ns2.example.com.", 300, "A", ("192.0.2.54",)),
        LogicalRRset("www.example.com.", 300, "A", ("192.0.2.10",)),
        LogicalRRset("www.example.com.", 300, "AAAA", ("2001:db8::10",)),
        LogicalRRset("mail.example.com.", 300, "A", ("192.0.2.20",)),
        LogicalRRset(origin, 300, "MX", ("10 mail.example.com.",)),
        LogicalRRset(origin, 300, "TXT", ('"v=spf1 -all"',)),
        LogicalRRset("api.example.com.", 300, "A", ("203.0.113.1",)),
        LogicalRRset("old.example.com.", 300, "A", ("198.51.100.1",)),
        LogicalRRset("old.example.com.", 300, "TXT", ('"to-be-deleted"',)),
    )
    return LogicalZone(origin, rrsets)


# GUI scenario presets (do not auto-submit)
SCENARIOS: dict[str, list[dict]] = {
    "add": [
        {
            "op": "ADD",
            "owner": "www.example.com.",
            "rrtype": "A",
            "ttl": 300,
            "rdata": "203.0.113.10",
            "old_rdata": "",
        }
    ],
    "modify": [
        {
            "op": "MODIFY",
            "owner": "api.example.com.",
            "rrtype": "A",
            "ttl": 300,
            "rdata": "203.0.113.99",
            "old_rdata": "203.0.113.1",
        }
    ],
    "delete": [
        {
            "op": "DELETE",
            "owner": "old.example.com.",
            "rrtype": "TXT",
            "ttl": 300,
            "rdata": '"to-be-deleted"',
            "old_rdata": "",
        }
    ],
}
