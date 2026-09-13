#!/usr/bin/env python3
"""Assertions over the inventory report the daemon produced in the fixture."""
import json
import sys

report = json.load(open(sys.argv[1]))
services = report["services"]
listeners = report["listeners"]
failures = []


def expect(condition, message):
    if not condition:
        failures.append(message)


def service_on(port):
    return [s for s in services if port in s.get("ports", [])]


ports = {l["port"] for l in listeners}
for port, what in [(80, "nginx"), (443, "nginx tls"), (5432, "postgres"), (6379, "redis"), (3000, "pm2 app"), (25565, "screen game server"), (8080, "nohup script")]:
    expect(port in ports, f"listener on {port} ({what}) not found; saw {sorted(ports)}")

expect(report["complete"], "scan reported incomplete")
expect(any("systemd" in w for w in report.get("warnings", [])), "expected an honest 'systemd not reachable' warning in a container")

web = service_on(80)
expect(web and web[0]["kind"] in ("web_server", "proxy"), f"port 80 should classify as a web server, got {web}")
expect(any("nginx" in (s.get("name") or "").lower() or "nginx" in s["key"] for s in web), f"nginx not named on port 80: {web}")

db = service_on(5432)
expect(db and db[0]["kind"] == "database", f"postgres should classify as a database, got {db}")

cache = service_on(6379)
expect(cache and cache[0]["kind"] == "cache", f"redis should classify as a cache, got {cache}")

pm2 = service_on(3000)
expect(pm2 and pm2[0]["manager"] == "pm2", f"the shop-api process should be attributed to pm2, got {pm2}")

game = service_on(25565)
expect(game and game[0]["manager"] == "screen", f"the screen session should be attributed to screen, got {game}")

adhoc = service_on(8080) or [u for u in report.get("unknown", []) if u.get("port") == 8080]
expect(adhoc, "the nohup'd python server on 8080 should appear as a service or an unknown listener")

expect(any("backup" in (t.get("command") or "") for t in report.get("scheduled", [])), f"the cron.d backup job was not found in scheduled: {report.get('scheduled')}")
expect(any("shop.example.com" in " ".join(c.get("names", [])) or "shop.example.com" in c.get("subject", "") for c in report.get("certificates", [])), f"the letsencrypt-style certificate was not found: {report.get('certificates')}")

if failures:
    print("FAILED:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print(f"ok: {len(services)} services, {len(listeners)} listeners, {len(report.get('scheduled', []))} scheduled, {len(report.get('certificates', []))} certificates")
