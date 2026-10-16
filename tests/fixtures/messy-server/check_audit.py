#!/usr/bin/env python3
"""Assertions over the security audit the daemon produced in the fixture."""
import json
import sys

report = json.load(open(sys.argv[1]))
host = report["host"]
failures = []


def expect(condition, message):
    if not condition:
        failures.append(message)


def suspicious(kind, source, reason):
    return [s for s in host["suspicious"] if s["kind"] == kind and source in s["source"] and reason in s["reasons"]]


packages = {(p["ecosystem"], p["name"], p["version"]) for p in report["packages"]}
for want in [("npm", "lodash", "4.17.15"), ("npm", "minimist", "0.0.8"), ("pypi", "requests", "2.19.0"), ("pypi", "django", "3.2.0"), ("packagist", "laravel/framework", "8.0.0"), ("npm", "pm2", None)]:
    if want[2] is None:
        expect(any(p[0] == want[0] and p[1] == want[1] for p in packages), f"global {want[1]} not found")
    else:
        expect(want in packages, f"{want} not found in packages")

expect(suspicious("cron", "/etc/cron.d/sysupdate", "download_exec"), "the curl | sh cron job wasn't flagged")
expect(suspicious("cron", "crontabs/www-data", "miner"), "the miner in www-data's crontab wasn't flagged")
expect(suspicious("systemd", "dbus-org.helper.service", "reverse_shell"), "the reverse shell unit wasn't flagged")
expect(suspicious("profile", "/root/.bashrc", "download_exec"), "root's .bashrc download wasn't flagged")
expect(suspicious("process", "pid", "temp_path"), f"the process from /dev/shm wasn't flagged: {host['suspicious']}")
expect(suspicious("process", "pid", "miner"), "the process named like a miner wasn't flagged")
expect(suspicious("process", "pid", "fake_kernel_thread"), "the fake kernel thread wasn't flagged")
expect(not any("nginx" in s["command"] or "postgres" in s["command"] for s in host["suspicious"] if s["kind"] == "process"), "an ordinary process was flagged")

expect(host["accounts"]["extra_root"] == ["toor"], f"extra root accounts: {host['accounts']}")
expect("www-data" in host["accounts"]["system_logins"], f"system logins: {host['accounts']}")
expect(host["preload"] == ["/usr/local/lib/libprocesshider.so"], f"preload: {host['preload']}")
expect(any(s["path"] == "/tmp/.x/bash" and s["reason"] == "root_shell" for s in host["setuid"]), f"the setuid bash wasn't found: {host['setuid']}")
expect(not any(s["path"] in ("/usr/bin/sudo", "/usr/bin/passwd", "/bin/su", "/usr/bin/su") for s in host["setuid"]), f"a normal setuid program was flagged: {host['setuid']}")
expect(any(w["path"] == "/opt/scripts/backup.sh" and w["reason"] == "root_script" for w in host["writable"]), f"the world-writable root script wasn't found: {host['writable']}")
keys = {k["user"]: k for k in host["ssh_keys"]}
expect(keys.get("root", {}).get("keys", [{}])[0].get("fingerprint") == "SHA256:wiUclTj5wWPzqoZ8XNN4y6Jj1SR7OAJSCVrwU2rMtus", f"root's key: {keys.get('root')}")

expect(any(d["service"] == "postgres" and d["issue"] == "trust_network" and d["listens_everywhere"] for d in report["databases"]), f"postgres trust: {report['databases']}")

blog = [s for s in report["sites"] if s["names"] == ["blog.example.com"]]
expect(blog and ".env" in blog[0]["risky_files"] and ".git" in blog[0]["risky_files"], f"blog risky files: {blog}")
expect(blog and blog[0]["wordpress"] and blog[0]["wordpress"]["version"] == "5.8.1", f"wordpress: {blog}")
expect(blog and blog[0]["wordpress"]["plugins"] == [{"slug": "contact-form-7", "version": "5.3.1"}], f"plugins: {blog}")
expect(any(s["names"] == ["shop.example.com"] and s["tls"] for s in report["sites"]), f"shop site: {report['sites']}")
expect(any(a["path"] == "/srv/laravel" and a["debug_in_production"] and a["env_world_readable"] for a in report["apps"]), f"laravel debug: {report['apps']}")

runtimes = {r["name"] for r in report["runtimes"]}
for name in ("node", "python", "nginx", "postgres", "redis", "openssl"):
    expect(name in runtimes, f"runtime {name} not found: {report['runtimes']}")

if failures:
    print("FAILED:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print(f"ok: {len(report['packages'])} packages, {len(report['sites'])} sites, {len(host['suspicious'])} suspicious, {report['duration_ms']} ms")
