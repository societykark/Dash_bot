import os
import re
import socket
import hashlib
import urllib.parse
import json
import logging
import asyncio
from datetime import datetime

import aiohttp
import whois
import dns.resolver
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
    ConversationHandler,
)

# ========== CONFIGURACIÓN ==========
TOKEN = os.environ.get("TOKEN")
if not TOKEN:
    raise ValueError("❌ La variable de entorno TOKEN no está configurada.")

EMAILREP_KEY = os.environ.get("EMAILREP_KEY", "")
NUMVERIFY_KEY = os.environ.get("NUMVERIFY_KEY", "")
SHODAN_KEY = os.environ.get("SHODAN_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "")

# ========== LOGS ==========
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ========== ESTADOS PARA CONVERSACIÓN ==========
WAITING_FOR_VALUE = 1

# ========== FUNCIONES DE API (ASÍNCRONAS) ==========

async def fetch_json(session, url, headers=None, timeout=15):
    try:
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status == 200:
                try:
                    return await resp.json()
                except:
                    text = await resp.text()
                    return {"error": f"Respuesta no JSON: {text[:100]}"}
            else:
                return {"error": f"HTTP {resp.status}"}
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except Exception as e:
        return {"error": str(e)}

# ---------- 1. Username (WhatsMyName) ----------
async def api_username(username: str) -> dict:
    if not username:
        return {"error": "Usuario vacío"}
    url = f"https://whatsmyname.app/api/v1/username?username={username}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINTBot/1.0; +https://t.me/jsemanper)"}
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url, headers=headers)
        if "error" in data:
            return data
        sites = data.get("sites", [])
        if not sites:
            return {"status": "empty", "message": "No se encontraron resultados."}
        return {"status": "ok", "total": len(sites), "sites": sites[:50]}

# ---------- 2. Email (EmailRep + HIBP) ----------
async def api_email(email: str) -> dict:
    if not email:
        return {"error": "Correo vacío"}
    result = {}
    async with aiohttp.ClientSession() as session:
        # EmailRep
        headers = {"User-Agent": "EmailRepBot/1.0"}
        url = f"https://emailrep.io/{email}"
        data = await fetch_json(session, url, headers=headers)
        if "error" in data:
            result["emailrep_error"] = data["error"]
        else:
            result["emailrep"] = data

        # HIBP
        hibp_headers = {"User-Agent": "Mozilla/5.0"}
        if HIBP_API_KEY:
            hibp_headers["hibp-api-key"] = HIBP_API_KEY
        else:
            result["hibp_error"] = "API key de HIBP no configurada (opcional)."
            # Intentamos sin key (puede dar 401)
        url_hibp = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            async with session.get(url_hibp, headers=hibp_headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    result["hibp"] = [b["Name"] for b in data]
                elif r.status == 404:
                    result["hibp"] = []
                elif r.status == 401:
                    result["hibp_error"] = "401 - Necesitas una API key de HIBP (gratis en haveibeenpwned.com/API/Key)"
                else:
                    result["hibp_error"] = f"Código {r.status}"
        except Exception as e:
            result["hibp_error"] = str(e)
    return result

# ---------- 3. Teléfono (Numverify) ----------
async def api_phone(phone: str) -> dict:
    if not NUMVERIFY_KEY:
        return {"error": "API key de Numverify no configurada (gratis en numverify.com)"}
    if not phone:
        return {"error": "Número vacío"}
    url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={phone}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url)

# ---------- 4. Dominio WHOIS ----------
async def api_domain(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else "N/A",
            "org": getattr(w, "org", "N/A"),
        }
    except Exception as e:
        return {"error": str(e)}

# ---------- 5. Portscan (síncrono pero adaptado) ----------
async def api_portscan(host: str, port_range: str = None) -> dict:
    if not host:
        return {"error": "Host vacío"}
    try:
        ip = socket.gethostbyname(host)
    except:
        return {"error": "No se pudo resolver el host"}
    if not port_range:
        port_range = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017"
    ports = []
    if "-" in port_range:
        try:
            start, end = map(int, port_range.split("-"))
            if end - start > 1000:
                return {"error": "Rango demasiado amplio (máx 1000)"}
            ports = list(range(start, end + 1))
        except:
            return {"error": "Formato inválido"}
    else:
        try:
            ports = [int(p.strip()) for p in port_range.split(",")]
        except:
            return {"error": "Formato inválido"}
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return {"host": host, "ip": ip, "open_ports": open_ports}

# ---------- 6. Reputación IP (ip-api) ----------
async def api_reputation(target: str) -> dict:
    if not target:
        return {"error": "Target vacío"}
    try:
        socket.inet_aton(target)
        ip = target
    except:
        try:
            ip = socket.gethostbyname(target)
        except:
            return {"error": "No se pudo resolver"}
    url = f"http://ip-api.com/json/{ip}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url)

# ---------- 7. Metadatos desde archivo (se maneja aparte) ----------
async def api_metadata_file(file_content: bytes, filename: str) -> dict:
    metadata = {"filename": filename, "size_bytes": len(file_content)}
    if filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf")):
        header = file_content[:20].hex()
        metadata["magic_bytes"] = header
        metadata["message"] = "Metadatos limitados (sin Pillow)."
    else:
        try:
            content = file_content.decode("utf-8", errors="ignore")
            metadata["md5"] = hashlib.md5(content.encode()).hexdigest()
        except:
            metadata["md5"] = "No se pudo leer (archivo binario)"
    return metadata

# ---------- 8. Metadatos desde URL ----------
async def api_metadata_url(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=15) as resp:
                if resp.status != 200:
                    return {"error": "No se pudo descargar"}
                content = await resp.read()
                filename = url.split("/")[-1]
                return await api_metadata_file(content, filename)
        except Exception as e:
            return {"error": str(e)}

# ---------- 9. Hash ----------
async def api_hash(hash_str: str) -> dict:
    if not hash_str:
        return {"error": "Hash vacío"}
    length = len(hash_str)
    if length == 32:
        htype = "MD5"
    elif length == 40:
        htype = "SHA1"
    elif length == 64:
        htype = "SHA256"
    else:
        return {"error": "Longitud no reconocida"}
    return {"hash": hash_str, "type": htype, "message": "Solo identificación"}

# ---------- 10. Shodan ----------
async def api_shodan(query: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "Se requiere API key de Shodan (gratis en shodan.io)"}
    if not query:
        return {"error": "Consulta vacía"}
    url = f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url)

# ---------- 11. Dork ----------
async def api_dork(dork: str) -> dict:
    if not dork:
        return {"error": "Consulta vacía"}
    encoded = urllib.parse.quote(dork)
    return {"url": f"https://www.google.com/search?q={encoded}"}

# ---------- 12. Bitcoin ----------
async def api_bitcoin(address: str) -> dict:
    if not address:
        return {"error": "Dirección vacía"}
    url = f"https://blockchain.info/rawaddr/{address}"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        if "error" in data:
            return data
        return {
            "address": address,
            "total_received": data.get("total_received"),
            "total_sent": data.get("total_sent"),
            "balance": data.get("balance"),
            "n_tx": data.get("n_tx"),
        }

# ---------- 13. Email Forensics ----------
async def api_email_forensics(headers_text: str) -> dict:
    if not headers_text:
        return {"error": "Cabeceras vacías"}
    lines = headers_text.split("\n")
    parsed = {}
    for line in lines:
        if ": " in line:
            key, val = line.split(": ", 1)
            parsed[key.lower()] = val
    return parsed

# ---------- 14. Breach Check ----------
async def api_breach(email: str) -> dict:
    if not email:
        return {"error": "Correo vacío"}
    headers = {"User-Agent": "Mozilla/5.0"}
    if HIBP_API_KEY:
        headers["hibp-api-key"] = HIBP_API_KEY
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    breaches = [{"name": b["Name"], "date": b["BreachDate"]} for b in data]
                    return {"email": email, "breaches": breaches}
                elif r.status == 404:
                    return {"email": email, "breaches": []}
                elif r.status == 401:
                    return {"error": "401 - Necesitas API key de HIBP (gratis en haveibeenpwned.com/API/Key)"}
                else:
                    return {"error": f"Código {r.status}"}
        except Exception as e:
            return {"error": str(e)}

# ---------- 15. IP Geolocation ----------
async def api_ipgeo(ip: str) -> dict:
    if not ip:
        return {"error": "IP vacía"}
    url = f"http://ip-api.com/json/{ip}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url)

# ---------- 16. MAC Lookup ----------
async def api_mac(mac: str) -> dict:
    if not mac:
        return {"error": "MAC vacía"}
    mac = mac.replace("-", "").replace(":", "").upper()
    if len(mac) < 6:
        return {"error": "MAC demasiado corta"}
    prefix = mac[:6]
    url = f"https://api.macvendors.com/{prefix}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    vendor = await r.text()
                    return {"mac": mac, "vendor": vendor.strip()}
                else:
                    return {"mac": mac, "vendor": "No encontrado"}
        except Exception as e:
            return {"error": str(e)}

# ---------- 17. Subdominios (crt.sh) ----------
async def api_subdomains(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        if "error" in data:
            return data
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for n in name.split("\n"):
                    if n.endswith(domain):
                        subdomains.add(n.strip())
        return {"domain": domain, "subdomains": list(subdomains)[:100]}

# ---------- 18. Reverse Image Search ----------
async def api_reverse_image(image_url: str) -> dict:
    if not image_url:
        return {"error": "URL vacía"}
    encoded = urllib.parse.quote(image_url)
    return {"url": f"https://www.google.com/searchbyimage?image_url={encoded}"}

# ---------- 19. Password Check (Pwned Passwords) ----------
async def api_password_check(password: str) -> dict:
    if not password:
        return {"error": "Contraseña vacía"}
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    text = await r.text()
                    lines = text.splitlines()
                    for line in lines:
                        if line.startswith(suffix):
                            count = int(line.split(":")[1])
                            return {"pwned": True, "count": count}
                    return {"pwned": False}
                else:
                    return {"error": "Error en API"}
        except Exception as e:
            return {"error": str(e)}

# ---------- 20. AI Threat (VirusTotal) ----------
async def api_ai_threat(url: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"error": "Se requiere API key de VirusTotal (gratis en virustotal.com)"}
    if not url:
        return {"error": "URL vacía"}
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    data = {"url": url}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data, timeout=15) as r:
                if r.status == 200:
                    resp = await r.json()
                    return {"message": "Escaneo enviado", "id": resp["data"]["id"]}
                else:
                    return {"error": "Error en VirusTotal"}
        except Exception as e:
            return {"error": str(e)}

# ---------- 21. JS Secret Scanner ----------
async def api_js_secrets(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as r:
                if r.status != 200:
                    return {"error": "No se pudo obtener el archivo"}
                content = await r.text()
                patterns = {
                    "AWS Key": r"AKIA[0-9A-Z]{16}",
                    "Google API": r"AIza[0-9A-Za-z\-_]{35}",
                    "GitHub Token": r"ghp_[0-9A-Za-z]{36}",
                    "JWT": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
                }
                found = []
                for name, pat in patterns.items():
                    matches = re.findall(pat, content)
                    if matches:
                        found.append({"type": name, "matches": matches[:3]})
                return {"secrets_found": found}
        except Exception as e:
            return {"error": str(e)}

# ---------- 22. Wayback ----------
async def api_wayback(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    full = f"https://archive.org/wayback/available?url={url}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, full)

# ---------- 23. Subdomain Takeover ----------
async def api_takeover(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    sub_data = await api_subdomains(domain)
    if "error" in sub_data:
        return sub_data
    subdomains = sub_data.get("subdomains", [])
    vulnerable = []
    for sub in subdomains[:20]:
        try:
            answers = dns.resolver.resolve(sub, "CNAME")
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                if any(x in target for x in ["s3.amazonaws.com", "github.io", "herokuapp.com"]):
                    vulnerable.append({"subdomain": sub, "cname": target})
        except:
            pass
    return {"subdomains": subdomains[:50], "potential_takeover": vulnerable}

# ---------- 24. Exposed Files ----------
async def api_exposed_files(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    common_files = [
        "/robots.txt", "/.env", "/.git/config", "/backup.zip", "/backup.sql",
        "/config.php", "/wp-config.php", "/.htaccess", "/phpinfo.php", "/admin/config.php"
    ]
    found = []
    async with aiohttp.ClientSession() as session:
        for path in common_files:
            url = f"http://{domain}{path}"
            try:
                async with session.get(url, timeout=5) as r:
                    if r.status == 200:
                        content = await r.read()
                        found.append({"url": url, "size": len(content)})
            except:
                pass
    return {"exposed": found}

# ---------- 25. Security Headers ----------
async def api_security_headers(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    if not url.startswith("http"):
        url = "https://" + url
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10, allow_redirects=True) as r:
                headers = r.headers
                important = {
                    "Content-Security-Policy": headers.get("Content-Security-Policy", "No"),
                    "X-Frame-Options": headers.get("X-Frame-Options", "No"),
                    "X-Content-Type-Options": headers.get("X-Content-Type-Options", "No"),
                    "Strict-Transport-Security": headers.get("Strict-Transport-Security", "No"),
                    "Referrer-Policy": headers.get("Referrer-Policy", "No"),
                    "Permissions-Policy": headers.get("Permissions-Policy", "No"),
                }
                return {"headers": important}
        except Exception as e:
            return {"error": str(e)}

# ---------- 26. CVE Search ----------
async def api_cve(keyword: str) -> dict:
    if not keyword:
        return {"error": "Palabra clave vacía"}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url)

# ---------- 27. ASN Lookup ----------
async def api_asn(ip: str) -> dict:
    if not ip:
        return {"error": "IP vacía"}
    url = f"https://ipinfo.io/{ip}/json"
    async with aiohttp.ClientSession() as session:
        data = await fetch_json(session, url)
        if "error" in data:
            return data
        return {
            "org": data.get("org"),
            "asn": data.get("asn", "N/A"),
            "country": data.get("country"),
        }

# ---------- 28. S3 Bucket Finder ----------
async def api_s3finder(company: str) -> dict:
    if not company:
        return {"error": "Nombre vacío"}
    perms = [
        company, f"{company}-backup", f"{company}-dev", f"{company}-prod",
        f"{company}-staging", f"{company}-data", f"{company}-static",
        f"{company}-assets", f"{company}-media", f"{company}-cdn",
    ]
    found = []
    async with aiohttp.ClientSession() as session:
        for bucket in perms:
            url = f"https://{bucket}.s3.amazonaws.com"
            try:
                async with session.get(url, timeout=5) as r:
                    if r.status in (200, 403):
                        found.append({"bucket": bucket, "status": r.status})
            except:
                pass
    return {"buckets": found}

# ---------- 29. CORS Check ----------
async def api_cors(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    if not url.startswith("http"):
        url = "https://" + url
    async with aiohttp.ClientSession() as session:
        try:
            async with session.options(url, timeout=10) as r:
                cors = r.headers.get("Access-Control-Allow-Origin")
                return {"cors_origin": cors, "cors_enabled": cors is not None}
        except Exception as e:
            return {"error": str(e)}

# ---------- 30. GitHub Secrets ----------
async def api_github_secrets(org: str) -> dict:
    if not GITHUB_TOKEN:
        return {"error": "Se requiere GitHub token (crea uno con permisos de búsqueda)"}
    if not org:
        return {"error": "Organización vacía"}
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OSINTBot",
    }
    query = f"org:{org} extension:conf OR extension:env OR extension:key OR filename:.env"
    url = f"https://api.github.com/search/code?q={query}"
    async with aiohttp.ClientSession() as session:
        return await fetch_json(session, url, headers=headers, timeout=30)

# ---------- 31. Tech Detection ----------
async def api_tech_detect(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    if not domain.startswith("http"):
        domain = "https://" + domain
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(domain, timeout=10, ssl=False) as r:
                headers = r.headers
                content = await r.text()
                tech = {}
                if "Server" in headers:
                    tech["Servidor"] = headers["Server"]
                if "x-powered-by" in headers:
                    tech["Powered by"] = headers["x-powered-by"]
                if "/wp-content/" in content:
                    tech["CMS"] = "WordPress"
                if "Drupal" in content:
                    tech["CMS"] = "Drupal"
                if "Joomla" in content:
                    tech["CMS"] = "Joomla"
                if "laravel" in content.lower():
                    tech["Framework"] = "Laravel"
                if "django" in content.lower():
                    tech["Framework"] = "Django"
                return {"domain": domain, "technologies": tech}
        except Exception as e:
            return {"error": str(e)}

# ========== FUNCIONES DEL BOT ==========

def format_result(cmd_name, result):
    """Convierte resultado a string formateado con HTML"""
    if "error" in result:
        return f"<b>Error en /{cmd_name}:</b>\n\n<code>{result['error']}</code>"
    return f"<b>Resultado de /{cmd_name}:</b>\n\n<code>{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}</code>"

async def send_result(update, cmd_name, result):
    await update.message.reply_text(
        format_result(cmd_name, result),
        parse_mode=ParseMode.HTML
    )

# Comandos directos
async def cmd_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/username <usuario>`", parse_mode=ParseMode.HTML)
        return
    value = " ".join(context.args)
    result = await api_username(value)
    await send_result(update, "username", result)

async def cmd_email(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/email <correo>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_email(value)
    await send_result(update, "email", result)

async def cmd_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/phone <número>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_phone(value)
    await send_result(update, "phone", result)

async def cmd_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/domain <dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_domain(value)
    await send_result(update, "domain", result)

async def cmd_portscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/portscan <host>` o `/portscan <host> 80-100`", parse_mode=ParseMode.HTML)
        return
    host = context.args[0]
    port_range = context.args[1] if len(context.args) > 1 else None
    result = await api_portscan(host, port_range)
    await send_result(update, "portscan", result)

async def cmd_reputation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/reputation <ip/dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_reputation(value)
    await send_result(update, "reputation", result)

async def cmd_metadata_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/metadata_url <url_imagen>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_metadata_url(value)
    await send_result(update, "metadata_url", result)

async def cmd_hash(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/hash <hash>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_hash(value)
    await send_result(update, "hash", result)

async def cmd_shodan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/shodan <ip>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_shodan(value)
    await send_result(update, "shodan", result)

async def cmd_dork(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/dork <consulta>`", parse_mode=ParseMode.HTML)
        return
    value = " ".join(context.args)
    result = await api_dork(value)
    await send_result(update, "dork", result)

async def cmd_bitcoin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/bitcoin <dirección>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_bitcoin(value)
    await send_result(update, "bitcoin", result)

async def cmd_breach(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/breach <email>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_breach(value)
    await send_result(update, "breach", result)

async def cmd_ipgeo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/ipgeo <ip>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_ipgeo(value)
    await send_result(update, "ipgeo", result)

async def cmd_mac(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/mac <mac>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_mac(value)
    await send_result(update, "mac", result)

async def cmd_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/subdomains <dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_subdomains(value)
    await send_result(update, "subdomains", result)

async def cmd_reverse_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/reverse_image <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_reverse_image(value)
    await send_result(update, "reverse_image", result)

async def cmd_password_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/password_check <contraseña>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_password_check(value)
    await send_result(update, "password_check", result)

async def cmd_ai_threat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/ai_threat <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_ai_threat(value)
    await send_result(update, "ai_threat", result)

async def cmd_js_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/js_secrets <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_js_secrets(value)
    await send_result(update, "js_secrets", result)

async def cmd_wayback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/wayback <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_wayback(value)
    await send_result(update, "wayback", result)

async def cmd_takeover(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/takeover <dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_takeover(value)
    await send_result(update, "takeover", result)

async def cmd_exposed_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/exposed_files <dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_exposed_files(value)
    await send_result(update, "exposed_files", result)

async def cmd_security_headers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/security_headers <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_security_headers(value)
    await send_result(update, "security_headers", result)

async def cmd_cve(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/cve <palabra>`", parse_mode=ParseMode.HTML)
        return
    value = " ".join(context.args)
    result = await api_cve(value)
    await send_result(update, "cve", result)

async def cmd_asn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/asn <ip>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_asn(value)
    await send_result(update, "asn", result)

async def cmd_s3finder(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/s3finder <empresa>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_s3finder(value)
    await send_result(update, "s3finder", result)

async def cmd_cors(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/cors <url>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_cors(value)
    await send_result(update, "cors", result)

async def cmd_github_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/github_secrets <organización>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_github_secrets(value)
    await send_result(update, "github_secrets", result)

async def cmd_tech_detect(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/tech_detect <dominio>`", parse_mode=ParseMode.HTML)
        return
    value = context.args[0]
    result = await api_tech_detect(value)
    await send_result(update, "tech_detect", result)

async def cmd_email_forensics(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Uso: `/email_forensics <cabeceras>` (múltiples líneas)", parse_mode=ParseMode.HTML)
        return
    value = " ".join(context.args)
    result = await api_email_forensics(value)
    await send_result(update, "email_forensics", result)

# ========== MENÚ Y CONVERSACIÓN ==========

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🕵️ <b>Bot OSINT - Herramientas de inteligencia de fuentes abiertas</b>\n\n"
        "Usa /menu para ver las opciones interactivas.\n"
        "O escribe directamente un comando (ej. /email correo@ejemplo.com).\n\n"
        "📌 <i>Algunos comandos requieren API keys (las verás en el menú).</i>",
        parse_mode=ParseMode.HTML,
    )

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("🔍 Username", callback_data="username")],
        [InlineKeyboardButton("📧 Email", callback_data="email")],
        [InlineKeyboardButton("📞 Teléfono", callback_data="phone")],
        [InlineKeyboardButton("🌐 Dominio WHOIS", callback_data="domain")],
        [InlineKeyboardButton("🔌 Portscan", callback_data="portscan")],
        [InlineKeyboardButton("⚡ Reputación", callback_data="reputation")],
        [InlineKeyboardButton("🖼️ Metadatos (URL)", callback_data="metadata_url")],
        [InlineKeyboardButton("🔐 Hash", callback_data="hash")],
        [InlineKeyboardButton("🔎 Shodan", callback_data="shodan")],
        [InlineKeyboardButton("📄 Dork", callback_data="dork")],
        [InlineKeyboardButton("₿ Bitcoin", callback_data="bitcoin")],
        [InlineKeyboardButton("📊 Breach Check", callback_data="breach")],
        [InlineKeyboardButton("🌍 IP Geolocation", callback_data="ipgeo")],
        [InlineKeyboardButton("🖧 MAC Lookup", callback_data="mac")],
        [InlineKeyboardButton("📡 Subdominios", callback_data="subdomains")],
        [InlineKeyboardButton("🔍 Reverse Image", callback_data="reverse_image")],
        [InlineKeyboardButton("🔑 Password Check", callback_data="password_check")],
        [InlineKeyboardButton("🤖 AI Threat", callback_data="ai_threat")],
        [InlineKeyboardButton("💻 JS Secrets", callback_data="js_secrets")],
        [InlineKeyboardButton("📆 Wayback", callback_data="wayback")],
        [InlineKeyboardButton("⚠️ Takeover", callback_data="takeover")],
        [InlineKeyboardButton("📁 Exposed Files", callback_data="exposed_files")],
        [InlineKeyboardButton("🛡️ Security Headers", callback_data="security_headers")],
        [InlineKeyboardButton("🐞 CVE Search", callback_data="cve")],
        [InlineKeyboardButton("🌐 ASN", callback_data="asn")],
        [InlineKeyboardButton("📦 S3 Finder", callback_data="s3finder")],
        [InlineKeyboardButton("🔗 CORS", callback_data="cors")],
        [InlineKeyboardButton("🔑 GitHub Secrets", callback_data="github_secrets")],
        [InlineKeyboardButton("🌡️ Tech Detect", callback_data="tech_detect")],
        [InlineKeyboardButton("✉️ Email Forensics", callback_data="email_forensics")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("📋 <b>Elige una herramienta:</b>", reply_markup=reply_markup, parse_mode=ParseMode.HTML)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    command = query.data
    context.user_data["command"] = command
    prompt = f"✏️ Escribe el valor para <b>/</b><code>{command}</code> (o /cancel para cancelar):"
    await query.edit_message_text(prompt, parse_mode=ParseMode.HTML)
    return WAITING_FOR_VALUE

async def handle_value(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    value = update.message.text.strip()
    command = context.user_data.get("command")
    if not command:
        await update.message.reply_text("❌ No sé qué herramienta usar. Usa /menu.", parse_mode=ParseMode.HTML)
        return ConversationHandler.END

    # Mapeo de comandos a funciones
    func_map = {
        "username": api_username,
        "email": api_email,
        "phone": api_phone,
        "domain": api_domain,
        "portscan": lambda v: api_portscan(v, None),
        "reputation": api_reputation,
        "metadata_url": api_metadata_url,
        "hash": api_hash,
        "shodan": api_shodan,
        "dork": api_dork,
        "bitcoin": api_bitcoin,
        "breach": api_breach,
        "ipgeo": api_ipgeo,
        "mac": api_mac,
        "subdomains": api_subdomains,
        "reverse_image": api_reverse_image,
        "password_check": api_password_check,
        "ai_threat": api_ai_threat,
        "js_secrets": api_js_secrets,
        "wayback": api_wayback,
        "takeover": api_takeover,
        "exposed_files": api_exposed_files,
        "security_headers": api_security_headers,
        "cve": api_cve,
        "asn": api_asn,
        "s3finder": api_s3finder,
        "cors": api_cors,
        "github_secrets": api_github_secrets,
        "tech_detect": api_tech_detect,
        "email_forensics": api_email_forensics,
    }
    if command not in func_map:
        await update.message.reply_text("❌ Comando no reconocido.", parse_mode=ParseMode.HTML)
        return ConversationHandler.END

    result = await func_map[command](value)
    await update.message.reply_text(
        format_result(command, result),
        parse_mode=ParseMode.HTML
    )
    context.user_data.pop("command", None)
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("❌ Operación cancelada.", parse_mode=ParseMode.HTML)
    return ConversationHandler.END

# ========== MANEJO DE ARCHIVOS ==========
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document or update.message.photo[-1] if update.message.photo else None
    if not document:
        await update.message.reply_text("❌ No se detectó archivo.", parse_mode=ParseMode.HTML)
        return
    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    filename = document.file_name if hasattr(document, "file_name") else "archivo.jpg"
    result = await api_metadata_file(file_content, filename)
    await update.message.reply_text(
        f"<b>Metadatos del archivo:</b>\n\n<code>{json.dumps(result, indent=2, ensure_ascii=False)}</code>",
        parse_mode=ParseMode.HTML
    )

# ========== MAIN ==========

def main() -> None:
    application = Application.builder().token(TOKEN).build()

    # Conversación para menú interactivo
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^(username|email|phone|domain|portscan|reputation|metadata_url|hash|shodan|dork|bitcoin|breach|ipgeo|mac|subdomains|reverse_image|password_check|ai_threat|js_secrets|wayback|takeover|exposed_files|security_headers|cve|asn|s3finder|cors|github_secrets|tech_detect|email_forensics)$")],
        states={
            WAITING_FOR_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_value)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    application.add_handler(conv_handler)

    # Comandos directos
    application.add_handler(CommandHandler("username", cmd_username))
    application.add_handler(CommandHandler("email", cmd_email))
    application.add_handler(CommandHandler("phone", cmd_phone))
    application.add_handler(CommandHandler("domain", cmd_domain))
    application.add_handler(CommandHandler("portscan", cmd_portscan))
    application.add_handler(CommandHandler("reputation", cmd_reputation))
    application.add_handler(CommandHandler("metadata_url", cmd_metadata_url))
    application.add_handler(CommandHandler("hash", cmd_hash))
    application.add_handler(CommandHandler("shodan", cmd_shodan))
    application.add_handler(CommandHandler("dork", cmd_dork))
    application.add_handler(CommandHandler("bitcoin", cmd_bitcoin))
    application.add_handler(CommandHandler("breach", cmd_breach))
    application.add_handler(CommandHandler("ipgeo", cmd_ipgeo))
    application.add_handler(CommandHandler("mac", cmd_mac))
    application.add_handler(CommandHandler("subdomains", cmd_subdomains))
    application.add_handler(CommandHandler("reverse_image", cmd_reverse_image))
    application.add_handler(CommandHandler("password_check", cmd_password_check))
    application.add_handler(CommandHandler("ai_threat", cmd_ai_threat))
    application.add_handler(CommandHandler("js_secrets", cmd_js_secrets))
    application.add_handler(CommandHandler("wayback", cmd_wayback))
    application.add_handler(CommandHandler("takeover", cmd_takeover))
    application.add_handler(CommandHandler("exposed_files", cmd_exposed_files))
    application.add_handler(CommandHandler("security_headers", cmd_security_headers))
    application.add_handler(CommandHandler("cve", cmd_cve))
    application.add_handler(CommandHandler("asn", cmd_asn))
    application.add_handler(CommandHandler("s3finder", cmd_s3finder))
    application.add_handler(CommandHandler("cors", cmd_cors))
    application.add_handler(CommandHandler("github_secrets", cmd_github_secrets))
    application.add_handler(CommandHandler("tech_detect", cmd_tech_detect))
    application.add_handler(CommandHandler("email_forensics", cmd_email_forensics))

    # Comandos de inicio y menú
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", menu))

    # Manejo de archivos
    application.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO, handle_file))

    # Comandos desconocidos
    async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("❌ Comando no reconocido. Usa /menu.", parse_mode=ParseMode.HTML)
    application.add_handler(MessageHandler(filters.COMMAND, unknown))

    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()