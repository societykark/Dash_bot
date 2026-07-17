import os
import re
import socket
import hashlib
import urllib.parse
import tempfile
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional

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

# ========== LOGS ==========
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ========== CACHÉ (opcional) ==========
cache: Dict[str, Dict] = {}
CACHE_TTL = 300  # 5 minutos

def get_cache(key: str) -> Optional[Dict]:
    if key in cache:
        data, timestamp = cache[key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_TTL):
            return data
        del cache[key]
    return None

def set_cache(key: str, data: Dict):
    cache[key] = (data, datetime.now())

# ========== ESTADOS PARA CONVERSACIÓN ==========
WAITING_FOR_VALUE = 1

# ========== FUNCIONES DE API (ASÍNCRONAS) ==========

async def fetch_json(session, url, headers=None, timeout=15):
    try:
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status == 200:
                return await resp.json()
            return {"error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"error": str(e)}

async def api_username(username: str) -> dict:
    if not username:
        return {"error": "Usuario vacío"}
    async with aiohttp.ClientSession() as session:
        url = f"https://whatsmyname.app/api/v1/username?username={username}"
        data = await fetch_json(session, url)
        if "error" in data:
            return data
        sites = data.get("sites", [])
        if not sites:
            return {"status": "empty", "message": "No se encontraron resultados."}
        return {"status": "ok", "total": len(sites), "sites": sites[:50]}

async def api_email(email: str) -> dict:
    if not email:
        return {"error": "Correo vacío"}
    result = {}
    async with aiohttp.ClientSession() as session:
        headers = {"User-Agent": "Mozilla/5.0"}
        if EMAILREP_KEY:
            headers["X-API-Key"] = EMAILREP_KEY
        url = f"https://emailrep.io/{email}"
        resp = await fetch_json(session, url, headers=headers)
        if "error" in resp:
            result["emailrep_error"] = resp["error"]
        else:
            result["emailrep"] = resp

        # HIBP
        hibp_headers = {"User-Agent": "Mozilla/5.0"}
        url_hibp = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            async with session.get(url_hibp, headers=hibp_headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    result["hibp"] = [b["Name"] for b in data]
                elif r.status == 404:
                    result["hibp"] = []
                else:
                    result["hibp_error"] = f"Código {r.status}"
        except Exception as e:
            result["hibp_error"] = str(e)
    return result

async def api_phone(phone: str) -> dict:
    if not NUMVERIFY_KEY:
        return {"error": "API key de Numverify no configurada"}
    if not phone:
        return {"error": "Número vacío"}
    async with aiohttp.ClientSession() as session:
        url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={phone}"
        return await fetch_json(session, url)

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
    loop = asyncio.get_event_loop()
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return {"host": host, "ip": ip, "open_ports": open_ports}

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
    async with aiohttp.ClientSession() as session:
        url = f"http://ip-api.com/json/{ip}"
        return await fetch_json(session, url)

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

async def api_shodan(query: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "Se requiere API key de Shodan"}
    if not query:
        return {"error": "Consulta vacía"}
    async with aiohttp.ClientSession() as session:
        url = f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}"
        return await fetch_json(session, url)

async def api_dork(dork: str) -> dict:
    if not dork:
        return {"error": "Consulta vacía"}
    encoded = urllib.parse.quote(dork)
    return {"url": f"https://www.google.com/search?q={encoded}"}

async def api_bitcoin(address: str) -> dict:
    if not address:
        return {"error": "Dirección vacía"}
    async with aiohttp.ClientSession() as session:
        url = f"https://blockchain.info/rawaddr/{address}"
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

async def api_breach(email: str) -> dict:
    if not email:
        return {"error": "Correo vacío"}
    async with aiohttp.ClientSession() as session:
        headers = {"User-Agent": "Mozilla/5.0"}
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            async with session.get(url, headers=headers, timeout=10) as r:
                if r.status == 200:
                    data = await r.json()
                    breaches = [{"name": b["Name"], "date": b["BreachDate"]} for b in data]
                    return {"email": email, "breaches": breaches}
                elif r.status == 404:
                    return {"email": email, "breaches": []}
                else:
                    return {"error": f"Error {r.status}"}
        except Exception as e:
            return {"error": str(e)}

async def api_ipgeo(ip: str) -> dict:
    if not ip:
        return {"error": "IP vacía"}
    async with aiohttp.ClientSession() as session:
        url = f"http://ip-api.com/json/{ip}"
        return await fetch_json(session, url)

async def api_mac(mac: str) -> dict:
    if not mac:
        return {"error": "MAC vacía"}
    mac = mac.replace("-", "").replace(":", "").upper()
    if len(mac) < 6:
        return {"error": "MAC demasiado corta"}
    prefix = mac[:6]
    async with aiohttp.ClientSession() as session:
        url = f"https://api.macvendors.com/{prefix}"
        try:
            async with session.get(url, timeout=10) as r:
                if r.status == 200:
                    vendor = await r.text()
                    return {"mac": mac, "vendor": vendor.strip()}
                else:
                    return {"mac": mac, "vendor": "No encontrado"}
        except Exception as e:
            return {"error": str(e)}

async def api_subdomains(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    async with aiohttp.ClientSession() as session:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
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

async def api_reverse_image(image_url: str) -> dict:
    if not image_url:
        return {"error": "URL vacía"}
    encoded = urllib.parse.quote(image_url)
    return {"url": f"https://www.google.com/searchbyimage?image_url={encoded}"}

async def api_password_check(password: str) -> dict:
    if not password:
        return {"error": "Contraseña vacía"}
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    async with aiohttp.ClientSession() as session:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
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

async def api_ai_threat(url: str) -> dict:
    if not VIRUSTOTAL_KEY:
        return {"error": "Se requiere API key de VirusTotal"}
    if not url:
        return {"error": "URL vacía"}
    async with aiohttp.ClientSession() as session:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        data = {"url": url}
        try:
            async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data, timeout=15) as r:
                if r.status == 200:
                    resp = await r.json()
                    return {"message": "Escaneo enviado", "id": resp["data"]["id"]}
                else:
                    return {"error": "Error en VirusTotal"}
        except Exception as e:
            return {"error": str(e)}

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

async def api_wayback(url: str) -> dict:
    if not url:
        return {"error": "URL vacía"}
    async with aiohttp.ClientSession() as session:
        full = f"https://archive.org/wayback/available?url={url}"
        return await fetch_json(session, full)

async def api_takeover(domain: str) -> dict:
    if not domain:
        return {"error": "Dominio vacío"}
    # Obtener subdominios
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

async def api_cve(keyword: str) -> dict:
    if not keyword:
        return {"error": "Palabra clave vacía"}
    async with aiohttp.ClientSession() as session:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
        return await fetch_json(session, url)

async def api_asn(ip: str) -> dict:
    if not ip:
        return {"error": "IP vacía"}
    async with aiohttp.ClientSession() as session:
        url = f"https://ipinfo.io/{ip}/json"
        data = await fetch_json(session, url)
        if "error" in data:
            return data
        return {
            "org": data.get("org"),
            "asn": data.get("asn", "N/A"),
            "country": data.get("country"),
        }

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

async def api_github_secrets(org: str) -> dict:
    if not GITHUB_TOKEN:
        return {"error": "Se requiere GitHub token"}
    if not org:
        return {"error": "Organización vacía"}
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    query = f"org:{org} extension:conf OR extension:env OR extension:key OR filename:.env"
    async with aiohttp.ClientSession() as session:
        url = f"https://api.github.com/search/code?q={query}"
        return await fetch_json(session, url, headers=headers, timeout=30)

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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "🕵️ *Bot OSINT - Herramientas de inteligencia de fuentes abiertas*\n\n"
        "Usa `/menu` para ver las opciones interactivas.\n"
        "O escribe directamente un comando:\n"
        "`/search <usuario>`\n"
        "`/email <correo>`\n"
        "`/phone <número>`\n"
        "`/domain <dominio>`\n"
        "`/portscan <host>`\n"
        "`/reputation <ip/dominio>`\n"
        "`/hash <hash>`\n"
        "`/shodan <ip>`\n"
        "`/dork <consulta>`\n"
        "`/bitcoin <dirección>`\n"
        "`/breach <email>`\n"
        "`/ipgeo <ip>`\n"
        "`/mac <mac>`\n"
        "`/subdomains <dominio>`\n"
        "`/reverse_image <url>`\n"
        "`/password <contraseña>`\n"
        "`/ai_threat <url>`\n"
        "`/js_secrets <url>`\n"
        "`/wayback <url>`\n"
        "`/takeover <dominio>`\n"
        "`/exposed <dominio>`\n"
        "`/security_headers <url>`\n"
        "`/cve <palabra>`\n"
        "`/asn <ip>`\n"
        "`/s3finder <empresa>`\n"
        "`/cors <url>`\n"
        "`/github_secrets <organización>`\n"
        "`/tech_detect <dominio>`\n\n"
        "También puedes enviar un archivo (imagen, PDF, etc.) para obtener metadatos.",
        parse_mode=ParseMode.MARKDOWN,
    )

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("🔍 Username", callback_data="username")],
        [InlineKeyboardButton("📧 Email", callback_data="email")],
        [InlineKeyboardButton("📞 Teléfono", callback_data="phone")],
        [InlineKeyboardButton("🌐 Dominio WHOIS", callback_data="domain")],
        [InlineKeyboardButton("🔌 Portscan", callback_data="portscan")],
        [InlineKeyboardButton("⚡ Reputación", callback_data="reputation")],
        [InlineKeyboardButton("🖼️ Metadatos (archivo)", callback_data="metadata_file")],
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
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("📋 *Elige una herramienta:*", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    command = query.data
    # Guardar el comando en user_data para la conversación
    context.user_data["command"] = command
    # Dependiendo del comando, pedir el valor correspondiente
    if command == "metadata_file":
        await query.edit_message_text("📤 Envía un archivo (imagen, PDF, texto, etc.) y te extraeré los metadatos.")
        return WAITING_FOR_VALUE
    else:
        prompt = f"✏️ Escribe el valor para `/{command}`:"
        await query.edit_message_text(prompt, parse_mode=ParseMode.MARKDOWN)
        return WAITING_FOR_VALUE

async def handle_value(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Recibir el valor escrito por el usuario
    value = update.message.text.strip()
    command = context.user_data.get("command")
    if not command:
        await update.message.reply_text("❌ No se qué herramienta usar. Usa /menu.")
        return ConversationHandler.END

    # Ejecutar la función correspondiente
    result = await execute_command(command, value, update.message)
    await update.message.reply_text(f"*Resultado de /{command}:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}", parse_mode=ParseMode.MARKDOWN)
    context.user_data.pop("command", None)
    return ConversationHandler.END

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Manejar archivos para metadata
    document = update.message.document or update.message.photo
    if not document:
        await update.message.reply_text("❌ No se detectó archivo.")
        return
    # Descargar archivo
    file = await document.get_file()
    file_content = await file.download_as_bytearray()
    filename = document.file_name if hasattr(document, "file_name") else "archivo.jpg"
    result = await api_metadata_file(file_content, filename)
    await update.message.reply_text(f"📊 *Metadatos del archivo:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)}", parse_mode=ParseMode.MARKDOWN)

async def execute_command(command: str, value: str, update_obj=None) -> dict:
    # Mapeo de comandos a funciones
    func_map = {
        "username": api_username,
        "email": api_email,
        "phone": api_phone,
        "domain": api_domain,
        "portscan": api_portscan,
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
        return {"error": "Comando no reconocido"}
    try:
        return await func_map[command](value)
    except Exception as e:
        return {"error": str(e)}

# Handlers para comandos directos (con argumentos)
async def cmd_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("❌ Uso: `/username <usuario>`", parse_mode=ParseMode.MARKDOWN)
        return
    value = " ".join(context.args)
    result = await api_username(value)
    await update.message.reply_text(f"🔍 *Resultado de username:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}", parse_mode=ParseMode.MARKDOWN)

async def cmd_email(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("❌ Uso: `/email <correo>`", parse_mode=ParseMode.MARKDOWN)
        return
    value = context.args[0]
    result = await api_email(value)
    await update.message.reply_text(f"📧 *Resultado de email:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}", parse_mode=ParseMode.MARKDOWN)

async def cmd_phone(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("❌ Uso: `/phone <número>`", parse_mode=ParseMode.MARKDOWN)
        return
    value = context.args[0]
    result = await api_phone(value)
    await update.message.reply_text(f"📞 *Resultado de phone:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}", parse_mode=ParseMode.MARKDOWN)

# Repetir para todos los comandos (usaré un generador dinámico)
def make_cmd_handler(func, cmd_name):
    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text(f"❌ Uso: `/{cmd_name} <valor>`", parse_mode=ParseMode.MARKDOWN)
            return
        value = " ".join(context.args)
        result = await func(value)
        await update.message.reply_text(f"*Resultado de /{cmd_name}:*\n\n{json.dumps(result, indent=2, ensure_ascii=False)[:4000]}", parse_mode=ParseMode.MARKDOWN)
    return handler

# Mapeo de comandos directos
direct_commands = [
    ("username", api_username),
    ("email", api_email),
    ("phone", api_phone),
    ("domain", api_domain),
    ("portscan", api_portscan),
    ("reputation", api_reputation),
    ("metadata_url", api_metadata_url),
    ("hash", api_hash),
    ("shodan", api_shodan),
    ("dork", api_dork),
    ("bitcoin", api_bitcoin),
    ("breach", api_breach),
    ("ipgeo", api_ipgeo),
    ("mac", api_mac),
    ("subdomains", api_subdomains),
    ("reverse_image", api_reverse_image),
    ("password_check", api_password_check),
    ("ai_threat", api_ai_threat),
    ("js_secrets", api_js_secrets),
    ("wayback", api_wayback),
    ("takeover", api_takeover),
    ("exposed_files", api_exposed_files),
    ("security_headers", api_security_headers),
    ("cve", api_cve),
    ("asn", api_asn),
    ("s3finder", api_s3finder),
    ("cors", api_cors),
    ("github_secrets", api_github_secrets),
    ("tech_detect", api_tech_detect),
]

# ========== MAIN ==========

def main() -> None:
    application = Application.builder().token(TOKEN).build()

    # Conversación para menú interactivo
    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^(username|email|phone|domain|portscan|reputation|metadata_file|metadata_url|hash|shodan|dork|bitcoin|breach|ipgeo|mac|subdomains|reverse_image|password_check|ai_threat|js_secrets|wayback|takeover|exposed_files|security_headers|cve|asn|s3finder|cors|github_secrets|tech_detect)$")],
        states={
            WAITING_FOR_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_value)],
        },
        fallbacks=[CommandHandler("cancel", lambda u, c: u.message.reply_text("❌ Cancelado."))],
    )
    application.add_handler(conv_handler)

    # Comandos directos
    for cmd, func in direct_commands:
        application.add_handler(CommandHandler(cmd, make_cmd_handler(func, cmd)))

    # Comandos especiales
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("email_forensics", make_cmd_handler(api_email_forensics, "email_forensics")))

    # Manejo de archivos
    application.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO, handle_file))

    # Manejo de comandos desconocidos
    async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("❌ Comando no reconocido. Usa /menu.")
    application.add_handler(MessageHandler(filters.COMMAND, unknown))

    # Iniciar
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()