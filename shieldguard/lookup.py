from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import requests

from .i18n import get_lang, t
from .models import ThreatFinding
from .utils import compile_feed_regex, load_threat_feed

# Multilingual built-in knowledge base (vi, en, zh, es, de)
KNOWN_PATTERNS: List[Tuple[re.Pattern[str], Dict[str, Dict[str, str]]]] = [
    (
        re.compile(r"(xmrig|lolminer|gminer|phoenixminer|t-rex|nbminer|rigel|srbminer|winring0)", re.I),
        {
            "vi": {
                "name": "Phần mềm đào tiền ảo (Crypto Miner) / Driver nhân WinRing0",
                "verdict": "NGUY HIỂM — Mã độc đào coin (CPU/GPU)",
                "purpose": "Sử dụng CPU/GPU chạy ngầm để đào tiền ảo cho kẻ tấn công, làm máy nóng, lag và tụt FPS.",
                "recommendation": "Diệt tiến trình, xóa Scheduled Task và xóa/cách ly toàn bộ thư mục chứa file ngay.",
            },
            "en": {
                "name": "Crypto Miner / WinRing0 Kernel Driver",
                "verdict": "DANGEROUS — Unauthorized Crypto-Miner (CPU/GPU)",
                "purpose": "Uses your CPU/GPU in the background to mine cryptocurrency for attackers, causing high heat, lag, and FPS drops.",
                "recommendation": "Kill the process, delete its Scheduled Task, and quarantine/delete the entire folder immediately.",
            },
            "zh": {
                "name": "加密货币挖矿程序 / WinRing0 内核驱动",
                "verdict": "危险 — 后台挖矿木马 (CPU/GPU)",
                "purpose": "在后台占用您的 CPU/GPU 为攻击者挖矿，导致电脑发热、卡顿与帧率下降。",
                "recommendation": "立即结束进程、删除计划任务并隔离或删除整个目录。",
            },
            "es": {
                "name": "Minero de Criptomonedas / Driver WinRing0",
                "verdict": "PELIGROSO — Malware minero (CPU/GPU)",
                "purpose": "Usa tu CPU/GPU en segundo plano para minar criptomonedas para atacantes, causando calor y lentitud.",
                "recommendation": "Finaliza el proceso, elimina la tarea programada y pon en cuarentena/elimina la carpeta.",
            },
            "de": {
                "name": "Krypto-Miner / WinRing0-Treiber",
                "verdict": "GEFÄHRLICH — Unerwünschter Krypto-Miner (CPU/GPU)",
                "purpose": "Nutzt CPU/GPU im Hintergrund zum Schürfen von Kryptowährung, verursacht Hitze und Leistungseinbußen.",
                "recommendation": "Prozess beenden, geplante Aufgabe löschen und den Ordner sofort isolieren/löschen.",
            },
        },
    ),
    (
        re.compile(r"(sysmon\.py|syscheck2|c:\\windows\\systemhealth)", re.I),
        {
            "vi": {
                "name": "Watchdog mã độc ẩn Task Manager (SystemHealth / SysMon)",
                "verdict": "NGUY HIỂM — Thành phần điều khiển mã độc",
                "purpose": "Giả mạo thư mục Windows để chạy ngầm khi khởi động, tự ẩn/dừng miner khi mở Task Manager và có thể kèm infostealer.",
                "recommendation": "Xóa Scheduled Task, diệt tiến trình python.exe liên quan và xóa sạch C:\\Windows\\SystemHealth.",
            },
            "en": {
                "name": "Stealth Malware Watchdog (SystemHealth / SysMon)",
                "verdict": "DANGEROUS — Malware Persistence & Anti-TaskManager Controller",
                "purpose": "Masquerades as a Windows folder, pauses/hides miners when Task Manager opens, and may bundle an infostealer.",
                "recommendation": "Delete the Scheduled Task, kill the python.exe process, and remove C:\\Windows\\SystemHealth.",
            },
            "zh": {
                "name": "隐藏式木马守护进程 (SystemHealth / SysMon)",
                "verdict": "危险 — 恶意软件控制组件",
                "purpose": "伪装成 Windows 系统目录开机自启，打开任务管理器时自动隐藏挖矿进程，并可能附带窃密模块。",
                "recommendation": "删除计划任务，结束相关 python.exe 进程，并彻底删除 C:\\Windows\\SystemHealth。",
            },
            "es": {
                "name": "Watchdog de Malware Oculto (SystemHealth / SysMon)",
                "verdict": "PELIGROSO — Controlador de malware",
                "purpose": "Se disfraza de carpeta de Windows, oculta mineros al abrir el Administrador de tareas y puede robar contraseñas.",
                "recommendation": "Elimina la tarea programada, detén python.exe y borra C:\\Windows\\SystemHealth.",
            },
            "de": {
                "name": "Versteckter Malware-Watchdog (SystemHealth / SysMon)",
                "verdict": "GEFÄHRLICH — Malware-Steuerungskomponente",
                "purpose": "Tarnt sich als Windows-Ordner, versteckt Miner beim Öffnen des Task-Managers und kann Passwörter stehlen.",
                "recommendation": "Geplante Aufgabe löschen, python.exe beenden und C:\\Windows\\SystemHealth entfernen.",
            },
        },
    ),
    (
        re.compile(r"(aact_tools|aact_x64|kmsss\.exe|kmsautos|\\windows\\kms\b|sppextcomobjhook|sppextcomobjpatcher)", re.I),
        {
            "vi": {
                "name": "Công cụ kích hoạt Windows/Office không chính thức (KMS / AAct / HackTool)",
                "verdict": "CẢNH BÁO — Công cụ crack / HackTool (không phải file mặc định của Windows)",
                "purpose": "Dùng để giả lập máy chủ KMS kích hoạt Windows/Office. Công cụ này thường tự thêm ngoại lệ vào Windows Defender để không bị chặn.",
                "recommendation": "Nếu không còn dùng nữa, nên gỡ ngoại lệ Windows Defender để tránh kẻ xấu lợi dụng thư mục bị bỏ qua.",
            },
            "en": {
                "name": "Unofficial Windows/Office Activator (KMS / AAct / HackTool)",
                "verdict": "WARNING — Crack / HackTool (not an official Windows component)",
                "purpose": "Emulates a KMS server to activate Windows/Office. These tools typically add themselves to Windows Defender exclusions.",
                "recommendation": "If you no longer need it, remove the Defender exclusion so real malware cannot abuse the excluded path.",
            },
            "zh": {
                "name": "非官方 Windows/Office 激活工具 (KMS / AAct / HackTool)",
                "verdict": "警告 — 激活工具 / HackTool（非微软官方组件）",
                "purpose": "用于模拟 KMS 服务器激活 Windows 或 Office，通常会自行添加 Windows Defender 排除项以防被拦截。",
                "recommendation": "如果不再使用，建议移除 Defender 排除项，防止真实木马利用排除目录。",
            },
            "es": {
                "name": "Activador no oficial de Windows/Office (KMS / AAct / HackTool)",
                "verdict": "ADVERTENCIA — Herramienta KMS / HackTool (no es oficial de Windows)",
                "purpose": "Emula un servidor KMS para activar Windows/Office y suele añadirse a las exclusiones de Windows Defender.",
                "recommendation": "Si ya no lo usas, elimina la exclusión de Defender para evitar riesgos de seguridad.",
            },
            "de": {
                "name": "Inoffizieller Windows/Office-Aktivator (KMS / AAct / HackTool)",
                "verdict": "WARNUNG — HackTool / Aktivator (keine offizielle Windows-Datei)",
                "purpose": "Emuliert einen KMS-Server zur Aktivierung von Windows/Office und fügt sich oft zu den Defender-Ausnahmen hinzu.",
                "recommendation": "Falls nicht mehr benötigt, entfernen Sie die Defender-Ausnahme, damit echte Malware den Pfad nicht missbraucht.",
            },
        },
    ),
    (
        re.compile(r"(ouninstall|office uninstall)", re.I),
        {
            "vi": {
                "name": "Công cụ gỡ cài đặt Microsoft Office (OUninstall)",
                "verdict": "THẬN TRỌNG — Thường đi kèm bộ cài Office C2R/Tool không chính thức",
                "purpose": "Dùng để gỡ cài đặt các phiên bản Microsoft Office cũ hoặc thiết lập Office.",
                "recommendation": "Nếu đã cài/gỡ xong Office, bạn có thể gỡ ngoại lệ Windows Defender cho an toàn.",
            },
            "en": {
                "name": "Microsoft Office Uninstall Utility (OUninstall)",
                "verdict": "CAUTION — Commonly bundled with unofficial Office C2R installers",
                "purpose": "Used to uninstall older Microsoft Office installations or manage Office packages.",
                "recommendation": "Once finished installing/uninstalling Office, it is safer to remove its Windows Defender exclusion.",
            },
            "zh": {
                "name": "Microsoft Office 卸载工具 (OUninstall)",
                "verdict": "注意 — 常随非官方 Office 安装工具附带",
                "purpose": "用于卸载旧版 Microsoft Office 或配置 Office 安装包。",
                "recommendation": "如已完成安装或卸载，建议移除其在 Windows Defender 中的排除项。",
            },
            "es": {
                "name": "Utilidad de desinstalación de Microsoft Office (OUninstall)",
                "verdict": "PRECAUCIÓN — Suele incluirse con instaladores C2R no oficiales de Office",
                "purpose": "Sirve para desinstalar versiones antiguas de Microsoft Office.",
                "recommendation": "Si ya terminaste de instalar/desinstalar Office, conviene quitar su exclusión de Defender.",
            },
            "de": {
                "name": "Microsoft Office Deinstallations-Tool (OUninstall)",
                "verdict": "VORSICHT — Oft Teil inoffizieller Office-C2R-Installer",
                "purpose": "Wird zum Entfernen älterer Microsoft Office-Installationen verwendet.",
                "recommendation": "Nach Abschluss der Office-Installation empfiehlt es sich, die Defender-Ausnahme zu entfernen.",
            },
        },
    ),
    (
        re.compile(r"(jetbrains|intellij|pycharm|webstorm|ideaprojects|androidstudio|\.gradle)", re.I),
        {
            "vi": {
                "name": "Môi trường lập trình JetBrains / IntelliJ IDEA / Dự án code",
                "verdict": "AN TOÀN — Phần mềm lập trình hợp lệ",
                "purpose": "Thư mục IDE JetBrains hoặc thư mục mã nguồn dự án. IDE tự đề xuất thêm ngoại lệ Defender để biên dịch nhanh hơn.",
                "recommendation": "An toàn — có thể giữ nguyên, không cần xóa.",
            },
            "en": {
                "name": "JetBrains IDE / IntelliJ IDEA / Source Code Project",
                "verdict": "SAFE — Legitimate Developer Tool",
                "purpose": "JetBrains IDE cache or project folder. JetBrains IDEs automatically offer to add Defender exclusions for faster builds.",
                "recommendation": "Safe — you can keep this exclusion.",
            },
            "zh": {
                "name": "JetBrains / IntelliJ IDEA 开发环境或代码项目",
                "verdict": "安全 — 合法开发工具",
                "purpose": "JetBrains IDE 缓存或项目目录，IDE 会自动建议添加到 Defender 排除项以加快编译速度。",
                "recommendation": "安全 — 可以保留，无需删除。",
            },
            "es": {
                "name": "IDE JetBrains / IntelliJ IDEA / Proyecto de código",
                "verdict": "SEGURO — Herramienta de desarrollo legítima",
                "purpose": "Carpeta de caché o proyecto de JetBrains. El IDE sugiere excluirla de Defender para compilar más rápido.",
                "recommendation": "Seguro — puedes mantenerla sin problemas.",
            },
            "de": {
                "name": "JetBrains IDE / IntelliJ IDEA / Quellcode-Projekt",
                "verdict": "SICHER — Legitimes Entwicklerwerkzeug",
                "purpose": "JetBrains-IDE-Cache oder Projektordner. Die IDE schlägt Defender-Ausnahmen für schnellere Builds vor.",
                "recommendation": "Sicher — kann beibehalten werden.",
            },
        },
    ),
    (
        re.compile(r"(unityengine\.|unity\.splines|assembly-csharp\.dll)", re.I),
        {
            "vi": {
                "name": "Thư viện chuẩn của Game Unity Engine",
                "verdict": "AN TOÀN — Thành phần game hợp lệ (Steam)",
                "purpose": "DLL chuẩn do Unity Engine tạo ra khi biên dịch game.",
                "recommendation": "An toàn — không cần cách ly hay xóa.",
            },
            "en": {
                "name": "Standard Unity Engine Game Library",
                "verdict": "SAFE — Legitimate Steam Game Component",
                "purpose": "Standard DLL compiled by the Unity Engine for game graphics, particles, splines, and game logic.",
                "recommendation": "Safe — do not quarantine or delete (doing so will break the game).",
            },
            "zh": {
                "name": "Unity 引擎标准游戏库文件",
                "verdict": "安全 — 合法 Steam 游戏组件",
                "purpose": "Unity 游戏引擎编译生成的标准 DLL（图形、粒子、样条线与游戏逻辑）。",
                "recommendation": "安全 — 请勿隔离或删除，否则游戏无法运行。",
            },
            "es": {
                "name": "Biblioteca estándar de juegos Unity Engine",
                "verdict": "SEGURO — Componente legítimo de juego (Steam)",
                "purpose": "DLL estándar generada por Unity Engine para gráficos y lógica del juego.",
                "recommendation": "Seguro — no eliminar ni poner en cuarentena.",
            },
            "de": {
                "name": "Standard-Bibliothek der Unity Game Engine",
                "verdict": "SICHER — Legitime Steam-Spielkomponente",
                "purpose": "Standard-DLL der Unity Engine für Grafik, Partikel und Spiellogik.",
                "recommendation": "Sicher — nicht löschen oder isolieren.",
            },
        },
    ),
]


def check_internet(timeout: float = 3.0) -> bool:
    """Quickly verify whether the machine has active Internet connectivity."""
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def extract_lookup_subject(finding: ThreatFinding) -> str:
    """Extract the most meaningful filename or component name from a ThreatFinding."""
    raw = (finding.details.get("path") or finding.target or finding.display_title).strip().strip('"')
    cleaned = raw.rstrip("\\/")
    if "\\" in cleaned or "/" in cleaned:
        parts = [p for p in re.split(r"[\\/]", cleaned) if p]
        if parts:
            return parts[-1]
    return cleaned or finding.display_title


_KB_FEED_CACHE: Tuple[Any, List[Tuple[re.Pattern[str], Dict[str, Dict[str, str]]]]] = (None, [])


def _get_feed_knowledge_patterns() -> List[Tuple[re.Pattern[str], Dict[str, Dict[str, str]]]]:
    global _KB_FEED_CACHE
    feed = load_threat_feed()
    if _KB_FEED_CACHE[0] is feed:
        return _KB_FEED_CACHE[1]
    out: List[Tuple[re.Pattern[str], Dict[str, Dict[str, str]]]] = []
    for entry in feed.get("knowledge_base") or []:
        if not isinstance(entry, dict):
            continue
        pat = compile_feed_regex(str(entry.get("pattern", "")), re.I)
        locales = entry.get("locales")
        if pat and isinstance(locales, dict):
            out.append((pat, locales))
    _KB_FEED_CACHE = (feed, out)
    return out


def lookup_local_knowledge(finding: ThreatFinding) -> Optional[Dict[str, str]]:
    """Match against built-in local knowledge base and threat feed in the active UI language."""
    haystack = f"{finding.display_title} {finding.target} {finding.display_reason} {finding.details}"
    lang = get_lang()
    for pattern, localized in KNOWN_PATTERNS + _get_feed_knowledge_patterns():
        if pattern.search(haystack):
            return localized.get(lang) or localized.get("en") or localized.get("vi")
    return None


def _query_duckduckgo_web(subject: str) -> Optional[str]:
    try:
        resp = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": subject, "format": "json", "no_html": 1, "skip_disambig": 1},
            headers={"User-Agent": "ShieldGuard/1.0"},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        abstract = (data.get("AbstractText") or "").strip()
        if abstract:
            src = data.get("AbstractSource") or "DuckDuckGo"
            return f"[{src}] {abstract}"
        for topic in data.get("RelatedTopics") or []:
            if isinstance(topic, dict) and topic.get("Text"):
                return f"[DuckDuckGo] {topic['Text']}"
    except Exception:
        pass
    return None


def _query_wikipedia(subject: str) -> Optional[str]:
    clean_name = re.sub(r"\.(exe|dll|sys|ps1|py|bat|vbs|cmd)$", "", subject, flags=re.I).strip()
    if len(clean_name) < 3:
        return None
    lang = get_lang()
    langs = [lang, "en"] if lang != "en" else ["en"]
    for wl in langs:
        try:
            r = requests.get(
                f"https://{wl}.wikipedia.org/w/api.php",
                params={
                    "action": "query",
                    "list": "search",
                    "srsearch": f"{clean_name} windows software",
                    "format": "json",
                    "srlimit": 1,
                },
                headers={"User-Agent": "ShieldGuard/1.0"},
                timeout=6,
            )
            if r.status_code != 200:
                continue
            hits = r.json().get("query", {}).get("search", [])
            if not hits:
                continue
            title = hits[0].get("title", "")
            snippet = re.sub(r"<[^>]+>", "", hits[0].get("snippet", "")).strip()
            if clean_name.lower() in title.lower() or clean_name.lower() in snippet.lower():
                return f"[Wikipedia ({wl.upper()}) - {title}] {snippet}..."
        except Exception:
            continue
    return None


def _query_gemini_ai(finding: ThreatFinding, subject: str, api_key: str) -> Optional[str]:
    if not api_key:
        return None
    lang_names = {
        "vi": "Vietnamese",
        "en": "English",
        "zh": "Simplified Chinese",
        "es": "Spanish",
        "de": "German",
    }
    out_lang = lang_names.get(get_lang(), "English")
    prompt = (
        f"You are a Windows security expert. Reply concisely in {out_lang} (max 5 lines) explaining "
        "what this file/item does, whether it is safe or malware/virus, and what the user should do:\n"
        f"- Subject: {subject}\n"
        f"- Target/Path: {finding.target}\n"
        f"- Category: {finding.category.label_vi}\n"
        f"- Scanner reason: {finding.display_reason}\n"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key.strip()}"
    try:
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=15,
        )
        if resp.status_code != 200:
            return f"[AI] Gemini API error (HTTP {resp.status_code}). Check API Key."
        candidates = resp.json().get("candidates") or []
        if candidates:
            parts = candidates[0].get("content", {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts).strip()
            if text:
                return text
    except Exception as exc:
        return f"[AI] Gemini connection error: {exc}"
    return None


def build_google_search_url(finding: ThreatFinding) -> str:
    subject = extract_lookup_subject(finding)
    suffix = {
        "vi": "là gì an toàn hay virus windows",
        "en": "what is it safe or virus windows",
        "zh": "是什么 安全还是病毒 windows",
        "es": "que es seguro o virus windows",
        "de": "was ist das sicher oder virus windows",
    }.get(get_lang(), "what is it safe or virus windows")
    query = f'"{subject}" {suffix}'
    return f"https://www.google.com/search?q={quote_plus(query)}"


def lookup_finding_info(finding: ThreatFinding, gemini_api_key: str = "") -> Dict[str, Any]:
    subject = extract_lookup_subject(finding)
    local_info = lookup_local_knowledge(finding)
    online = check_internet()

    def _kb_lines(info: Dict[str, str]) -> List[str]:
        return [
            t("lkp_lbl_name", val=info["name"]),
            t("lkp_lbl_verdict", val=info["verdict"]),
            t("lkp_lbl_purpose", val=info["purpose"]),
            t("lkp_lbl_rec", val=info["recommendation"]),
        ]

    if not online:
        lines = [t("lkp_offline_hdr"), ""]
        if local_info:
            lines.append(t("lkp_offline_kb"))
            lines.extend(_kb_lines(local_info))
        else:
            lines.append(t("lkp_offline_none", subject=subject))
        return {"online": False, "subject": subject, "report": "\n".join(lines)}

    sections: List[str] = [t("lkp_subject", subject=subject), ""]

    if local_info:
        sections.append(t("lkp_sec_kb"))
        sections.extend(_kb_lines(local_info))
        sections.append("")

    if gemini_api_key.strip():
        ai_text = _query_gemini_ai(finding, subject, gemini_api_key)
        if ai_text:
            sections.extend([t("lkp_sec_ai"), ai_text, ""])

    web_summary = _query_duckduckgo_web(subject) or _query_wikipedia(subject)
    if web_summary:
        sections.extend([t("lkp_sec_web"), web_summary, ""])
    elif not local_info and not gemini_api_key.strip():
        sections.extend([t("lkp_sec_web"), t("lkp_web_none", subject=subject), ""])

    return {"online": True, "subject": subject, "report": "\n".join(sections).strip()}
