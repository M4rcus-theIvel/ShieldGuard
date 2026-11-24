from __future__ import annotations

from pathlib import Path
import subprocess
import threading
from tkinter import filedialog, messagebox
from typing import Any, Callable, Dict, List, Optional
import webbrowser

import customtkinter as ctk

from . import __app_name__, __version__
from .exporter import default_log_filename, export_findings_log
from .i18n import LANG_CODE_TO_LABEL, LANG_LABEL_TO_CODE, LANGUAGES, get_lang, init_language, set_lang, t
from .lookup import build_google_search_url, lookup_finding_info
from .models import ThreatCategory, ThreatFinding
from .quarantine import (
    delete_quarantine_item_permanently,
    load_history,
    load_quarantine_items,
    remediate_finding,
    restore_quarantine_item,
)
from .scanner_defender import scan_defender
from .scanner_files import (
    check_virustotal_hash,
    quick_scan_hotspot_folders,
    scan_path_heuristics,
    scan_with_defender_cli,
)
from .scanner_persistence import scan_persistence
from .scanner_processes import query_nvidia_gpu_status, scan_processes
from .updater import check_github_update
from .utils import compute_sha256, format_bytes, is_admin, load_config, relaunch_as_admin, save_config

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG_SIDEBAR = "#0f172a"
BG_MAIN = "#111827"
BG_CARD = "#1e293b"
BG_ROW = "#172033"
ACCENT = "#2563eb"
ACCENT_HOVER = "#1d4ed8"
DANGER = "#dc2626"
DANGER_HOVER = "#b91c1c"
SUCCESS = "#16a34a"
WARNING = "#d97706"
TEXT_MUTED = "#94a3b8"


class FindingDetailDialog(ctk.CTkToplevel):
    """Popup window showing full finding details with selectable/copyable text and online/AI lookup."""

    def __init__(self, master: "ShieldGuardApp", finding: ThreatFinding) -> None:
        super().__init__(master)
        self.app_master = master
        self.finding = finding
        self.title(t("detail_win_title", cat=finding.category.label_vi))
        self.geometry("820x600")
        self.minsize(640, 460)
        self.configure(fg_color=BG_MAIN)
        self.transient(master)
        self.grab_set()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top header
        top = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8)
        top.grid(row=0, column=0, padx=16, pady=(14, 8), sticky="ew")
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top,
            text=finding.severity.label_vi.upper(),
            width=100,
            corner_radius=6,
            fg_color=finding.severity.color,
            text_color="#ffffff",
            font=ctk.CTkFont(size=11, weight="bold"),
            pady=4,
        ).grid(row=0, column=0, padx=(12, 10), pady=12, sticky="nw")

        ctk.CTkLabel(
            top,
            text=f"[{finding.category.label_vi}] {finding.display_title}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f8fafc",
            anchor="w",
            justify="left",
            wraplength=640,
        ).grid(row=0, column=1, padx=(0, 12), pady=12, sticky="ew")

        # Full copyable textbox
        self.full_text = self._format_full_report(finding)
        self.textbox = ctk.CTkTextbox(
            self,
            fg_color=BG_ROW,
            text_color="#e2e8f0",
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            corner_radius=8,
            border_width=1,
            border_color="#334155",
        )
        self.textbox.grid(row=1, column=0, padx=16, pady=6, sticky="nsew")
        self.textbox.insert("1.0", self.full_text)
        self.textbox.bind("<Key>", lambda e: "break" if not (e.state & 0x4 and e.keysym.lower() in ("c", "a")) else None)

        # Optional Gemini AI key row
        ai_bar = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8)
        ai_bar.grid(row=2, column=0, padx=16, pady=(4, 4), sticky="ew")
        ai_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            ai_bar,
            text=t("ai_key_label"),
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(10, 6), pady=7)
        self.entry_ai_key = ctk.CTkEntry(
            ai_bar,
            show="*",
            height=28,
            placeholder_text=t("ai_key_ph"),
        )
        self.entry_ai_key.grid(row=0, column=1, padx=(0, 6), pady=7, sticky="ew")
        if master.config_data.get("gemini_api_key"):
            self.entry_ai_key.insert(0, master.config_data["gemini_api_key"])
        ctk.CTkButton(
            ai_bar,
            text=t("btn_save"),
            width=70,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            command=self._save_ai_key,
        ).grid(row=0, column=2, padx=(0, 10), pady=7)

        # Bottom action bar
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=3, column=0, padx=16, pady=(6, 14), sticky="ew")

        self.btn_lookup = ctk.CTkButton(
            bar,
            text=t("btn_lookup"),
            width=155,
            height=34,
            fg_color="#6d28d9",
            hover_color="#5b21b6",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._run_lookup,
        )
        self.btn_lookup.pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            bar,
            text=t("btn_google"),
            width=115,
            height=34,
            fg_color="#0f766e",
            hover_color="#115e59",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: webbrowser.open(build_google_search_url(finding)),
        ).pack(side="left", padx=(0, 6))

        self.btn_copy_all = ctk.CTkButton(
            bar,
            text=t("btn_copy_all"),
            width=115,
            height=34,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._copy_all,
        )
        self.btn_copy_all.pack(side="left", padx=(0, 6))

        self.btn_copy_target = ctk.CTkButton(
            bar,
            text=t("btn_copy_target"),
            width=110,
            height=34,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._copy_target,
        )
        self.btn_copy_target.pack(side="left", padx=(0, 6))

        target_path = Path(finding.details.get("path") or finding.target)
        if target_path.exists():
            ctk.CTkButton(
                bar,
                text=t("btn_open_folder"),
                width=115,
                height=34,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda p=target_path: self._reveal_in_explorer(p),
            ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            bar,
            text=t("btn_close"),
            width=80,
            height=34,
            fg_color="#475569",
            hover_color="#64748b",
            command=self.destroy,
        ).pack(side="right")

    def _save_ai_key(self) -> None:
        self.app_master.config_data["gemini_api_key"] = self.entry_ai_key.get().strip()
        save_config(self.app_master.config_data)
        messagebox.showinfo(__app_name__, t("ai_key_saved"))

    def _run_lookup(self) -> None:
        self.btn_lookup.configure(state="disabled", text=t("btn_looking_up"))
        ai_key = self.entry_ai_key.get().strip()

        def _job() -> None:
            res = lookup_finding_info(self.finding, gemini_api_key=ai_key)

            def _done() -> None:
                if not self.winfo_exists():
                    return
                self.btn_lookup.configure(state="normal", text=t("btn_lookup"))
                if not res.get("online"):
                    messagebox.showwarning(t("offline_title"), t("offline_msg"))
                base_report = self._format_full_report(self.finding)
                self.full_text = (
                    base_report
                    + "\n\n==================================================\n"
                    + t("lookup_header")
                    + "\n==================================================\n"
                    + res.get("report", "")
                )
                self.textbox.delete("1.0", "end")
                self.textbox.insert("1.0", self.full_text)
                self.textbox.see("end")

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    @staticmethod
    def _format_full_report(f: ThreatFinding) -> str:
        lines = [
            f"{t('rpt_title'):<14}: {f.display_title}",
            f"{t('rpt_severity'):<14}: {f.severity.label_vi} ({f.severity.value})",
            f"{t('rpt_category'):<14}: {f.category.label_vi} ({f.category.value})",
            f"{t('rpt_time'):<14}: {f.detected_at}",
            f"{t('rpt_status'):<14}: {t('rpt_status_done') if f.remediated else t('rpt_status_open')}",
            "",
            t("rpt_sec_target"),
            f.target,
            "",
            t("rpt_sec_reason"),
            f.display_reason,
        ]
        if f.details:
            lines.append("")
            lines.append(t("rpt_sec_tech"))
            for k, v in f.details.items():
                if v not in (None, "", []):
                    lines.append(f"{k}: {v}")
        return "\n".join(lines)

    def _copy_all(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.full_text)
        self.update()
        self.btn_copy_all.configure(text=t("btn_copied"))
        self.after(1600, lambda: self.btn_copy_all.configure(text=t("btn_copy_all")))

    def _copy_target(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.finding.target)
        self.update()
        self.btn_copy_target.configure(text=t("btn_copied"))
        self.after(1600, lambda: self.btn_copy_target.configure(text=t("btn_copy_target")))

    @staticmethod
    def _reveal_in_explorer(p: Path) -> None:
        try:
            if p.is_file():
                subprocess.Popen(["explorer.exe", "/select,", str(p)])
            else:
                subprocess.Popen(["explorer.exe", str(p)])
        except Exception:
            pass


class ShieldGuardApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        init_language()
        self.geometry("1160x740")
        self.minsize(980, 640)
        self.configure(fg_color=BG_MAIN)

        self.admin_mode = is_admin()
        self.config_data = load_config()
        self.scan_busy = False
        self.cancel_event = threading.Event()
        self.active_page = "dashboard"

        self.all_findings: List[ThreatFinding] = []
        self.proc_findings: List[ThreatFinding] = []
        self.persist_findings: List[ThreatFinding] = []
        self.defender_findings: List[ThreatFinding] = []
        self.file_findings: List[ThreatFinding] = []
        self.last_gpu_info: Dict[str, Any] = {}
        self.last_defender_status: Dict[str, Any] = {}

        self.nav_buttons: Dict[str, ctk.CTkButton] = {}
        self.pages: Dict[str, ctk.CTkFrame] = {}

        self._build_layout()
        self._select_page(self.active_page)
        self._refresh_gpu_badge_async()

    # ------------------------------------------------------------------ Layout
    def _build_layout(self) -> None:
        self.title(t("window_title", app=__app_name__, ver=__version__))
        for child in self.winfo_children():
            child.destroy()
        self.nav_buttons.clear()
        self.pages.clear()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=BG_SIDEBAR)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(8, weight=1)

        ctk.CTkLabel(
            sidebar,
            text=f"🛡️ {__app_name__}",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#f8fafc",
        ).grid(row=0, column=0, padx=20, pady=(20, 2), sticky="w")

        ctk.CTkLabel(
            sidebar,
            text=t("subtitle", ver=__version__),
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
        ).grid(row=1, column=0, padx=20, pady=(0, 14), sticky="w")

        nav_items = [
            ("dashboard", t("nav_dashboard")),
            ("processes", t("nav_processes")),
            ("persistence", t("nav_persistence")),
            ("defender", t("nav_defender")),
            ("files", t("nav_files")),
            ("quarantine", t("nav_quarantine")),
        ]
        for idx, (key, label) in enumerate(nav_items, start=2):
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                height=38,
                corner_radius=8,
                fg_color="transparent",
                hover_color="#1e293b",
                text_color="#e2e8f0",
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda k=key: self._select_page(k),
            )
            btn.grid(row=idx, column=0, padx=12, pady=3, sticky="ew")
            self.nav_buttons[key] = btn

        # Language switcher & Update check card
        lang_frame = ctk.CTkFrame(sidebar, fg_color=BG_CARD, corner_radius=10)
        lang_frame.grid(row=9, column=0, padx=12, pady=(8, 8), sticky="ew")
        ctk.CTkLabel(
            lang_frame,
            text=t("lang_label"),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(padx=12, pady=(8, 4), anchor="w")
        lang_labels = [lbl for _, lbl in LANGUAGES]
        self.lang_menu = ctk.CTkOptionMenu(
            lang_frame,
            values=lang_labels,
            height=30,
            fg_color="#334155",
            button_color=ACCENT,
            button_hover_color=ACCENT_HOVER,
            command=self._on_language_change,
        )
        self.lang_menu.set(LANG_CODE_TO_LABEL.get(get_lang(), "Tiếng Việt"))
        self.lang_menu.pack(padx=12, pady=(0, 8), fill="x")

        self.btn_update = ctk.CTkButton(
            lang_frame,
            text=t("btn_check_update"),
            height=30,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._check_updates_now,
        )
        self.btn_update.pack(padx=12, pady=(0, 10), fill="x")

        # Admin status card
        admin_frame = ctk.CTkFrame(sidebar, fg_color=BG_CARD, corner_radius=10)
        admin_frame.grid(row=10, column=0, padx=12, pady=(0, 14), sticky="ew")

        badge_text = t("admin_ok") if self.admin_mode else t("admin_user")
        badge_color = "#4ade80" if self.admin_mode else "#fbbf24"
        ctk.CTkLabel(
            admin_frame,
            text=badge_text,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=badge_color,
        ).pack(padx=12, pady=(10, 4), anchor="w")

        if not self.admin_mode:
            ctk.CTkLabel(
                admin_frame,
                text=t("admin_need_desc"),
                font=ctk.CTkFont(size=11),
                text_color=TEXT_MUTED,
                justify="left",
            ).pack(padx=12, pady=(0, 8), anchor="w")
            ctk.CTkButton(
                admin_frame,
                text=t("btn_elevate"),
                height=32,
                fg_color=WARNING,
                hover_color="#b45309",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=self._elevate_now,
            ).pack(padx=12, pady=(0, 10), fill="x")
        else:
            ctk.CTkLabel(
                admin_frame,
                text=t("admin_ok_desc"),
                font=ctk.CTkFont(size=11),
                text_color=TEXT_MUTED,
            ).pack(padx=12, pady=(0, 10), anchor="w")

        # Main container
        self.main_area = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.main_area.grid(row=0, column=1, sticky="nsew")
        self.main_area.grid_columnconfigure(0, weight=1)
        self.main_area.grid_rowconfigure(0, weight=1)

        self._build_dashboard_page()
        self._build_processes_page()
        self._build_persistence_page()
        self._build_defender_page()
        self._build_files_page()
        self._build_quarantine_page()

        # Re-populate existing results if any (e.g. after switching language)
        if self.all_findings:
            self._render_findings_list(self.dash_list, self.all_findings, on_after_remediate=self._rerender_dashboard)
        if self.proc_findings:
            self._rerender_proc()
        if self.persist_findings:
            self._rerender_persist()
        if self.last_defender_status:
            self._render_defender_results()
        if self.file_findings:
            self._rerender_files()
        if self.last_gpu_info.get("available"):
            g = self.last_gpu_info
            self.lbl_metric_gpu.configure(text=f"{g['util_pct']}% | {g['temp_c']}°C")
        self._update_dashboard_metrics()

    def _on_language_change(self, selected_label: str) -> None:
        code = LANG_LABEL_TO_CODE.get(selected_label, "vi")
        if code == get_lang():
            return
        set_lang(code)
        self.config_data["language"] = code
        self._build_layout()
        self._select_page(self.active_page)

    def _select_page(self, key: str) -> None:
        self.active_page = key
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color=ACCENT if k == key else "transparent")
        for k, frame in self.pages.items():
            if k == key:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()
        if key == "quarantine":
            self._render_quarantine_page()

    def _elevate_now(self) -> None:
        if relaunch_as_admin():
            self.destroy()
        else:
            messagebox.showwarning(__app_name__, t("uac_fail"))

    def _check_updates_now(self) -> None:
        self.btn_update.configure(state="disabled", text=t("upd_checking"))

        def _job() -> None:
            res = check_github_update()

            def _done() -> None:
                if not self.winfo_exists():
                    return
                self.btn_update.configure(state="normal", text=t("btn_check_update"))
                if not res.get("configured", True):
                    messagebox.showinfo(__app_name__, t("upd_not_cfg"))
                    return
                if not res.get("ok"):
                    if res.get("offline"):
                        messagebox.showwarning(t("offline_title"), t("offline_msg"))
                    else:
                        messagebox.showwarning(__app_name__, t("upd_err", err=res.get("error", "")))
                    return
                if not res.get("has_update"):
                    messagebox.showinfo(__app_name__, t("upd_latest", cur=res["current_version"]))
                    return
                notes = res.get("notes") or "-"
                if messagebox.askyesno(
                    __app_name__,
                    t("upd_available", latest=res["latest_version"], cur=res["current_version"], notes=notes),
                ):
                    webbrowser.open(res["download_url"])

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    # --------------------------------------------------------- Helper UI Cards
    def _create_metric_card(self, parent: ctk.CTkFrame, title: str, value: str, color: str) -> ctk.CTkLabel:
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12)
        card.pack(side="left", fill="both", expand=True, padx=6)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color=TEXT_MUTED).pack(
            padx=14, pady=(12, 2), anchor="w"
        )
        val_lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=20, weight="bold"), text_color=color)
        val_lbl.pack(padx=14, pady=(0, 12), anchor="w")
        return val_lbl

    def _render_findings_list(
        self,
        container: ctk.CTkScrollableFrame,
        findings: List[ThreatFinding],
        on_after_remediate: Optional[Callable[[], None]] = None,
    ) -> None:
        for w in container.winfo_children():
            w.destroy()

        if not findings:
            ctk.CTkLabel(
                container,
                text=t("no_threats"),
                font=ctk.CTkFont(size=14),
                text_color="#4ade80",
            ).pack(pady=36)
            return

        # Multi-select batch toolbar at the top of the list
        active_findings = [f for f in findings if not f.remediated]
        check_vars: Dict[str, ctk.BooleanVar] = {}

        if active_findings:
            toolbar = ctk.CTkFrame(container, fg_color="#1e293b", corner_radius=0)
            toolbar.pack(fill="x", padx=2, pady=(0, 2))

            btn_fix_sel = ctk.CTkButton(
                toolbar,
                text=t("btn_fix_selected", n=0),
                height=30,
                width=165,
                corner_radius=4,
                fg_color=DANGER,
                hover_color=DANGER_HOVER,
                state="disabled",
                font=ctk.CTkFont(size=12, weight="bold"),
            )
            btn_fix_sel.pack(side="right", padx=(6, 10), pady=6)

            def _sync_sel_btn() -> None:
                cnt = sum(1 for v in check_vars.values() if v.get())
                btn_fix_sel.configure(
                    text=t("btn_fix_selected", n=cnt),
                    state="normal" if cnt > 0 else "disabled",
                )

            def _set_all(val: bool) -> None:
                for v in check_vars.values():
                    v.set(val)
                _sync_sel_btn()

            def _fix_selected() -> None:
                chosen = [f for f in active_findings if check_vars.get(f.id) and check_vars[f.id].get()]
                if not chosen:
                    return
                self._remediate_batch(chosen, after_cb=on_after_remediate)

            btn_fix_sel.configure(command=_fix_selected)

            ctk.CTkButton(
                toolbar,
                text=t("btn_select_all"),
                height=30,
                width=125,
                corner_radius=4,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda: _set_all(True),
            ).pack(side="left", padx=(10, 6), pady=6)

            ctk.CTkButton(
                toolbar,
                text=t("btn_deselect_all"),
                height=30,
                width=105,
                corner_radius=4,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=12),
                command=lambda: _set_all(False),
            ).pack(side="left", padx=0, pady=6)

            ctk.CTkFrame(container, height=1, corner_radius=0, fg_color="#334155").pack(fill="x", padx=2)
        else:
            def _sync_sel_btn() -> None:
                pass

        for idx, f in enumerate(findings):
            row_bg = BG_ROW if idx % 2 == 0 else "#1a253a"
            row = ctk.CTkFrame(container, fg_color=row_bg, corner_radius=0, border_width=0)
            row.pack(fill="x", padx=2, pady=0)
            row.grid_columnconfigure(2, weight=1)

            var = ctk.BooleanVar(value=False)
            if not f.remediated:
                check_vars[f.id] = var
            cb = ctk.CTkCheckBox(
                row,
                text="",
                variable=var,
                width=24,
                checkbox_width=20,
                checkbox_height=20,
                state="disabled" if f.remediated else "normal",
                command=_sync_sel_btn,
            )
            cb.grid(row=0, column=0, rowspan=2, padx=(10, 4), pady=12, sticky="n")

            ctk.CTkLabel(
                row,
                text=f.severity.label_vi.upper(),
                width=94,
                corner_radius=4,
                fg_color=f.severity.color,
                text_color="#ffffff",
                font=ctk.CTkFont(size=11, weight="bold"),
                pady=4,
            ).grid(row=0, column=1, rowspan=2, padx=(4, 10), pady=12, sticky="n")

            title_text = f"[{f.category.label_vi}] {f.display_title}"
            if f.remediated:
                title_text = t("remediated_prefix") + title_text
            ctk.CTkLabel(
                row,
                text=title_text,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#4ade80" if f.remediated else "#f8fafc",
                anchor="w",
                justify="left",
                wraplength=490,
            ).grid(row=0, column=2, padx=4, pady=(10, 2), sticky="ew")

            reason_str = f.display_reason
            target_preview = f.target if len(f.target) <= 130 else f.target[:127] + "..."
            reason_preview = reason_str if len(reason_str) <= 190 else reason_str[:187] + "..."
            detail_text = f"{t('lbl_target')}: {target_preview}\n{t('lbl_reason')}: {reason_preview}"
            ctk.CTkLabel(
                row,
                text=detail_text,
                font=ctk.CTkFont(size=12),
                text_color=TEXT_MUTED,
                anchor="w",
                justify="left",
                wraplength=490,
            ).grid(row=1, column=2, padx=4, pady=(0, 10), sticky="ew")

            btn_col = ctk.CTkFrame(row, fg_color="transparent", corner_radius=0)
            btn_col.grid(row=0, column=3, rowspan=2, padx=(6, 12), pady=10, sticky="e")

            ctk.CTkButton(
                btn_col,
                text=t("btn_details"),
                width=140,
                height=30,
                corner_radius=4,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda finding=f: FindingDetailDialog(self, finding),
            ).pack(pady=(0, 6))

            action_label = self._remediate_button_label(f.category)
            ctk.CTkButton(
                btn_col,
                text=t("act_done") if f.remediated else action_label,
                width=140,
                height=30,
                corner_radius=4,
                state="disabled" if f.remediated else "normal",
                fg_color="#334155" if f.remediated else DANGER,
                hover_color=DANGER_HOVER,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda finding=f, cb=on_after_remediate: self._handle_remediate_one(finding, cb),
            ).pack()

            ctk.CTkFrame(container, height=1, corner_radius=0, fg_color="#263248").pack(fill="x", padx=2, pady=0)

        try:
            container._parent_canvas.yview_moveto(0)
            container.update_idletasks()
        except Exception:
            pass

    @staticmethod
    def _remediate_button_label(cat: ThreatCategory) -> str:
        return t(f"act_{cat.value}")

    def _handle_remediate_one(
        self, finding: ThreatFinding, after_cb: Optional[Callable[[], None]] = None
    ) -> None:
        if not messagebox.askyesno(
            __app_name__,
            t("confirm_remediate", title=finding.title, target=finding.target),
        ):
            return
        ok, msg = remediate_finding(finding)
        if ok:
            messagebox.showinfo(__app_name__, msg)
        else:
            messagebox.showerror(__app_name__, msg)
        if after_cb:
            after_cb()
        self._update_dashboard_metrics()

    # --------------------------------------------------------------- Page 1: Dashboard
    def _build_dashboard_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["dashboard"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.grid(row=0, column=0, padx=24, pady=(20, 10), sticky="ew")

        ctk.CTkLabel(
            header,
            text=t("dash_title"),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#f8fafc",
        ).pack(side="left")

        btn_box = ctk.CTkFrame(header, fg_color="transparent")
        btn_box.pack(side="right")

        self.btn_fix_all = ctk.CTkButton(
            btn_box,
            text=t("btn_fix_all"),
            height=40,
            width=135,
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled",
            command=self._remediate_all_dashboard,
        )
        self.btn_fix_all.pack(side="right", padx=(8, 0))

        self.btn_export_dash = ctk.CTkButton(
            btn_box,
            text=t("btn_export_log"),
            height=40,
            width=125,
            fg_color="#0f766e",
            hover_color="#115e59",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._export_log(self.all_findings, "Full System Scan"),
        )
        self.btn_export_dash.pack(side="right", padx=(8, 0))

        self.btn_full_scan = ctk.CTkButton(
            btn_box,
            text=t("btn_full_scan"),
            height=40,
            width=185,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._run_full_scan,
        )
        self.btn_full_scan.pack(side="right")

        metrics = ctk.CTkFrame(page, fg_color="transparent")
        metrics.grid(row=1, column=0, padx=18, pady=6, sticky="ew")
        self.lbl_metric_threats = self._create_metric_card(metrics, t("metric_threats"), "0", "#4ade80")
        self.lbl_metric_gpu = self._create_metric_card(metrics, t("metric_gpu"), t("checking"), "#38bdf8")
        self.lbl_metric_quarantine = self._create_metric_card(
            metrics, t("metric_quarantine"), str(len(load_quarantine_items())), "#fbbf24"
        )

        prog_box = ctk.CTkFrame(page, fg_color=BG_CARD, corner_radius=10)
        prog_box.grid(row=2, column=0, padx=24, pady=(8, 8), sticky="ew")
        self.lbl_dash_status = ctk.CTkLabel(
            prog_box,
            text=t("dash_ready"),
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1",
            anchor="w",
        )
        self.lbl_dash_status.pack(padx=14, pady=(10, 4), fill="x")
        self.dash_progress = ctk.CTkProgressBar(prog_box, height=8)
        self.dash_progress.set(0)
        self.dash_progress.pack(padx=14, pady=(0, 10), fill="x")

        self.dash_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.dash_list.grid(row=3, column=0, padx=24, pady=(4, 20), sticky="nsew")
        ctk.CTkLabel(
            self.dash_list,
            text=t("dash_empty"),
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
        ).pack(pady=40)

    def _refresh_gpu_badge_async(self) -> None:
        def _job() -> None:
            gpu = query_nvidia_gpu_status()
            self.last_gpu_info = gpu
            if gpu.get("available"):
                txt = f"{gpu['util_pct']}% | {gpu['temp_c']}°C"
                col = "#ef4444" if gpu["util_pct"] >= 80 else "#38bdf8"
            else:
                txt = t("no_nvidia")
                col = TEXT_MUTED
            self.after(0, lambda: self.lbl_metric_gpu.configure(text=txt, text_color=col))

        threading.Thread(target=_job, daemon=True).start()

    def _update_dashboard_metrics(self) -> None:
        active = [f for f in self.all_findings if not f.remediated]
        self.lbl_metric_threats.configure(
            text=str(len(active)),
            text_color="#ef4444" if active else "#4ade80",
        )
        self.lbl_metric_quarantine.configure(text=str(len(load_quarantine_items())))
        self.btn_fix_all.configure(state="normal" if active else "disabled")

    def _run_full_scan(self) -> None:
        if self.scan_busy:
            return
        self.scan_busy = True
        self.btn_full_scan.configure(state="disabled", text=t("btn_scanning"))
        self.dash_progress.set(0.08)

        def _worker() -> None:
            combined: List[ThreatFinding] = []
            try:
                self.after(0, lambda: self.lbl_dash_status.configure(text=t("scan_step_1")))
                p_findings, p_meta = scan_processes()
                self.proc_findings = p_findings
                self.last_gpu_info = p_meta.get("gpu", {})
                combined.extend(p_findings)
                self.after(0, lambda: self.dash_progress.set(0.30))

                self.after(0, lambda: self.lbl_dash_status.configure(text=t("scan_step_2")))
                per_findings = scan_persistence()
                self.persist_findings = per_findings
                combined.extend(per_findings)
                self.after(0, lambda: self.dash_progress.set(0.55))

                self.after(0, lambda: self.lbl_dash_status.configure(text=t("scan_step_3")))
                d_findings, d_status = scan_defender()
                self.defender_findings = d_findings
                self.last_defender_status = d_status
                combined.extend(d_findings)
                self.after(0, lambda: self.dash_progress.set(0.75))

                self.after(0, lambda: self.lbl_dash_status.configure(text=t("scan_step_4")))
                f_findings, f_count = quick_scan_hotspot_folders()
                combined.extend(f_findings)
                combined.sort(key=lambda x: x.severity.rank, reverse=True)
                self.all_findings = combined

                def _finish() -> None:
                    self.dash_progress.set(1.0)
                    self.lbl_dash_status.configure(
                        text=t("scan_done", procs=p_meta.get("total_processes", 0), files=f_count, count=len(combined))
                    )
                    self._render_findings_list(self.dash_list, self.all_findings, on_after_remediate=self._rerender_dashboard)
                    self._render_findings_list(self.proc_list, self.proc_findings, on_after_remediate=self._rerender_proc)
                    self._render_findings_list(self.persist_list, self.persist_findings, on_after_remediate=self._rerender_persist)
                    self._render_defender_results()
                    if self.last_gpu_info.get("available"):
                        g = self.last_gpu_info
                        self.lbl_metric_gpu.configure(text=f"{g['util_pct']}% | {g['temp_c']}°C")
                    self._update_dashboard_metrics()
                    self.btn_full_scan.configure(state="normal", text=t("btn_full_scan"))
                    self.scan_busy = False

                self.after(0, _finish)
            except Exception as exc:
                self.after(0, lambda: self._on_scan_error(str(exc)))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_error(self, err: str) -> None:
        self.scan_busy = False
        self.btn_full_scan.configure(state="normal", text=t("btn_full_scan"))
        self.lbl_dash_status.configure(text=t("scan_err", err=err))

    def _rerender_dashboard(self) -> None:
        self._render_findings_list(self.dash_list, self.all_findings, on_after_remediate=self._rerender_dashboard)
        self._update_dashboard_metrics()

    def _export_log(self, findings: List[ThreatFinding], scope: str) -> None:
        if not findings:
            messagebox.showinfo(__app_name__, t("export_empty"))
            return
        save_path = filedialog.asksaveasfilename(
            title=t("export_title"),
            initialdir=str(Path.home() / "Desktop"),
            initialfile=default_log_filename(".txt"),
            defaultextension=".txt",
            filetypes=[
                ("Text Log (*.txt)", "*.txt"),
                ("JSON Report (*.json)", "*.json"),
            ],
        )
        if not save_path:
            return
        try:
            saved = export_findings_log(findings, save_path, scan_scope=scope, gpu_info=self.last_gpu_info)
            if messagebox.askyesno(__app_name__, t("export_ok", path=str(saved))):
                subprocess.Popen(["explorer.exe", "/select,", str(saved)])
        except Exception as exc:
            messagebox.showerror(__app_name__, t("export_err", err=str(exc)))

    def _remediate_batch(
        self, items: List[ThreatFinding], after_cb: Optional[Callable[[], None]] = None
    ) -> None:
        if not items:
            return
        if not messagebox.askyesno(__app_name__, t("confirm_fix_selected", count=len(items))):
            return
        order = {
            ThreatCategory.SCHEDULED_TASK: 0,
            ThreatCategory.PROCESS: 1,
            ThreatCategory.SERVICE: 2,
            ThreatCategory.WMI: 3,
            ThreatCategory.REGISTRY: 4,
            ThreatCategory.DEFENDER_EXCLUSION: 5,
            ThreatCategory.STARTUP_FILE: 6,
            ThreatCategory.FILE: 7,
        }
        items = sorted(items, key=lambda f: order.get(f.category, 9))
        ok_cnt = 0
        fail_msgs: List[str] = []
        for f in items:
            ok, msg = remediate_finding(f)
            if ok:
                ok_cnt += 1
            else:
                fail_msgs.append(f"- {f.display_title}: {msg}")

        summary = t("fix_all_summary", ok=ok_cnt, total=len(items))
        if fail_msgs:
            summary += t("fix_all_need_admin") + "\n".join(fail_msgs[:6])
        messagebox.showinfo(__app_name__, summary)
        if after_cb:
            after_cb()
        self._update_dashboard_metrics()

    def _remediate_all_dashboard(self) -> None:
        active = [f for f in self.all_findings if not f.remediated]
        if not active:
            return
        self._remediate_batch(active, after_cb=self._rerender_dashboard)

    # --------------------------------------------------------------- Page 2: Processes
    def _build_processes_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["processes"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(page, fg_color="transparent")
        top.grid(row=0, column=0, padx=24, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text=t("proc_title"), font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        self.btn_scan_proc = ctk.CTkButton(
            top, text=t("btn_scan_proc"), height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self._run_proc_scan
        )
        self.btn_scan_proc.pack(side="right")

        self.lbl_proc_info = ctk.CTkLabel(
            page, text=t("proc_desc"), font=ctk.CTkFont(size=12), text_color=TEXT_MUTED, anchor="w"
        )
        self.lbl_proc_info.grid(row=1, column=0, padx=24, pady=(0, 8), sticky="ew")

        self.proc_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.proc_list.grid(row=2, column=0, padx=24, pady=(4, 20), sticky="nsew")

    def _run_proc_scan(self) -> None:
        self.btn_scan_proc.configure(state="disabled", text=t("btn_scanning"))

        def _job() -> None:
            findings, meta = scan_processes()
            self.proc_findings = findings
            g = meta.get("gpu", {})
            gtxt = f" | GPU: {g['gpu_name']} ({g['util_pct']}%, {g['mem_used_mb']}/{g['mem_total_mb']} MB, {g['temp_c']}°C)" if g.get("available") else ""

            def _done() -> None:
                self.lbl_proc_info.configure(text=t("proc_done", procs=meta.get("total_processes", 0), gpu=gtxt, count=len(findings)))
                self._rerender_proc()
                self.btn_scan_proc.configure(state="normal", text=t("btn_scan_proc"))

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    def _rerender_proc(self) -> None:
        self._render_findings_list(self.proc_list, self.proc_findings, on_after_remediate=self._rerender_proc)

    # --------------------------------------------------------------- Page 3: Persistence
    def _build_persistence_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["persistence"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(page, fg_color="transparent")
        top.grid(row=0, column=0, padx=24, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text=t("persist_title"), font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        self.btn_scan_persist = ctk.CTkButton(
            top, text=t("btn_scan_persist"), height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self._run_persist_scan
        )
        self.btn_scan_persist.pack(side="right")

        self.lbl_persist_info = ctk.CTkLabel(
            page, text=t("persist_desc"), font=ctk.CTkFont(size=12), text_color=TEXT_MUTED, anchor="w"
        )
        self.lbl_persist_info.grid(row=1, column=0, padx=24, pady=(0, 8), sticky="ew")

        self.persist_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.persist_list.grid(row=2, column=0, padx=24, pady=(4, 20), sticky="nsew")

    def _run_persist_scan(self) -> None:
        self.btn_scan_persist.configure(state="disabled", text=t("btn_scanning"))

        def _job() -> None:
            findings = scan_persistence()
            self.persist_findings = findings

            def _done() -> None:
                self.lbl_persist_info.configure(text=t("persist_done", count=len(findings)))
                self._rerender_persist()
                self.btn_scan_persist.configure(state="normal", text=t("btn_scan_persist"))

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    def _rerender_persist(self) -> None:
        self._render_findings_list(self.persist_list, self.persist_findings, on_after_remediate=self._rerender_persist)

    # --------------------------------------------------------------- Page 4: Defender
    def _build_defender_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["defender"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(page, fg_color="transparent")
        top.grid(row=0, column=0, padx=24, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(top, text=t("def_title"), font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        self.btn_scan_def = ctk.CTkButton(
            top, text=t("btn_scan_def"), height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self._run_defender_scan
        )
        self.btn_scan_def.pack(side="right")

        self.lbl_def_status = ctk.CTkLabel(
            page,
            text=t("def_note"),
            font=ctk.CTkFont(size=12),
            text_color="#fbbf24" if not self.admin_mode else TEXT_MUTED,
            anchor="w",
        )
        self.lbl_def_status.grid(row=1, column=0, padx=24, pady=(0, 8), sticky="ew")

        self.defender_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.defender_list.grid(row=2, column=0, padx=24, pady=(4, 20), sticky="nsew")

    def _run_defender_scan(self) -> None:
        self.btn_scan_def.configure(state="disabled", text=t("def_checking"))

        def _job() -> None:
            findings, st = scan_defender()
            self.defender_findings = findings
            self.last_defender_status = st
            self.after(0, self._render_defender_results)
            self.after(0, lambda: self.btn_scan_def.configure(state="normal", text=t("btn_scan_def")))

        threading.Thread(target=_job, daemon=True).start()

    def _render_defender_results(self) -> None:
        st = self.last_defender_status
        rt = st.get("realtime_enabled")
        rt_txt = t("def_rt_on") if rt is True else (t("def_rt_off") if rt is False else t("def_rt_unknown"))
        adm_note = "" if self.admin_mode else t("def_admin_warn")
        self.lbl_def_status.configure(
            text=t("def_status_line", rt=rt_txt, count=len(self.defender_findings), warn=adm_note)
        )
        self._render_findings_list(self.defender_list, self.defender_findings, on_after_remediate=self._render_defender_results)

    # --------------------------------------------------------------- Page 5: File & VT
    def _build_files_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["files"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(page, text=t("files_title"), font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, padx=24, pady=(20, 10), sticky="w"
        )

        ctrl = ctk.CTkFrame(page, fg_color=BG_CARD, corner_radius=12)
        ctrl.grid(row=1, column=0, padx=24, pady=6, sticky="ew")
        ctrl.grid_columnconfigure(0, weight=1)

        row1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row1.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        row1.grid_columnconfigure(0, weight=1)

        self.entry_target_path = ctk.CTkEntry(row1, placeholder_text=t("entry_path_ph"), height=36)
        self.entry_target_path.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        ctk.CTkButton(row1, text=t("btn_pick_file"), width=95, height=36, command=self._pick_file).grid(row=0, column=1, padx=4)
        ctk.CTkButton(row1, text=t("btn_pick_folder"), width=115, height=36, command=self._pick_folder).grid(row=0, column=2, padx=(4, 0))

        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        self.btn_scan_heur = ctk.CTkButton(
            row2, text=t("btn_heur"), height=36, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self._run_file_heuristics
        )
        self.btn_scan_heur.pack(side="left", padx=(0, 8))
        self.btn_scan_mp = ctk.CTkButton(
            row2, text=t("btn_mp"), height=36, fg_color="#0f766e", hover_color="#115e59", command=self._run_mp_scan
        )
        self.btn_scan_mp.pack(side="left", padx=(0, 8))
        self.btn_scan_vt = ctk.CTkButton(
            row2, text=t("btn_vt"), height=36, fg_color="#6d28d9", hover_color="#5b21b6", command=self._run_vt_lookup
        )
        self.btn_scan_vt.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            row2,
            text=t("btn_export_log"),
            height=36,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self._export_log(self.file_findings, f"File Scan: {self.entry_target_path.get().strip()}"),
        ).pack(side="right")

        row3 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row3.grid(row=2, column=0, padx=14, pady=(4, 12), sticky="ew")
        row3.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(row3, text=t("vt_key_label"), font=ctk.CTkFont(size=12), text_color=TEXT_MUTED).grid(
            row=0, column=0, padx=(0, 8)
        )
        self.entry_vt_key = ctk.CTkEntry(row3, show="*", placeholder_text=t("vt_key_ph"), height=32)
        self.entry_vt_key.grid(row=0, column=1, padx=(0, 8), sticky="ew")
        if self.config_data.get("vt_api_key"):
            self.entry_vt_key.insert(0, self.config_data["vt_api_key"])
        ctk.CTkButton(row3, text=t("btn_save_key"), width=85, height=32, command=self._save_vt_key).grid(row=0, column=2)

        self.lbl_file_status = ctk.CTkLabel(
            page, text=t("files_hint"), font=ctk.CTkFont(size=12), text_color=TEXT_MUTED, anchor="w"
        )
        self.lbl_file_status.grid(row=2, column=0, padx=24, pady=(4, 4), sticky="ew")

        self.file_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.file_list.grid(row=3, column=0, padx=24, pady=(4, 20), sticky="nsew")

    def _pick_file(self) -> None:
        p = filedialog.askopenfilename(title=t("btn_pick_file"))
        if p:
            self.entry_target_path.delete(0, "end")
            self.entry_target_path.insert(0, p)

    def _pick_folder(self) -> None:
        p = filedialog.askdirectory(title=t("btn_pick_folder"))
        if p:
            self.entry_target_path.delete(0, "end")
            self.entry_target_path.insert(0, p)

    def _save_vt_key(self) -> None:
        self.config_data["vt_api_key"] = self.entry_vt_key.get().strip()
        save_config(self.config_data)
        messagebox.showinfo(__app_name__, t("vt_saved"))

    def _run_file_heuristics(self) -> None:
        target = self.entry_target_path.get().strip()
        if not target or not Path(target).exists():
            messagebox.showwarning(__app_name__, t("pick_valid_path"))
            return
        self.btn_scan_heur.configure(state="disabled", text=t("btn_scanning"))
        self.lbl_file_status.configure(text=t("scanning_heur", target=target))

        def _job() -> None:
            findings, count = scan_path_heuristics(
                target,
                progress_cb=lambda n, p: self.after(
                    0, lambda: self.lbl_file_status.configure(text=t("scanned_progress", n=n, path=p[:85]))
                ),
            )
            self.file_findings = findings

            def _done() -> None:
                self.lbl_file_status.configure(text=t("heur_done", count=count, found=len(findings)))
                self._render_findings_list(self.file_list, self.file_findings, on_after_remediate=self._rerender_files)
                self.btn_scan_heur.configure(state="normal", text=t("btn_heur"))

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    def _rerender_files(self) -> None:
        self._render_findings_list(self.file_list, self.file_findings, on_after_remediate=self._rerender_files)

    def _run_mp_scan(self) -> None:
        target = self.entry_target_path.get().strip()
        if not target or not Path(target).exists():
            messagebox.showwarning(__app_name__, t("pick_valid_path"))
            return
        self.btn_scan_mp.configure(state="disabled", text=t("btn_mp_busy"))
        self.lbl_file_status.configure(text=t("mp_running", target=target))

        def _job() -> None:
            found, out = scan_with_defender_cli(target)

            def _done() -> None:
                self.btn_scan_mp.configure(state="normal", text=t("btn_mp"))
                if found:
                    self.lbl_file_status.configure(text=t("mp_found"))
                    messagebox.showwarning("Windows Defender", t("mp_found_msg", out=out[:900]))
                else:
                    self.lbl_file_status.configure(text=t("mp_clean"))
                    messagebox.showinfo("Windows Defender", t("mp_clean_msg", out=out[:900]))

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    def _run_vt_lookup(self) -> None:
        target = self.entry_target_path.get().strip()
        p = Path(target)
        if not target or not p.is_file():
            messagebox.showwarning(__app_name__, t("vt_single_file"))
            return
        api_key = self.entry_vt_key.get().strip()
        if not api_key:
            messagebox.showwarning(__app_name__, t("vt_need_key"))
            return
        self.btn_scan_vt.configure(state="disabled", text=t("btn_vt_busy"))
        self.lbl_file_status.configure(text=t("vt_hashing"))

        def _job() -> None:
            sha = compute_sha256(p)
            res = check_virustotal_hash(sha, api_key)

            def _done() -> None:
                self.btn_scan_vt.configure(state="normal", text=t("btn_vt"))
                if not res.get("ok"):
                    self.lbl_file_status.configure(text=f"VirusTotal: {res.get('error')}")
                    messagebox.showerror("VirusTotal", str(res.get("error")))
                    return
                if not res.get("found"):
                    self.lbl_file_status.configure(text=t("vt_not_found", sha=sha[:16]))
                    messagebox.showinfo("VirusTotal", t("vt_not_found_msg", sha=sha))
                    return
                mal = res["malicious"]
                susp = res["suspicious"]
                total = mal + susp + res["undetected"] + res["harmless"]
                self.lbl_file_status.configure(text=t("vt_result_line", mal=mal, total=total, susp=susp))
                if messagebox.askyesno(
                    "VirusTotal",
                    t("vt_result_dialog", name=p.name, sha=sha, mal=mal, total=total, susp=susp),
                ):
                    webbrowser.open(res["link"])

            self.after(0, _done)

        threading.Thread(target=_job, daemon=True).start()

    # --------------------------------------------------------------- Page 6: Quarantine & History
    def _build_quarantine_page(self) -> None:
        page = ctk.CTkFrame(self.main_area, fg_color=BG_MAIN)
        self.pages["quarantine"] = page
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        page.grid_rowconfigure(4, weight=1)

        top = ctk.CTkFrame(page, fg_color="transparent")
        top.grid(row=0, column=0, padx=24, pady=(20, 8), sticky="ew")
        ctk.CTkLabel(top, text=t("q_title"), font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkButton(top, text=t("btn_refresh"), width=110, height=34, command=self._render_quarantine_page).pack(side="right")

        ctk.CTkLabel(page, text=t("q_section_files"), font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=1, column=0, padx=24, pady=(4, 4), sticky="w"
        )
        self.q_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.q_list.grid(row=2, column=0, padx=24, pady=(0, 10), sticky="nsew")

        ctk.CTkLabel(page, text=t("q_section_hist"), font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=3, column=0, padx=24, pady=(4, 4), sticky="w"
        )
        self.hist_list = ctk.CTkScrollableFrame(page, fg_color=BG_CARD, corner_radius=12)
        self.hist_list.grid(row=4, column=0, padx=24, pady=(0, 20), sticky="nsew")

    def _render_quarantine_page(self) -> None:
        for w in self.q_list.winfo_children():
            w.destroy()
        items = load_quarantine_items()
        if not items:
            ctk.CTkLabel(self.q_list, text=t("q_empty"), text_color=TEXT_MUTED).pack(pady=24)
        else:
            for idx, item in enumerate(items):
                row_bg = BG_ROW if idx % 2 == 0 else "#1a253a"
                row = ctk.CTkFrame(self.q_list, fg_color=row_bg, corner_radius=0)
                row.pack(fill="x", padx=2, pady=0)
                row.grid_columnconfigure(0, weight=1)
                info = t(
                    "q_item_info",
                    title=item.threat_title,
                    size=format_bytes(item.size_bytes),
                    orig=item.original_path,
                    time=item.quarantined_at,
                )
                ctk.CTkLabel(row, text=info, justify="left", anchor="w", font=ctk.CTkFont(size=12)).grid(
                    row=0, column=0, padx=12, pady=8, sticky="ew"
                )
                ctk.CTkButton(
                    row,
                    text=t("btn_restore"),
                    width=105,
                    height=30,
                    corner_radius=4,
                    fg_color=SUCCESS,
                    hover_color="#15803d",
                    command=lambda iid=item.id: self._restore_q(iid),
                ).grid(row=0, column=1, padx=4, pady=8)
                ctk.CTkButton(
                    row,
                    text=t("btn_delete_perm"),
                    width=105,
                    height=30,
                    corner_radius=4,
                    fg_color=DANGER,
                    hover_color=DANGER_HOVER,
                    command=lambda iid=item.id: self._delete_q(iid),
                ).grid(row=0, column=2, padx=(4, 10), pady=8)
                ctk.CTkFrame(self.q_list, height=1, corner_radius=0, fg_color="#263248").pack(fill="x", padx=2)

        for w in self.hist_list.winfo_children():
            w.destroy()
        hist = load_history()
        if not hist:
            ctk.CTkLabel(self.hist_list, text=t("hist_empty"), text_color=TEXT_MUTED).pack(pady=24)
        else:
            for h in hist[:40]:
                icon = "✅" if h.get("success") else "❌"
                txt = f"{icon} [{h.get('time')}] {h.get('action')} — {h.get('target')}\n     {h.get('message')}"
                ctk.CTkLabel(
                    self.hist_list, text=txt, justify="left", anchor="w", font=ctk.CTkFont(size=12), text_color="#cbd5e1"
                ).pack(fill="x", padx=10, pady=3)

        self._update_dashboard_metrics()

    def _restore_q(self, item_id: str) -> None:
        if not messagebox.askyesno(__app_name__, t("confirm_restore")):
            return
        ok, msg = restore_quarantine_item(item_id)
        (messagebox.showinfo if ok else messagebox.showerror)(__app_name__, msg)
        self._render_quarantine_page()

    def _delete_q(self, item_id: str) -> None:
        if not messagebox.askyesno(__app_name__, t("confirm_delete_perm")):
            return
        ok, msg = delete_quarantine_item_permanently(item_id)
        (messagebox.showinfo if ok else messagebox.showerror)(__app_name__, msg)
        self._render_quarantine_page()


def run_app() -> None:
    app = ShieldGuardApp()
    app.mainloop()
