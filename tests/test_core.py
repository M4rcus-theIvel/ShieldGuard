from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shieldguard import exporter, i18n, lookup, models, quarantine, scanner_files, scanner_processes, ui, updater, utils  # noqa: E402


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

    assert hasattr(ui, "ShieldGuardApp") and hasattr(ui, "FindingDetailDialog")
    print("[OK] UI module loaded cleanly")
    print("[ALL TESTS PASSED]")


if __name__ == "__main__":
    main()
