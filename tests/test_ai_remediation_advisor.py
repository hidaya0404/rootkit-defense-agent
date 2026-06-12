from analysis.ai_remediation_advisor import build_ai_recommendation


def test_ai_recommendation_selects_kernel_module_playbook():
    artifact = {
        "artifact_id": "ART-1",
        "alert_id": "ALT-1",
        "analysis": {
            "risk_score": 92,
            "risk_level": "CRITICAL",
            "strings_sample": [
                "rootkit insmod init_module sys_call_table hook_getdents64",
                "/lib/modules/evil.ko"
            ],
            "iocs": {"paths": ["/lib/modules/evil.ko"], "ips": [], "domains": [], "urls": []},
            "yara_matches": ["Suspicious_Linux_Rootkit_Indicators"],
        },
    }

    recommendation = build_ai_recommendation(artifact)

    assert recommendation["model"]["external_api"] is False
    assert recommendation["selected_playbook"]["id"] == "kernel_module_rootkit_response"
    assert recommendation["selected_playbook"]["priority"] == "CRITICAL"
    assert recommendation["requires_human_validation"] is True
    assert recommendation["automatic_destructive_action_allowed"] is False


def test_ai_recommendation_selects_ld_preload_playbook():
    artifact = {
        "artifact_id": "ART-2",
        "alert_id": "ALT-2",
        "analysis": {
            "risk_score": 78,
            "risk_level": "HIGH",
            "strings_sample": [
                "/etc/ld.so.preload",
                "LD_PRELOAD readdir getdents64 hide_process"
            ],
            "iocs": {"paths": ["/etc/ld.so.preload"], "ips": [], "domains": [], "urls": []},
            "yara_matches": ["Suspicious_Linux_Rootkit_Indicators"],
        },
    }

    recommendation = build_ai_recommendation(artifact)

    assert recommendation["selected_playbook"]["id"] == "ld_preload_userland_hook_response"
    assert recommendation["confidence"] >= 0.5
    assert any("preload" in action.lower() for action in recommendation["recommended_actions"])


def test_ai_recommendation_prioritizes_strong_kernel_signals_over_metadata_noise():
    artifact = {
        "artifact_id": "ART-AI-DEMO-0001",
        "alert_id": "ALT-AI-DEMO-0001",
        "analysis": {
            "risk_score": 45,
            "risk_level": "MEDIUM",
            "metadata": {"filename": "rootkit_like_artifact.txt"},
            "hashes": {"sha256": "abc"},
            "elf_analysis": {"is_elf": False},
            "strings_sample": [
                "rootkit insmod init_module sys_call_table /lib/modules/demo.ko"
            ],
            "iocs": {
                "paths": ["/lib/modules/demo.ko"],
                "ips": [],
                "domains": ["demo.ko"],
                "urls": [],
                "suspicious_files": ["rootkit_like_artifact.txt"],
            },
            "yara_matches": ["YARA not available"],
        },
    }

    recommendation = build_ai_recommendation(artifact)

    assert recommendation["selected_playbook"]["id"] == "kernel_module_rootkit_response"
    assert "/lib/modules" in recommendation["matched_signals"]
