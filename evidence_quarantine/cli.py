from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from evidence_quarantine.config import QuarantineConfig
from evidence_quarantine.lab_detector import LabDetector
from evidence_quarantine.lab_simulator import RootkitLabSimulator
from evidence_quarantine.models import QuarantineRequest, RiskLevel, to_jsonable
from evidence_quarantine.quarantine_manager import QuarantineManager


def _json_print(payload: Any) -> None:
    print(json.dumps(to_jsonable(payload), indent=2, ensure_ascii=False))


def _config_from_args(args: argparse.Namespace) -> QuarantineConfig:
    if args.storage_root:
        return QuarantineConfig(
            storage_root=Path(args.storage_root),
            allow_system_paths=args.allow_system_paths,
            max_artifact_size_bytes=args.max_size,
        )
    return QuarantineConfig(
        allow_system_paths=args.allow_system_paths,
        max_artifact_size_bytes=args.max_size,
    )


def _quarantine(args: argparse.Namespace) -> int:
    manager = QuarantineManager(_config_from_args(args))
    result = manager.quarantine_artifact(
        QuarantineRequest(
            alert_id=args.alert_id,
            artifact_path=Path(args.path),
            detection_reason=args.reason,
            risk_level=RiskLevel(args.risk_level),
            source_module=args.source_module,
            tags=args.tag,
        )
    )
    _json_print(result.to_summary())
    return 0 if result.success else 2


def _list(args: argparse.Namespace) -> int:
    manager = QuarantineManager(_config_from_args(args))
    _json_print(manager.list_evidence())
    return 0


def _show(args: argparse.Namespace) -> int:
    manager = QuarantineManager(_config_from_args(args))
    record = manager.get_evidence(args.alert_id)
    if record is None:
        _json_print({"error": "alert_id not found", "alert_id": args.alert_id})
        return 1
    _json_print(record)
    return 0


def _demo(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    demo_dir = config.storage_root / "demo-input"
    demo_dir.mkdir(parents=True, exist_ok=True)
    sample = demo_dir / "rk_demo.ko"
    sample.write_bytes(
        b"BENIGN ROOTKIT DEFENSE DEMO ARTIFACT\n"
        b"This is not a real kernel module and must never be loaded.\n"
        b"It only simulates a .ko artifact name for quarantine testing.\n"
    )

    manager = QuarantineManager(config)
    result = manager.quarantine_artifact(
        QuarantineRequest(
            alert_id=args.alert_id or "ALT-DEMO-000001",
            artifact_path=sample,
            detection_reason="Benign demo artifact simulating a suspicious Linux kernel module file",
            risk_level=RiskLevel.HIGH,
            source_module="demo-simulator",
            tags=["demo", "benign", "rootkit", "kernel-module"],
        )
    )
    _json_print(
        {
            "demo_sample": sample,
            "result": result.to_summary(),
            "next_step": "Open metadata.json, hashes.json, manifest.json and audit.log inside the evidence_dir.",
        }
    )
    return 0 if result.success else 2


def _simulate_rootkit(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    lab_root = Path(args.lab_root) if args.lab_root else config.storage_root / "lab-victim"
    simulator = RootkitLabSimulator(lab_root)

    if args.quarantine:
        payload = simulator.quarantine_scenario(args.scenario, QuarantineManager(config))
    else:
        artifacts = simulator.create_scenario(args.scenario)
        payload = {
            "lab_root": lab_root.resolve(),
            "scenario": args.scenario,
            "alerts_file": lab_root.resolve() / "alerts.json",
            "alerts": [artifact.to_alert() for artifact in artifacts],
            "next_step": "Use --quarantine to send these benign artifacts into Evidence & Quarantine Manager.",
        }

    _json_print(payload)
    return 0


def _lab_detect(args: argparse.Namespace) -> int:
    manager = QuarantineManager(_config_from_args(args))
    payload = LabDetector(manager).process_alerts_file(Path(args.alerts_file))
    _json_print(payload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-quarantine",
        description="Evidence & Quarantine Manager for Rootkit Defense Agent",
    )
    parser.add_argument("--storage-root", help="Storage root for quarantine, audit and index data")
    parser.add_argument(
        "--allow-system-paths",
        action="store_true",
        help="Allow critical Linux paths such as /bin or /boot in a controlled lab only",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=100 * 1024 * 1024,
        help="Maximum artifact size in bytes",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    quarantine = subparsers.add_parser("quarantine", help="Quarantine an artifact and preserve evidence")
    quarantine.add_argument("--path", required=True, help="Path to suspicious artifact")
    quarantine.add_argument("--reason", required=True, help="Detection reason")
    quarantine.add_argument("--alert-id", help="Alert identifier generated by detection engine")
    quarantine.add_argument(
        "--risk-level",
        choices=[level.value for level in RiskLevel],
        default=RiskLevel.MEDIUM.value,
        help="Risk level associated with the alert",
    )
    quarantine.add_argument("--source-module", default="detection-engine")
    quarantine.add_argument("--tag", action="append", default=[])
    quarantine.set_defaults(func=_quarantine)

    list_cmd = subparsers.add_parser("list", help="List evidence packages")
    list_cmd.set_defaults(func=_list)

    show = subparsers.add_parser("show", help="Show a quarantine record from the local index")
    show.add_argument("--alert-id", required=True)
    show.set_defaults(func=_show)

    demo = subparsers.add_parser("demo", help="Create a benign sample and quarantine it")
    demo.add_argument("--alert-id")
    demo.set_defaults(func=_demo)

    simulate = subparsers.add_parser(
        "simulate-rootkit",
        help="Create benign rootkit-like lab artifacts without offensive behavior",
    )
    simulate.add_argument(
        "--scenario",
        choices=["full", "kernel-module", "ld-preload", "systemd", "cron", "hidden-payload", "binary-tamper"],
        default="full",
    )
    simulate.add_argument("--lab-root", help="Directory used as fake victim filesystem")
    simulate.add_argument(
        "--quarantine",
        action="store_true",
        help="Immediately quarantine generated benign artifacts",
    )
    simulate.set_defaults(func=_simulate_rootkit)

    lab_detect = subparsers.add_parser(
        "lab-detect",
        help="Process benign lab alerts on a victim machine with the detector installed",
    )
    lab_detect.add_argument("--alerts-file", required=True, help="Path to alerts.json generated by simulate-rootkit")
    lab_detect.set_defaults(func=_lab_detect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
