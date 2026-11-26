#!/usr/bin/env python3
"""Tiny append-only metrics logger for BOTOPIA runs.

Every event is one JSON line in reports/metrics.jsonl (override with METRICS_PATH).
Tracked events:
  attempt          an exploit attempt; pass --blocked when the gateway stopped it
  pr_opened        a fix PR opened by the bot
  pr_merged        a fix PR merged by a human
  pr_self_rejected a patch the bot discarded because the oracle failed (keep as evidence)
  human_message    a message a human had to send the bot (Needs You replies, nudges)

Usage:
  python scripts/metrics.py log attempt --issue idor_get_summary --blocked
  python scripts/metrics.py log pr_opened --pr 12 --issue idor_get_summary
  python scripts/metrics.py log human_message --note "approved PR 12"
  python scripts/metrics.py summary [--json]
"""
import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
EVENTS = ("attempt", "pr_opened", "pr_merged", "pr_self_rejected", "human_message")


def metrics_path() -> Path:
    return Path(os.getenv("METRICS_PATH", REPO_ROOT / "reports" / "metrics.jsonl"))


def log_event(event: str, **fields: Any) -> Dict[str, Any]:
    if event not in EVENTS:
        raise ValueError(f"unknown event {event!r}; expected one of {EVENTS}")
    entry = {"ts": time.time(), "event": event}
    entry.update({k: v for k, v in fields.items() if v is not None})
    path = metrics_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def read_events(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = path or metrics_path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summarize(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    count = {e: sum(1 for x in events if x["event"] == e) for e in EVENTS}
    attempts = [x for x in events if x["event"] == "attempt"]
    blocked = sum(1 for x in attempts if x.get("blocked"))
    succeeded = len(attempts) - blocked

    def ratio(num: int, den: int) -> Optional[float]:
        return round(num / den, 3) if den else None

    return {
        "attempts": len(attempts),
        "attempts_blocked": blocked,
        "attempts_succeeded": succeeded,
        "attack_success_rate": ratio(succeeded, len(attempts)),
        "prs_opened": count["pr_opened"],
        "prs_merged": count["pr_merged"],
        "prs_self_rejected": count["pr_self_rejected"],
        "human_messages": count["human_message"],
        "human_messages_per_pr_opened": ratio(count["human_message"], count["pr_opened"]),
        "human_messages_per_pr_merged": ratio(count["human_message"], count["pr_merged"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    log = sub.add_parser("log", help="append one event")
    log.add_argument("event", choices=EVENTS)
    log.add_argument("--issue")
    log.add_argument("--pr")
    log.add_argument("--note")
    log.add_argument("--blocked", action="store_true", help="for attempt: the gateway blocked it")
    summary = sub.add_parser("summary", help="print totals and ratios")
    summary.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.cmd == "log":
        extra = {"blocked": args.blocked} if args.event == "attempt" else {}
        print(json.dumps(log_event(args.event, issue=args.issue, pr=args.pr, note=args.note, **extra)))
        return
    s = summarize(read_events())
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        for k, v in s.items():
            print(f"{k:32} {v}")


if __name__ == "__main__":
    main()
