"""Interactive URL entry point for J.O.S.H.'s authorized passive assessments.

This is a command-line assessment helper, not a trained machine-learning model.
It reuses the scanner and optional AI explanation in jam.py.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import urllib.parse


SCANNER_PATH = Path(__file__).with_name("jam.py")
SCANNER_SPEC = importlib.util.spec_from_file_location("josh_passive_scanner", SCANNER_PATH)
if SCANNER_SPEC is None or SCANNER_SPEC.loader is None:
	raise RuntimeError(f"Could not load J.O.S.H. scanner: {SCANNER_PATH}")
SCANNER = importlib.util.module_from_spec(SCANNER_SPEC)
SCANNER_SPEC.loader.exec_module(SCANNER)


def collect_urls(args):
	urls = [*args.targets, *args.url]
	if urls:
		return urls
	print("Enter URLs one per line. Press Enter on an empty line when finished.")
	while True:
		try:
			value = input("URL: ").strip()
		except EOFError:
			break
		if not value:
			break
		urls.append(value)
	return urls


def confirm_scope():
	print("Only URLs on JOSH_ALLOWED_HOSTS are accepted, and targets must resolve to public IP addresses.")
	print("Checks are passive. If an Anthropic key is configured, generic finding descriptions may be sent to Claude and API charges may apply.")
	try:
		answer = input("Type YES to confirm you are authorized to assess these URLs and allow this processing: ")
	except EOFError:
		return False
	return answer.strip() == "YES"


def safe_target_label(raw_url):
	try:
		parsed = urllib.parse.urlsplit(raw_url)
		if parsed.scheme not in ("http", "https") or not parsed.hostname:
			return "(invalid URL)"
		return f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}"[:300]
	except (TypeError, ValueError):
		return "(invalid URL)"


def print_report(report):
	print(f"\nTarget: {report['target']}  (HTTP {report['status']})")
	if not report["findings"]:
		print("No indicators were found by these passive checks.")
	else:
		for item in report["triage"]["prioritized_findings"]:
			print(f"- {item['severity'].upper()}: {item['title']}")
			print(f"  Where: {item['location']}")
			print(f"  Why: {item['detail']}")
	print("Summary: " + report["triage"]["summary"])
	if report["triage"].get("ai_used"):
		print("AI explanation: " + report["triage"]["ai_explanation"])
	elif report["findings"]:
		print("AI explanation unavailable; showing local rule-based results.")
	print("These indicators need human review; they do not prove a vulnerability.\n")


def main():
	parser = argparse.ArgumentParser(
		description="Enter URLs for J.O.S.H.'s bounded, passive website assessment."
	)
	parser.add_argument("targets", nargs="*", help="URLs to assess; omit to enter them interactively")
	parser.add_argument("--url", action="append", default=[], help="URL to assess (repeat for multiple URLs)")
	parser.add_argument("--json", action="store_true", help="Print machine-readable JSON results")
	args = parser.parse_args()

	urls = collect_urls(args)
	if not urls:
		print("No URLs entered; nothing was scanned.")
		return 0
	if not confirm_scope():
		print("Authorization was not confirmed; nothing was scanned.", file=sys.stderr)
		return 2

	results = []
	for url in urls:
		try:
			results.append({"ok": True, "report": SCANNER.inspect_url(url)})
		except (PermissionError, ValueError) as exc:
			results.append({"ok": False, "target": safe_target_label(url), "error": str(exc)})
		if not args.json:
			if results[-1]["ok"]:
				print_report(results[-1]["report"])
			else:
				print(f"Could not assess {results[-1]['target']}: {results[-1]['error']}\n", file=sys.stderr)

	if args.json:
		print(json.dumps(results, indent=2, ensure_ascii=False))
	if any(not item["ok"] for item in results):
		return 2
	if any(item["report"]["findings"] for item in results):
		return 1
	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except KeyboardInterrupt:
		print("\nAssessment cancelled.", file=sys.stderr)
		raise SystemExit(130)
