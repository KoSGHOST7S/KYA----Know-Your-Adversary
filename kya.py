#!/usr/bin/env python3
"""
KYA -- Know Your Adversary
Web Application Security Auditor

Usage:
    python kya.py https://target.com
    python kya.py https://target.com --output report.json
    python kya.py https://target.com --model openai/gpt-4o-mini
    python kya.py https://target.com --modules headers,lfi,auth

LEGAL: Only audit applications you own or have explicit written permission to test.
"""
from __future__ import annotations

import sys
import time
import warnings
from typing import Optional

import click
from dotenv import load_dotenv

load_dotenv()

# Suppress InsecureRequestWarning for --no-verify scanning
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from scanner.base import Finding
from scanner.headers import HeadersScanner
from scanner.error_disclosure import ErrorDisclosureScanner
from scanner.lfi_rfi import LFIRFIScanner
from scanner.traversal import TraversalScanner
from scanner.file_upload import FileUploadScanner
from scanner.xxe import XXEScanner
from scanner.auth import AuthScanner
from scanner.verb_tamper import VerbTamperScanner
from scanner.ssrf import SSRFScanner
from report import formatter

ALL_MODULES = {
    "headers": (HeadersScanner, "Security Headers"),
    "error": (ErrorDisclosureScanner, "Error Disclosure"),
    "lfi": (LFIRFIScanner, "LFI / RFI"),
    "traversal": (TraversalScanner, "Directory Traversal"),
    "upload": (FileUploadScanner, "File Upload"),
    "xxe": (XXEScanner, "XXE Injection"),
    "auth": (AuthScanner, "Authentication"),
    "verbs": (VerbTamperScanner, "HTTP Verb Tampering"),
    "ssrf": (SSRFScanner, "SSRF"),
}


@click.command()
@click.argument("url")
@click.option("--output", "-o", default=None, help="Save report to JSON file (e.g. report.json)")
@click.option(
    "--model", "-m", default=None,
    help="OpenRouter model to use (default: from OPENROUTER_MODEL env or anthropic/claude-haiku-4-5)"
)
@click.option(
    "--modules", default=None,
    help=f"Comma-separated list of modules to run. Available: {', '.join(ALL_MODULES.keys())}. Default: all"
)
@click.option("--timeout", "-t", default=10, show_default=True, help="HTTP request timeout in seconds")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI analysis, show raw findings only")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose output")
def main(
    url: str,
    output: Optional[str],
    model: Optional[str],
    modules: Optional[str],
    timeout: int,
    no_ai: bool,
    verbose: bool,
) -> None:
    """
    KYA -- Know Your Adversary: Web Application Security Auditor.

    Scans URL for web vulnerabilities and generates an AI-powered
    offense-to-defense hardening report grounded in CBBH tradecraft.

    \b
    LEGAL DISCLAIMER:
    Only audit applications you own or have explicit written permission to test.
    Unauthorized scanning may be illegal in your jurisdiction.
    """
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    formatter.print_banner(url)

    # Determine which modules to run
    if modules:
        selected_keys = [m.strip().lower() for m in modules.split(",")]
        invalid = [k for k in selected_keys if k not in ALL_MODULES]
        if invalid:
            click.echo(f"[!] Unknown modules: {', '.join(invalid)}. "
                       f"Valid: {', '.join(ALL_MODULES.keys())}", err=True)
            sys.exit(1)
        selected = {k: ALL_MODULES[k] for k in selected_keys}
    else:
        selected = ALL_MODULES

    # Run all selected scanner modules
    start = time.time()
    all_findings: dict[str, list[Finding]] = {}

    formatter.console.print("\n[bold white]── Scanning ──[/bold white]\n")

    for key, (scanner_cls, display_name) in selected.items():
        formatter.print_scan_progress(display_name, status="running")
        scanner = scanner_cls(timeout=timeout, verbose=verbose)
        try:
            findings = scanner.run(url)
        except Exception as exc:
            if verbose:
                formatter.console.print(f"    [red]Error in {display_name}: {exc}[/red]")
            findings = []
        all_findings[display_name] = findings
        formatter.print_scan_progress(display_name, status="done")

    elapsed = time.time() - start

    # Show raw findings table
    formatter.print_raw_findings_table(all_findings)

    if no_ai:
        formatter.print_summary([], elapsed)
        if output:
            formatter.save_json(url, all_findings, [], output)
        return

    # AI analysis
    formatter.console.print("\n[bold white]── AI Analysis (KYA) ──[/bold white]")
    formatter.console.print("[dim]Sending findings to AI for exploit-path analysis...[/dim]\n")

    flat_findings = [f for findings in all_findings.values() for f in findings]

    try:
        from ai import analyst
        report_items = analyst.analyze(flat_findings, model=model)
    except ValueError as exc:
        formatter.console.print(f"[red]{exc}[/red]")
        formatter.console.print("[dim]Run with --no-ai to see raw findings without AI analysis.[/dim]")
        sys.exit(1)
    except Exception as exc:
        formatter.console.print(f"[red]AI analysis failed: {exc}[/red]")
        formatter.console.print("[dim]Showing raw findings only.[/dim]")
        report_items = []

    if report_items:
        formatter.print_kya_report(report_items)

    formatter.print_summary(report_items, time.time() - start)

    if output:
        formatter.save_json(url, all_findings, report_items, output)


if __name__ == "__main__":
    main()
