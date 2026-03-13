from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim white",
}

RESULT_COLORS = {
    "VULNERABLE": "bold red",
    "MISCONFIGURED": "yellow",
    "SECURE": "green",
    "INFO": "dim white",
}


def print_banner(target_url: str) -> None:
    banner = Text()
    banner.append("K Y A", style="bold red")
    banner.append(" -- Know Your Adversary\n", style="bold white")
    banner.append("Web Application Auditor\n\n", style="dim white")
    banner.append(f"Target : ", style="dim")
    banner.append(target_url, style="bold cyan")
    banner.append(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
    console.print(Panel(banner, border_style="red", padding=(1, 2)))


def print_scan_progress(module_name: str, status: str = "running") -> None:
    icon = "[yellow]>[/yellow]" if status == "running" else "[green]✓[/green]"
    console.print(f"  {icon} {module_name}", highlight=False)


def print_raw_findings_table(findings_by_module: dict[str, list]) -> None:
    console.print("\n[bold white]── Raw Scan Results ──[/bold white]\n")
    table = Table(box=box.ROUNDED, border_style="dim", show_header=True,
                  header_style="bold white")
    table.add_column("Module", style="white", min_width=12)
    table.add_column("Check", style="white", min_width=30)
    table.add_column("Result", min_width=14)
    table.add_column("Evidence", style="dim", min_width=40)

    for module, findings in findings_by_module.items():
        for f in findings:
            if f.result in ("SECURE", "INFO") and f.severity == "Info":
                continue  # skip clean/info rows for brevity
            result_style = RESULT_COLORS.get(f.result, "white")
            table.add_row(
                module,
                f.check,
                f"[{result_style}]{f.result}[/{result_style}]",
                f.evidence[:80] + ("..." if len(f.evidence) > 80 else ""),
            )

    console.print(table)


def print_kya_report(report_items: list[dict[str, Any]]) -> None:
    console.print("\n[bold white]── KYA Offense-to-Defense Report ──[/bold white]\n")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_items = sorted(report_items, key=lambda x: severity_order.get(x.get("severity", "Info"), 4))

    for item in sorted_items:
        severity = item.get("severity", "Info")
        check = item.get("check", "Unknown")
        is_exploitable = item.get("is_exploitable", False)
        exploit_path = item.get("exploit_path", "")
        owasp = item.get("owasp_category", "")
        cwe = item.get("cwe", "")
        cbbh_module = item.get("cbbh_module", "")
        hardening = item.get("hardening_control", "")
        layers = item.get("prevention_layers", [])

        sev_style = SEVERITY_COLORS.get(severity, "white")
        exploit_label = "[bold red]EXPLOITABLE[/bold red]" if is_exploitable else "[yellow]MISCONFIGURED[/yellow]"

        # Header line
        console.print(
            f"[{sev_style}][{severity}][/{sev_style}] {check}  {exploit_label}"
        )

        # Metadata line
        meta_parts = []
        if owasp:
            meta_parts.append(f"[dim]{owasp}[/dim]")
        if cwe:
            meta_parts.append(f"[dim]{cwe}[/dim]")
        if cbbh_module:
            meta_parts.append(f"[dim]{cbbh_module}[/dim]")
        if meta_parts:
            console.print("  " + "  |  ".join(meta_parts))

        # Exploit path panel
        if exploit_path:
            console.print(Panel(
                f"[white]{exploit_path}[/white]",
                title="[red]Exploit Path[/red]",
                border_style="red",
                padding=(0, 1),
            ))

        # Hardening panel
        if hardening or layers:
            content = f"[green]{hardening}[/green]"
            if layers:
                content += "\n\n[dim]Prevention layers:[/dim]"
                for i, layer in enumerate(layers, 1):
                    content += f"\n  [dim]{i}.[/dim] {layer}"
            console.print(Panel(
                content,
                title="[green]Hardening Control[/green]",
                border_style="green",
                padding=(0, 1),
            ))

        console.print()


def print_summary(report_items: list[dict[str, Any]], elapsed: float) -> None:
    counts: dict[str, int] = {}
    for item in report_items:
        sev = item.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1

    console.print("[bold white]── Summary ──[/bold white]")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        n = counts.get(sev, 0)
        if n:
            style = SEVERITY_COLORS.get(sev, "white")
            console.print(f"  [{style}]{sev:10}[/{style}]  {n}")
    console.print(f"\n  Completed in {elapsed:.1f}s")


def save_json(
    target_url: str,
    raw_findings: dict[str, list],
    report_items: list[dict[str, Any]],
    output_path: str,
) -> None:
    data = {
        "meta": {
            "tool": "KYA -- Know Your Adversary",
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
        },
        "raw_findings": {
            module: [f.to_dict() for f in findings]
            for module, findings in raw_findings.items()
        },
        "kya_report": report_items,
    }
    with open(output_path, "w") as fh:
        json.dump(data, fh, indent=2)
    console.print(f"\n[dim]Report saved to [cyan]{output_path}[/cyan][/dim]")
