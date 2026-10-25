"""Command-line interface for the AI-NIDS.

  python cli.py data/s2_portscan.pcap          analyse one capture, print alerts
  python cli.py data/s2_portscan.pcap --json    machine-readable output
  python cli.py --list                          list available captures
"""
import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nids.detect import analyze

console = Console()
SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}


def print_alerts(pcap, alerts, meta):
    console.rule(f"[bold]AI-NIDS report: {Path(pcap).name}")
    console.print(f"Flows analysed: [bold]{meta['n_flows']}[/]   "
                  f"Capture duration: [bold]{meta.get('duration','?')}s[/]   "
                  f"Alerts: [bold]{len(alerts)}[/]\n")
    if not alerts:
        console.print(Panel("[green]No intrusions detected - traffic consistent with the "
                            "benign baseline.[/]", title="Clean"))
        return
    for i, a in enumerate(alerts, 1):
        c = SEV_COLOR.get(a["severity"], "white")
        corr = " [dim](rule+ML agree)[/]" if a.get("corroborated_by_ml") else ""
        body = Table.grid(padding=(0, 1))
        body.add_column(style="bold", justify="right")
        body.add_column()
        body.add_row("Source", str(a["src"]))
        body.add_row("Target", str(a["dst"]))
        body.add_row("When", f"{a['start']:.1f}s - {a['end']:.1f}s")
        body.add_row("Layer", a["layer"] + (" / signature" if a["layer"] == "rule" else " / anomaly"))
        body.add_row("Confidence", f"{a['confidence']*100:.0f}%")
        body.add_row("Why", a["reason"])
        body.add_row("Evidence", json.dumps(a["evidence"]))
        body.add_row("Rule/Model", a.get("rule", "-"))
        console.print(Panel(body, title=f"[{c}]#{i}  {a['type']}  [{a['severity'].upper()}]{corr}[/]",
                            border_style=c))


def main():
    ap = argparse.ArgumentParser(description="AI-driven network intrusion detection")
    ap.add_argument("pcap", nargs="?", help="pcap file to analyse")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--model", default="models/hybrid.joblib")
    ap.add_argument("--list", action="store_true", help="list captures in data/")
    args = ap.parse_args()

    if args.list or not args.pcap:
        data = Path("data")
        caps = sorted(data.glob("*.pcap")) if data.exists() else []
        console.print("[bold]Available captures:[/]")
        for c in caps:
            console.print(f"  {c}")
        if not args.pcap:
            return

    alerts, df, meta = analyze(args.pcap, model_path=args.model)
    if args.json:
        print(json.dumps({"pcap": meta["pcap"], "n_flows": meta["n_flows"],
                          "alerts": alerts}, indent=2, default=str))
    else:
        print_alerts(args.pcap, alerts, meta)


if __name__ == "__main__":
    main()
