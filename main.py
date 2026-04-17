#!/usr/bin/env python3
"""
steganalysis - Command-line interface for the steganalysis tool.

Usage:
    python main.py                  # launch GUI
    python main.py <file>           # analyse a single file (CLI mode)
    python main.py <file> --json    # output results as JSON
    python main.py --help           # show this help
"""

import sys
import json
import argparse

from stegdetector import StegDetector


def cli_main() -> None:
    parser = argparse.ArgumentParser(
        prog="steganalysis",
        description="Detect hidden data in images, audio, video, and archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py photo.jpg
  python main.py audio.wav --json
  python main.py                    # opens the GUI
        """,
    )
    parser.add_argument("file", nargs="?", help="File to analyse")
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON (CLI mode only)",
    )
    args = parser.parse_args()

    if args.file is None:
        # No file argument → launch GUI
        try:
            import tkinter as tk
            from gui import SteganalysisGUI
            from tkinter import ttk
            root = tk.Tk()
            ttk.Style().theme_use('clam')
            SteganalysisGUI(root)
            root.mainloop()
        except ImportError as exc:
            print(f"[ERROR] GUI dependencies missing: {exc}", file=sys.stderr)
            print("Install tkinter or pass a filename to use CLI mode.", file=sys.stderr)
            sys.exit(1)
        return

    # CLI mode
    detector = StegDetector()

    def _progress(msg: str, pct: int) -> None:
        bar = "#" * (pct // 5)
        print(f"\r[{bar:<20}] {pct:3d}%  {msg}", end="", flush=True)

    result = detector.analyze(args.file, _progress)
    print()  # newline after progress bar

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print(f"[ERROR] {result['error']}", file=sys.stderr)
        sys.exit(2)

    print()
    print("=" * 60)
    print("STEGANALYSIS RESULTS")
    print("=" * 60)
    print(f"File     : {result['filename']}")
    print(f"Size     : {result['file_size']:,} bytes")
    print(f"Entropy  : {result['entropy']:.4f} ({result['entropy_status']})")
    print(f"Score    : {result['score']}/100")

    if result['reasons']:
        print("\nFindings:")
        for r in result['reasons']:
            print(f"  • {r}")

    print()
    if result['is_stego']:
        print("VERDICT: STEGO DETECTED  (score >= 50)")
        sys.exit(1)
    else:
        print("VERDICT: CLEAN")
        sys.exit(0)


if __name__ == "__main__":
    cli_main()
