#!/usr/bin/env python3
"""
SteganalysisGUI - Tkinter-based graphical interface for the steganalysis tool.

Provides a dark-themed desktop UI with file browser, progress tracking,
and result display. Generates HTML and text reports automatically.
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime

from stegdetector import StegDetector


class SteganalysisGUI:
    """
    Main application window for the steganalysis tool.

    Wraps StegDetector with a user-friendly interface. Analysis runs
    on a background thread to keep the UI responsive.

    Args:
        root: Tk root window to attach the interface to.
    """

    SUPPORTED_FILETYPES = [
        ("All Files", "*.*"),
        ("Images", "*.jpg *.jpeg *.png *.bmp *.gif"),
        ("Audio", "*.wav *.mp3 *.flac *.ogg"),
        ("Video", "*.mp4 *.avi *.mkv *.mov"),
        ("Archives", "*.rar *.zip *.7z"),
    ]

    FILE_TYPE_MAP = {
        '.jpg': 'JPEG Image', '.jpeg': 'JPEG Image',
        '.png': 'PNG Image',  '.bmp': 'Bitmap Image',
        '.gif': 'GIF Image',  '.wav': 'WAV Audio',
        '.mp3': 'MP3 Audio',  '.mp4': 'MP4 Video',
        '.avi': 'AVI Video',  '.mkv': 'MKV Video',
        '.rar': 'RAR Archive', '.zip': 'ZIP Archive',
        '.7z': '7-Zip Archive', '.exe': 'Executable',
        '.pdf': 'PDF Document', '.txt': 'Text File',
    }

    # Colour palette
    BG_DARK   = '#2c3e50'
    BG_MEDIUM = '#34495e'
    BG_LIGHT  = '#ecf0f1'
    ACCENT    = '#3498db'
    SUCCESS   = '#27ae60'
    DANGER    = '#e74c3c'
    TEXT_MUTED = '#bdc3c7'

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._configure_window()
        self._build_ui()

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _configure_window(self) -> None:
        self.root.title("Steganalysis Tool")
        self.root.geometry("700x640")
        self.root.resizable(True, True)
        self.root.configure(bg=self.BG_DARK)

    def _build_ui(self) -> None:
        self._build_header()
        self._build_main_frame()
        self._build_status_bar()

    def _build_header(self) -> None:
        tk.Label(
            self.root,
            text="Steganalysis Detection Tool",
            font=('Segoe UI', 20, 'bold'),
            bg=self.BG_DARK, fg='white',
        ).pack(pady=(20, 4))

        tk.Label(
            self.root,
            text="Detect hidden data in images, audio, video, and archives",
            font=('Segoe UI', 11),
            bg=self.BG_DARK, fg=self.TEXT_MUTED,
        ).pack(pady=(0, 10))

    def _build_main_frame(self) -> None:
        frame = tk.Frame(self.root, bg=self.BG_MEDIUM, relief='raised', bd=2)
        frame.pack(pady=10, padx=30, fill='both', expand=True)

        self._build_file_selector(frame)
        self._build_file_info(frame)
        self._build_algorithm_display(frame)
        self._build_analyze_button(frame)
        self._build_progress(frame)
        self._build_results(frame)

    def _build_file_selector(self, parent) -> None:
        container = tk.Frame(parent, bg=self.BG_MEDIUM)
        container.pack(pady=16, padx=20, fill='x')

        tk.Label(
            container, text="Select File to Analyse:",
            font=('Segoe UI', 11, 'bold'),
            bg=self.BG_MEDIUM, fg='white',
        ).pack(anchor='w', pady=(0, 6))

        row = tk.Frame(container, bg=self.BG_MEDIUM)
        row.pack(fill='x')

        self.file_path = tk.StringVar()
        tk.Entry(
            row, textvariable=self.file_path,
            font=('Segoe UI', 10),
            bg=self.BG_LIGHT, fg=self.BG_DARK,
            relief='flat', bd=1,
        ).pack(side='left', fill='x', expand=True, ipady=5)

        tk.Button(
            row, text="Browse",
            command=self.browse_file,
            font=('Segoe UI', 10, 'bold'),
            bg=self.ACCENT, fg='white',
            cursor='hand2', relief='flat',
            padx=20,
        ).pack(side='right', padx=(10, 0))

    def _build_file_info(self, parent) -> None:
        info_frame = tk.Frame(parent, bg=self.BG_DARK, relief='sunken', bd=1)
        info_frame.pack(pady=6, padx=20, fill='x')
        self.file_info_label = tk.Label(
            info_frame, text="No file selected",
            font=('Segoe UI', 9),
            bg=self.BG_DARK, fg=self.TEXT_MUTED, justify='left',
        )
        self.file_info_label.pack(pady=10, padx=10, anchor='w')

    def _build_algorithm_display(self, parent) -> None:
        container = tk.Frame(parent, bg=self.BG_MEDIUM)
        container.pack(pady=6, padx=20, fill='x')

        tk.Label(
            container, text="Algorithms selected:",
            font=('Segoe UI', 10, 'bold'),
            bg=self.BG_MEDIUM, fg='white',
        ).pack(anchor='w')

        self.algo_text = tk.Text(
            container, height=3,
            font=('Segoe UI', 9),
            bg=self.BG_DARK, fg=self.ACCENT,
            relief='flat', bd=1,
        )
        self.algo_text.pack(fill='x', pady=4)

    def _build_analyze_button(self, parent) -> None:
        self.analyze_btn = tk.Button(
            parent, text="Analyse File",
            command=self.start_analysis,
            font=('Segoe UI', 12, 'bold'),
            bg=self.SUCCESS, fg='white',
            cursor='hand2', relief='flat',
            padx=30, pady=10, state='disabled',
        )
        self.analyze_btn.pack(pady=12)

    def _build_progress(self, parent) -> None:
        style = ttk.Style()
        style.configure(
            'green.Horizontal.TProgressbar',
            background=self.SUCCESS,
            troughcolor=self.BG_DARK,
        )
        self.progress = ttk.Progressbar(
            parent, length=400, mode='determinate',
            style='green.Horizontal.TProgressbar',
        )
        self.progress.pack(pady=4)

        self.progress_label = tk.Label(
            parent, text="",
            font=('Segoe UI', 9),
            bg=self.BG_MEDIUM, fg=self.TEXT_MUTED,
        )
        self.progress_label.pack()

    def _build_results(self, parent) -> None:
        container = tk.Frame(parent, bg=self.BG_MEDIUM)
        container.pack(pady=12, padx=20, fill='both', expand=True)

        self.results_text = tk.Text(
            container, height=9,
            font=('Consolas', 9),
            bg=self.BG_DARK, fg='#ecf0f0',
            relief='flat', bd=1, wrap='word',
        )
        self.results_text.pack(side='left', fill='both', expand=True)

        scrollbar = tk.Scrollbar(container, command=self.results_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.results_text.config(yscrollcommand=scrollbar.set)

        self.results_text.tag_configure(
            "stego", foreground="#ff6b6b",
            font=('Consolas', 10, 'bold'),
        )
        self.results_text.tag_configure(
            "clean", foreground="#51cf66",
            font=('Consolas', 10, 'bold'),
        )
        self.results_text.tag_configure("info", foreground="#74b9ff")

    def _build_status_bar(self) -> None:
        self.status_label = tk.Label(
            self.root, text="Ready",
            font=('Segoe UI', 9),
            bg='#1a252f', fg='#95a5a6',
            relief='flat', anchor='w',
        )
        self.status_label.pack(side='bottom', fill='x', ipady=3, padx=2, pady=2)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def browse_file(self) -> None:
        """Open a file-picker dialog and populate the path entry."""
        filename = filedialog.askopenfilename(
            title="Select a file to analyse",
            filetypes=self.SUPPORTED_FILETYPES,
        )
        if filename:
            self.file_path.set(filename)
            self._update_file_info(filename)
            self.analyze_btn.config(state='normal', bg=self.SUCCESS)
            self.status_label.config(text=f"Selected: {os.path.basename(filename)}")

    def _update_file_info(self, filepath: str) -> None:
        if not os.path.exists(filepath):
            return
        size = os.path.getsize(filepath)
        ext = os.path.splitext(filepath)[1].lower()
        file_type = self.FILE_TYPE_MAP.get(ext, f"Unknown ({ext.upper()})")
        info = (
            f"File: {os.path.basename(filepath)}\n"
            f"Size: {size:,} bytes  ({size / 1024:.2f} KB)\n"
            f"Type: {file_type}"
        )
        self.file_info_label.config(text=info)
        self._show_algorithms_for_ext(ext)

    def _show_algorithms_for_ext(self, ext: str) -> None:
        algorithms = ["Entropy Analysis", "EOF Analysis", "String Analysis"]
        if ext in ('.jpg', '.jpeg', '.png', '.bmp', '.gif'):
            algorithms += ["LSB Steganalysis", "Steghide Detection"]
        if ext in ('.wav', '.mp3'):
            algorithms += ["Audio Steganalysis", "Steghide Detection"]
        if ext in ('.mp4', '.avi', '.mkv'):
            algorithms.append("Video Steganalysis")
        algorithms += ["Archive Detection", "Executable Detection"]
        self.algo_text.delete(1.0, tk.END)
        self.algo_text.insert(1.0, "  •  ".join(dict.fromkeys(algorithms)[:6]) + " …")

    def start_analysis(self) -> None:
        """Validate selection and launch background analysis thread."""
        filepath = self.file_path.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        self.analyze_btn.config(state='disabled', text="Analysing…")
        self.results_text.delete(1.0, tk.END)
        self.progress['value'] = 0
        self.progress_label.config(text="Starting analysis…")

        t = threading.Thread(target=self._run_analysis, args=(filepath,), daemon=True)
        t.start()

    def _run_analysis(self, filepath: str) -> None:
        detector = StegDetector()
        result = detector.analyze(filepath, self._update_progress)
        self.root.after(0, lambda: self._display_results(result))

    def _update_progress(self, message: str, value: int) -> None:
        self.root.after(0, lambda: (
            self.progress.__setitem__('value', value),
            self.progress_label.config(text=message),
            self.status_label.config(text=message),
        ))

    # ------------------------------------------------------------------
    # Results display
    # ------------------------------------------------------------------

    def _display_results(self, result: dict) -> None:
        rt = self.results_text
        rt.delete(1.0, tk.END)

        if 'error' in result:
            rt.insert(tk.END, f"Error: {result['error']}\n", "stego")
            self._reset_controls("Analysis failed")
            return

        rt.insert(tk.END, "=" * 58 + "\n")
        rt.insert(tk.END, "STEGANALYSIS RESULTS\n")
        rt.insert(tk.END, "=" * 58 + "\n\n")

        rt.insert(tk.END, f"File:     {result['filename']}\n", "info")
        rt.insert(tk.END, f"Size:     {result['file_size']:,} bytes\n")
        rt.insert(tk.END, f"Type:     {result['file_ext'].upper()}\n")
        rt.insert(tk.END, f"Entropy:  {result['entropy']:.4f} ({result['entropy_status']})\n\n")

        rt.insert(tk.END, "Algorithms applied:\n", "info")
        for algo in result['algorithms_used']:
            rt.insert(tk.END, f"  • {algo}\n")
        rt.insert(tk.END, "\n")

        if result['reasons']:
            rt.insert(tk.END, "Findings:\n", "info")
            for reason in result['reasons']:
                rt.insert(tk.END, f"  • {reason}\n")
        else:
            rt.insert(tk.END, "Findings: None\n", "clean")

        rt.insert(tk.END, "\n" + "-" * 58 + "\n")
        rt.insert(tk.END, f"Score: {result['score']}/100\n")

        if result['is_stego']:
            rt.insert(tk.END, "\nVERDICT: STEGO DETECTED\n", "stego")
            rt.insert(tk.END, "This file likely contains hidden data!\n", "stego")
            self.status_label.config(text=f"STEGO DETECTED in {result['filename']}")
        else:
            rt.insert(tk.END, "\nVERDICT: CLEAN\n", "clean")
            rt.insert(tk.END, "No steganography detected.\n", "clean")
            self.status_label.config(text=f"Clean: {result['filename']}")

        rt.insert(tk.END, "\n" + "=" * 58 + "\n")
        rt.insert(tk.END, f"MD5:    {result['hashes']['md5']}\n", "info")
        rt.insert(tk.END, f"SHA256: {result['hashes']['sha256'][:48]}…\n", "info")

        report_path = self._generate_reports(result)
        rt.insert(tk.END, f"\nReports saved to: {report_path}\n", "info")

        self._reset_controls("Analysis complete!")

    def _reset_controls(self, status: str) -> None:
        self.analyze_btn.config(state='normal', text="Analyse File")
        self.progress['value'] = 100
        self.progress_label.config(text=status)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _generate_reports(self, result: dict) -> str:
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = result['filename'].replace('.', '_')

        # Plain-text report
        txt_path = os.path.join(report_dir, f"{safe_name}_{timestamp}_report.txt")
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("STEGANALYSIS REPORT\n")
            f.write("=" * 70 + "\n\n")
            for key, val in [
                ("File", result['filename']),
                ("Path", result['filepath']),
                ("Size", f"{result['file_size']:,} bytes"),
                ("Type", result['file_ext'].upper()),
                ("Entropy", f"{result['entropy']:.4f}"),
                ("Score", f"{result['score']}/100"),
                ("Verdict", "STEGO DETECTED" if result['is_stego'] else "CLEAN"),
                ("Time", result['timestamp']),
                ("MD5", result['hashes']['md5']),
                ("SHA256", result['hashes']['sha256']),
            ]:
                f.write(f"{key:<10}: {val}\n")

            if result['reasons']:
                f.write("\nFindings:\n")
                for reason in result['reasons']:
                    f.write(f"  • {reason}\n")

        # HTML report
        html_path = os.path.join(report_dir, f"{safe_name}_{timestamp}_report.html")
        verdict_color = "#e74c3c" if result['is_stego'] else "#27ae60"
        verdict_text = "STEGO DETECTED" if result['is_stego'] else "CLEAN"
        findings_html = "".join(f"<li>{r}</li>" for r in result['reasons']) or "<li>None</li>"

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Steganalysis Report – {result['filename']}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#1a1a2e; color:#eee; margin:2rem; }}
  h1   {{ color:#3498db; }}
  table {{ border-collapse:collapse; width:100%; max-width:600px; }}
  td, th {{ padding:.5rem 1rem; border:1px solid #444; }}
  th {{ background:#2c3e50; text-align:left; }}
  .verdict {{ font-size:1.5rem; font-weight:bold; color:{verdict_color}; margin:1.5rem 0; }}
  .score {{ font-size:1.1rem; }}
  ul {{ padding-left:1.5rem; }}
</style>
</head>
<body>
<h1>Steganalysis Report</h1>
<div class="verdict">{verdict_text}</div>
<div class="score">Score: {result['score']}/100</div>
<h2>File Details</h2>
<table>
  <tr><th>File</th><td>{result['filename']}</td></tr>
  <tr><th>Size</th><td>{result['file_size']:,} bytes</td></tr>
  <tr><th>Type</th><td>{result['file_ext'].upper()}</td></tr>
  <tr><th>Entropy</th><td>{result['entropy']:.4f} ({result['entropy_status']})</td></tr>
  <tr><th>MD5</th><td>{result['hashes']['md5']}</td></tr>
  <tr><th>SHA-256</th><td style="font-size:.85em">{result['hashes']['sha256']}</td></tr>
  <tr><th>Analysed</th><td>{result['timestamp']}</td></tr>
</table>
<h2>Findings</h2>
<ul>{findings_html}</ul>
</body>
</html>""")

        return report_dir


def main() -> None:
    """Launch the GUI application."""
    root = tk.Tk()
    ttk.Style().theme_use('clam')
    SteganalysisGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
