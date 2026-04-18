# 🔍 Steganalysis Tool

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

A Python tool with a **dark-themed GUI** that analyzes files for hidden steganographic data. Supports images, audio, video, and archives. Runs on Windows, Linux, and macOS.

---

## What It Does

Loads a file and runs up to **9 detection checks** depending on the file type, then gives a **score out of 100** and a clear verdict: **CLEAN** or **STEGO DETECTED**.

| Detection Check | What It Looks For |
|---|---|
| **Entropy Analysis** | Shannon entropy above normal thresholds for the file format |
| **EOF / Appended Data** | Bytes hidden after JPEG `FF D9` or PNG `IEND` markers |
| **RAR Signature** | RAR archive bytes (`Rar!\x1a\x07`) embedded inside the file |
| **ZIP Signature** | ZIP/PK bytes (`PK\x03\x04`) embedded inside the file |
| **Executable Signature** | `MZ`, `PE`, `@echo`, or `powershell` bytes inside the file |
| **Stego Tool Signatures** | Strings from `steghide`, `OutGuess`, `F5`, `JSteg` |
| **String Analysis** | Keywords like `password=`, `BEGIN PGP`, `base64:`, `encrypted:` |
| **Steghide Integration** | Calls `steghide info <file>` and checks for embedded data |
| **LSB Analysis** | LSB bit distribution in PNG/BMP pixels (flags if ratio deviates > 0.08) |

---

## Scoring

Each triggered check adds a weighted score. Total is capped at 100.

| Finding | Score |
|---|---|
| RAR signature detected | +50 |
| Steghide embedded data confirmed | +50 |
| ZIP signature detected | +45 |
| Executable signature detected | +40 |
| Stego tool string found | +35 |
| Suspicious appended data | +25 |
| LSB anomaly | +25 |
| Stego-related strings (≥ 2) | +20 |
| High entropy | +10 |

**Verdict:** score ≥ 50 → 🔴 **STEGO DETECTED** &nbsp;|&nbsp; score < 50 → 🟢 **CLEAN**

---

## Supported File Types

| Type | Formats | Checks Applied |
|---|---|---|
| Images (JPEG) | `.jpg` `.jpeg` | Entropy, EOF, RAR, ZIP, EXE, Stego tools, Strings, Steghide |
| Images (lossless) | `.png` `.bmp` | Entropy, EOF, RAR, ZIP, EXE, Stego tools, Strings, LSB |
| Images (other) | `.gif` | Entropy, RAR, ZIP, EXE, Stego tools, Strings |
| Audio | `.wav` `.mp3` `.flac` `.ogg` | Entropy, RAR, ZIP, EXE, Stego tools, Strings (+ Steghide for WAV) |
| Video | `.mp4` `.avi` `.mkv` `.mov` | Entropy, RAR, ZIP, EXE, Stego tools, Strings |
| Archives | `.rar` `.zip` `.7z` | Entropy, RAR, ZIP, EXE, Stego tools, Strings |

---

## Installation

**Requirements:** Python 3.7+, tkinter (included with Python on Windows/macOS)

```bash
git clone https://github.com/shaharyar0306/steganalysis-tool.git
cd steganalysis-tool
pip install -r requirements.txt
```

**On Linux**, install tkinter separately if needed:
```bash
sudo apt install python3-tk
```

**Steghide** (optional — enables the steghide detection check):
```bash
# Ubuntu/Debian
sudo apt install steghide

# Windows: download from https://steghide.sourceforge.net
```

---

## Usage

### GUI Mode
```bash
python steganalyzer.py
```

1. Click **📂 Browse** and select any file
2. The tool shows file info and which algorithms will run
3. Click **🔍 Analyze File** and watch the progress bar
4. Read the verdict and findings in the results panel
5. Reports are automatically saved to the `reports/` folder

### Command Line Mode
```bash
python steganalyzer.py path/to/file.jpg
```

Output:
```
🔴 STEGO DETECTED - Score: 75/100
# or
🟢 CLEAN - Score: 15/100
```

---

## Output Reports

After every analysis two report files are saved to `reports/`:

**`filename_YYYYMMDD_HHMMSS_report.txt`**
```
======================================================================
STEGANALYSIS REPORT
======================================================================
File:     suspicious.jpg
Path:     /home/user/suspicious.jpg
Size:     155,589 bytes
Type:     .JPEG
Entropy:  7.9988
Score:    75/100
Verdict:  STEGO DETECTED
Time:     2026-04-18 14:30:25
MD5:      73eff2a5064fcd5da9614813bb13697b
SHA256:   5f665c657a6779ad89fdee31e17635...
```

**`filename_YYYYMMDD_HHMMSS_report.html`** — same information in a dark-themed HTML page with colour-coded verdict and findings list.

---

## GUI Overview

```
┌─────────────────────────────────────────────┐
│  🔍 Steganalysis Detection Tool             │
│  Detect hidden data in images, audio...     │
├─────────────────────────────────────────────┤
│  Select File: [________________] [📂 Browse]│
│                                             │
│  📁 File: photo.jpg                         │
│  📊 Size: 155,589 bytes  (151.94 KB)        │
│  🔖 Type: JPEG Image                        │
│                                             │
│  🛠️ Algorithms: Entropy • EOF • LSB • ...   │
│                                             │
│         [ 🔍 Analyze File ]                 │
│  [████████████████░░░░░░░░░░] 60%           │
│                                             │
│  ====== STEGANALYSIS RESULTS ======         │
│  File: photo.jpg                            │
│  Score: 75/100                              │
│  🔴 VERDICT: STEGO DETECTED                 │
└─────────────────────────────────────────────┘
```

---

## Code Structure

```
steganalyzer.py
│
├── class StegDetector
│   ├── calculate_entropy()       Shannon entropy calculation
│   ├── extract_strings()         Printable ASCII string extraction
│   ├── check_steghide()          steghide subprocess integration
│   ├── get_file_hashes()         MD5 and SHA256 hash calculation
│   ├── analyze_appended_data()   EOF / appended data detection
│   └── analyze()                 Main analysis — runs all checks
│
├── class SteganalysisGUI
│   ├── browse_file()             File picker dialog
│   ├── update_file_info()        Shows file name, size, type
│   ├── show_algorithms_for_type() Shows which checks will run
│   ├── start_analysis()          Spawns background thread
│   ├── run_analysis()            Calls StegDetector.analyze()
│   ├── display_results()         Renders verdict in the GUI
│   └── generate_reports()        Writes .txt and .html to reports/
│
└── main()                        Launches the Tkinter window
```

---

## Project Files

| File | Description |
|---|---|
| `steganalyzer.py` | Main script — GUI + all detection logic |
| `requirements.txt` | `Pillow` (for LSB analysis) |
| `LICENSE` | MIT |
| `README.md` | This file |
| `reports/` | Auto-created — stores generated reports |
| `screenshots/` | Tool screenshots |

---

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Shaharyar

---

## Author

**Shaharyar** · [@shaharyar0306](https://github.com/shaharyar0306)

---

*Made with Python and Tkinter for digital forensics and CTF challenges.*
