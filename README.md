# Steganalysis Tool

A desktop and CLI tool for detecting steganography — hidden data embedded inside
image, audio, video, and archive files. Built in Python with a Tkinter GUI and a
clean, importable analysis engine.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

---

## Features

| Algorithm | Supported formats |
|-----------|------------------|
| Shannon entropy analysis | All |
| EOF / appended-data detection | JPEG, PNG |
| Binary signature scanning (RAR, ZIP, EXE) | All |
| Stego-tool signature detection (steghide, OutGuess, F5, JSteg) | All |
| Suspicious string extraction | All |
| LSB (Least Significant Bit) steganalysis | PNG, BMP |
| Steghide probe integration | JPEG, BMP, WAV |

**Output:** suspicion score 0–100, plaintext report, and HTML report saved to `reports/`.

---

## Quick start

### Prerequisites

```
Python 3.10+
Pillow           (LSB analysis)
steghide         (optional – LSB probe via external tool)
```

### Install

```bash
git clone https://github.com/your-username/steganalysis-tool.git
cd steganalysis-tool
pip install -r requirements.txt
```

### Run (GUI)

```bash
python main.py
```

### Run (CLI)

```bash
# Analyse a single file
python main.py suspicious_photo.jpg

# Output raw JSON
python main.py suspicious_photo.jpg --json

# Exit code 0 = clean, 1 = stego detected, 2 = error
echo $?
```

---

## Usage examples

```bash
# Analyse a JPEG
python main.py holiday.jpg

# Analyse a WAV file and get JSON
python main.py recording.wav --json | python -m json.tool

# Batch scan a folder (bash)
for f in samples/*; do python main.py "$f"; done
```

### Importing as a library

```python
from stegdetector import StegDetector

detector = StegDetector()
result = detector.analyze("photo.jpg")

print(result['score'])      # 0–100
print(result['is_stego'])   # True / False
print(result['reasons'])    # list of triggered findings
```

---

## Repository layout

```
steganalysis-tool/
├── main.py           # CLI entry-point + GUI launcher
├── stegdetector.py   # Core analysis engine (no UI dependency)
├── gui.py            # Tkinter GUI (imports stegdetector)
├── requirements.txt
├── tests/
│   └── test_stegdetector.py
├── docs/
│   └── algorithms.md
├── assets/
│   └── screenshot.png
└── reports/          # auto-created at runtime
```

---

## Scoring

Each algorithm contributes a weighted score. A total ≥ 50 triggers a
**STEGO DETECTED** verdict.

| Finding | Score |
|---------|-------|
| RAR signature inside file | +50 |
| Steghide embedded data | +50 |
| ZIP signature inside file | +45 |
| Executable signature (MZ, PE) | +40 |
| Stego-tool name in file | +35 |
| Suspicious appended data | +25 |
| LSB distribution anomaly | +25 |
| Stego-related strings (≥ 2) | +20 |
| Entropy above format threshold | +10 |

Scores are capped at 100.

---

## Running the tests

```bash
pytest tests/ -v
```

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-algorithm`
3. Add tests in `tests/`.
4. Open a pull request against `main`.

Please keep the core `StegDetector` class free of GUI dependencies so it remains
importable in headless environments.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This tool is intended for **legitimate digital forensics, CTF challenges, and
security research** only. Do not use it to conceal or extract unlawful content.
