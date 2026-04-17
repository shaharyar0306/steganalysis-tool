# steganalysis-tool
🔍 Advanced steganalysis tool for detecting hidden data in images, audio, video, and archives
# 🔍 Steganalysis Tool - Steg Detection Suite

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**A comprehensive steganalysis tool that detects hidden data in images, audio, video, and archive files using multiple detection algorithms.**

![Steganalysis Tool GUI](screenshots/gui_main.png)

## 📋 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Detection Methods](#-detection-methods)
- [Supported Formats](#-supported-formats)
- [Screenshots](#-screenshots)
- [How It Works](#-how-it-works)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🎯 Core Capabilities
- **Multi-format Support**: Images, Audio, Video, Archives, Executables
- **Automatic File Type Detection**: Smart algorithm selection based on file type
- **Dual Interface**: GUI mode and Command-line mode
- **Detailed Reports**: Generates HTML and Text reports
- **Real-time Analysis**: Progress tracking and live results

### 🔬 Detection Algorithms
| Algorithm | Description |
|-----------|-------------|
| 📊 **Entropy Analysis** | Detects anomalies in data randomness |
| 📎 **EOF Analysis** | Identifies appended data after file end |
| 🎨 **LSB Steganalysis** | Statistical LSB distribution analysis |
| 🔐 **Steghide Detection** | Identifies steghide embedded content |
| 🗜️ **Archive Detection** | Detects RAR/ZIP embedded in files |
| ⚙️ **Executable Detection** | Finds hidden executable code |
| 🔍 **String Analysis** | Searches for stego-related keywords |

## 📥 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/steganalysis-tool.git
cd steganalysis-tool

# Install dependencies
pip install -r requirements.txt

# Run the tool
python steganalyzer.py
