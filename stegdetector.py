#!/usr/bin/env python3
"""
StegDetector - Core steganography detection engine.

Provides accurate steganalysis with reduced false positives across
images, audio, video, and archive files.
"""

import os
import math
import hashlib
import subprocess
from datetime import datetime
from collections import Counter


class StegDetector:
    """
    Steganography detection engine with multi-algorithm analysis.

    Supports entropy analysis, LSB steganalysis, signature detection,
    EOF data analysis, and steghide integration.

    Example:
        >>> detector = StegDetector()
        >>> result = detector.analyze("suspicious_image.jpg")
        >>> print(result['score'], result['is_stego'])
    """

    # Known steganography tool signatures
    RAR_SIGNATURES = [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00']
    ZIP_SIGNATURES = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
    EXE_SIGNATURES = [b'MZ', b'PE\x00\x00', b'@echo', b'powershell']
    STEGO_TOOL_SIGNATURES = [b'steghide', b'OutGuess', b'F5', b'JSteg']

    SUSPICIOUS_KEYWORDS = [
        'password=', 'secretkey', 'hiddenfile', 'stegpassword',
        'base64:', 'encrypted:', 'BEGIN RSA', 'BEGIN PGP'
    ]

    # Per-format entropy thresholds (above these = suspicious)
    ENTROPY_THRESHOLDS = {
        '.jpg': 7.98,
        '.jpeg': 7.98,
        '.png': 7.80,
        '.bmp': 7.00,
    }
    DEFAULT_ENTROPY_THRESHOLD = 7.95

    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte sequence.

        Args:
            data: Raw bytes to analyse.

        Returns:
            Entropy value in bits (0.0 – 8.0). Higher values indicate
            more randomness, which can suggest encrypted/compressed payloads.
        """
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def extract_strings(self, data: bytes, min_length: int = 4) -> list[str]:
        """
        Extract printable ASCII strings from binary data.

        Args:
            data: Raw bytes to scan.
            min_length: Minimum string length to keep (default 4).

        Returns:
            List of lowercased printable strings found.
        """
        strings = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current).lower())
                current = []
        if len(current) >= min_length:
            strings.append(''.join(current).lower())
        return strings

    def check_steghide(self, filepath: str) -> bool:
        """
        Probe a file for steghide-embedded data (no passphrase needed).

        Requires steghide to be installed and on PATH. Silently returns
        False if steghide is unavailable.

        Args:
            filepath: Path to the image or audio file.

        Returns:
            True if steghide reports embedded data, False otherwise.
        """
        try:
            result = subprocess.run(
                ['steghide', 'info', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = (result.stdout + result.stderr).lower()
            return 'embedded data' in output
        except Exception:
            return False

    def get_file_hashes(self, filepath: str) -> dict[str, str]:
        """
        Compute MD5 and SHA-256 hashes of a file.

        Args:
            filepath: Path to the target file.

        Returns:
            Dict with 'md5' and 'sha256' hex-digest strings.
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha256.update(chunk)
        return {'md5': md5.hexdigest(), 'sha256': sha256.hexdigest()}

    def analyze_appended_data(
        self, data: bytes, file_ext: str
    ) -> tuple[int, bool]:
        """
        Detect data appended after the logical end-of-file marker.

        Handles JPEG multi-EOI (thumbnails, Photoshop) and PNG IEND
        correctly to avoid false positives from legitimate metadata.

        Args:
            data: Full file contents as bytes.
            file_ext: Lowercase file extension (e.g. '.jpg').

        Returns:
            (appended_byte_count, is_suspicious) tuple.
        """
        if file_ext in ('.jpg', '.jpeg'):
            eoi_positions = []
            pos = 0
            while True:
                pos = data.find(b'\xff\xd9', pos)
                if pos == -1:
                    break
                eoi_positions.append(pos)
                pos += 1

            # Multiple EOIs = EXIF thumbnail; not suspicious
            if len(eoi_positions) > 1:
                return 0, False

            if eoi_positions:
                eoi = eoi_positions[0]
                extra = len(data) - (eoi + 2)
                if extra > 0:
                    snippet = data[eoi + 2: eoi + 2 + min(100, extra)]
                    if snippet[:2] == b'\xff\xd8':
                        return 0, False
                    if any(m in snippet for m in (b'Photoshop', b'Adobe', b'http://ns.adobe.com')):
                        return 0, False
                return extra, extra > 1000

        elif file_ext == '.png':
            iend = data.rfind(b'IEND')
            if iend != -1:
                extra = len(data) - (iend + 8)
                return extra, extra > 100

        return 0, False

    def analyze(
        self,
        filepath: str,
        progress_callback=None
    ) -> dict:
        """
        Run full steganalysis on a file.

        Applies all applicable detection algorithms and returns a
        comprehensive result dict with a suspicion score 0–100.

        Args:
            filepath: Absolute or relative path to the file.
            progress_callback: Optional callable(message: str, pct: int)
                               invoked at each analysis stage.

        Returns:
            Result dict with keys: filename, filepath, file_size,
            file_ext, entropy, entropy_status, appended_bytes,
            rar_detected, zip_detected, exe_detected, lsb_ratio,
            suspicious_strings, reasons, algorithms_used, score,
            is_stego, hashes, timestamp.
            On error: {'error': '<message>'}.
        """
        if not os.path.exists(filepath):
            return {'error': 'File not found'}

        def _progress(msg, pct):
            if progress_callback:
                progress_callback(msg, pct)

        _progress("Reading file…", 10)
        with open(filepath, 'rb') as f:
            data = f.read()

        file_size = len(data)
        file_ext = os.path.splitext(filepath)[1].lower()
        filename = os.path.basename(filepath)

        stego_score = 0
        reasons = []
        algorithms_used = []

        # Auto-select algorithms by file type
        if file_ext in ('.jpg', '.jpeg', '.png', '.bmp', '.gif'):
            algorithms_used.append("Image Steganalysis")
        if file_ext in ('.wav', '.mp3', '.flac', '.ogg'):
            algorithms_used.append("Audio Steganalysis")
        if file_ext in ('.mp4', '.avi', '.mkv', '.mov'):
            algorithms_used.append("Video Steganalysis")
        if file_ext in ('.rar', '.zip', '.7z'):
            algorithms_used.append("Archive Analysis")

        _progress("Calculating hashes…", 20)
        hashes = self.get_file_hashes(filepath)

        _progress("Analysing entropy…", 30)
        entropy = self.calculate_entropy(data)
        algorithms_used.append("Entropy Analysis")

        limit = self.ENTROPY_THRESHOLDS.get(file_ext, self.DEFAULT_ENTROPY_THRESHOLD)
        entropy_status = "Normal"
        if entropy > limit:
            stego_score += 10
            reasons.append(f"Very high entropy ({entropy:.3f} > {limit})")
            entropy_status = "High"

        _progress("Checking for appended data…", 40)
        appended_bytes, is_suspicious = self.analyze_appended_data(data, file_ext)
        if is_suspicious:
            stego_score += 25
            reasons.append(f"Suspicious appended data ({appended_bytes} bytes)")
            algorithms_used.append("EOF Analysis")

        _progress("Scanning for binary signatures…", 50)
        rar_detected = False
        for sig in self.RAR_SIGNATURES:
            if sig in data:
                stego_score += 50
                reasons.append("RAR archive signature detected")
                rar_detected = True
                algorithms_used.append("WinRAR Detection")
                break

        zip_detected = False
        for sig in self.ZIP_SIGNATURES:
            if sig in data:
                stego_score += 45
                reasons.append("ZIP archive signature detected")
                zip_detected = True
                algorithms_used.append("ZIP Detection")
                break

        exe_detected = ""
        for sig in self.EXE_SIGNATURES:
            if sig in data:
                stego_score += 40
                exe_detected = sig.decode('utf-8', errors='ignore')[:20]
                reasons.append(f"Executable signature: {exe_detected}")
                algorithms_used.append("Executable Detection")
                break

        _progress("Checking stego-tool signatures…", 60)
        for sig in self.STEGO_TOOL_SIGNATURES:
            if sig in data:
                stego_score += 35
                reasons.append(f"Stego tool signature: {sig.decode('utf-8', errors='ignore')}")
                algorithms_used.append("Tool Signature Detection")
                break

        strings = self.extract_strings(data)
        suspicious_found = [
            s[:50] for s in strings
            if any(kw in s for kw in self.SUSPICIOUS_KEYWORDS)
        ]
        if len(suspicious_found) >= 2:
            stego_score += 20
            reasons.append(f"Stego-related strings ({len(suspicious_found)} found)")
            algorithms_used.append("String Analysis")

        _progress("Running steghide probe…", 70)
        if file_ext in ('.jpg', '.jpeg', '.bmp', '.wav'):
            if self.check_steghide(filepath):
                stego_score += 50
                reasons.append("Steghide embedded data detected")
                algorithms_used.append("Steghide Detection")

        _progress("LSB steganalysis…", 80)
        lsb_ratio = None
        if file_ext in ('.png', '.bmp'):
            try:
                from PIL import Image
                img = Image.open(filepath)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                pixels = list(img.getdata())[:10000]
                lsb_ones = sum((r & 1) + (g & 1) + (b & 1) for r, g, b in pixels)
                lsb_ratio = lsb_ones / (len(pixels) * 3)
                if abs(0.5 - lsb_ratio) > 0.08:
                    stego_score += 25
                    reasons.append(f"LSB anomaly (ratio: {lsb_ratio:.3f})")
                    algorithms_used.append("LSB Steganalysis")
            except Exception:
                pass

        _progress("Generating report…", 90)

        return {
            'filename': filename,
            'filepath': filepath,
            'file_size': file_size,
            'file_ext': file_ext,
            'entropy': entropy,
            'entropy_status': entropy_status,
            'appended_bytes': appended_bytes,
            'rar_detected': rar_detected,
            'zip_detected': zip_detected,
            'exe_detected': exe_detected,
            'lsb_ratio': lsb_ratio,
            'suspicious_strings': suspicious_found[:10],
            'reasons': reasons,
            'algorithms_used': list(set(algorithms_used)),
            'score': min(100, stego_score),
            'is_stego': stego_score >= 50,
            'hashes': hashes,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
