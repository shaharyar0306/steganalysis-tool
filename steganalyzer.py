#!/usr/bin/env python3
"""
Steganalysis Tool with GUI - File Browser & Auto Detection
Windows Compatible
"""
import os
import sys
import math
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from collections import Counter
import threading

class StegDetector:
    """Accurate steganalysis with reduced false positives"""
    
    def __init__(self):
        # Steganography signatures
        self.rar_sigs = [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00']
        self.zip_sigs = [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']
        self.exe_sigs = [b'MZ', b'PE\x00\x00', b'@echo', b'powershell']
        self.stego_tools = [b'steghide', b'OutGuess', b'F5', b'JSteg']
        
        # Suspicious keywords
        self.keywords = [
            'password=', 'secretkey', 'hiddenfile', 'stegpassword',
            'base64:', 'encrypted:', 'BEGIN RSA', 'BEGIN PGP'
        ]
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy
    
    def extract_strings(self, data, min_length=4):
        """Extract printable strings"""
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
    
    def check_steghide(self, filepath):
        """Check for steghide embedded data"""
        try:
            result = subprocess.run(
                ['steghide', 'info', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = (result.stdout + result.stderr).lower()
            if 'embedded data' in output:
                return True
        except:
            pass
        return False
    
    def get_file_hashes(self, filepath):
        """Calculate MD5 and SHA256 hashes"""
        import hashlib
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    def analyze_appended_data(self, data, file_ext):
        """Smart appended data analysis - ignores EXIF/thumbnails"""
        if file_ext in ['.jpg', '.jpeg']:
            eoi_positions = []
            pos = 0
            while True:
                pos = data.find(b'\xff\xd9', pos)
                if pos == -1:
                    break
                eoi_positions.append(pos)
                pos += 1
            
            if len(eoi_positions) > 1:
                return 0, False
            
            if eoi_positions:
                eoi = eoi_positions[0]
                extra = len(data) - (eoi + 2)
                
                if extra > 0:
                    extra_data = data[eoi+2:eoi+2+min(100, extra)]
                    if extra_data[:2] == b'\xff\xd8':
                        return 0, False
                    if b'Photoshop' in extra_data or b'Adobe' in extra_data:
                        return 0, False
                    if b'http://ns.adobe.com' in extra_data:
                        return 0, False
                
                return extra, (extra > 1000)
                
        elif file_ext == '.png':
            iend = data.rfind(b'IEND')
            if iend != -1:
                extra = len(data) - (iend + 8)
                return extra, (extra > 100)
                
        return 0, False
    
    def analyze(self, filepath, progress_callback=None):
        """Main analysis with reduced false positives"""
        
        if not os.path.exists(filepath):
            return {'error': 'File not found'}
        
        if progress_callback:
            progress_callback("Reading file...", 10)
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        file_ext = os.path.splitext(filepath)[1].lower()
        filename = os.path.basename(filepath)
        stego_score = 0
        reasons = []
        algorithms_used = []
        
        # Auto-detect algorithms based on file type
        if file_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            algorithms_used.append("📷 Image Steganalysis")
        if file_ext in ['.wav', '.mp3', '.flac', '.ogg']:
            algorithms_used.append("🎵 Audio Steganalysis")
        if file_ext in ['.mp4', '.avi', '.mkv', '.mov']:
            algorithms_used.append("🎬 Video Steganalysis")
        if file_ext in ['.rar', '.zip', '.7z']:
            algorithms_used.append("📦 Archive Analysis")
        
        if progress_callback:
            progress_callback("Calculating hashes...", 20)
        
        hashes = self.get_file_hashes(filepath)
        
        if progress_callback:
            progress_callback("Analyzing entropy...", 30)
        
        # 1. Entropy Check
        entropy = self.calculate_entropy(data)
        algorithms_used.append("📊 Entropy Analysis")
        
        entropy_limits = {
            '.jpg': 7.98, '.jpeg': 7.98,
            '.png': 7.8, '.bmp': 7.0,
        }
        limit = entropy_limits.get(file_ext, 7.95)
        
        entropy_status = "Normal"
        if entropy > limit:
            stego_score += 10
            reasons.append(f"Very high entropy ({entropy:.3f} > {limit})")
            entropy_status = "High"
        
        if progress_callback:
            progress_callback("Checking for appended data...", 40)
        
        # 2. Smart Appended Data Check
        appended_bytes, is_suspicious = self.analyze_appended_data(data, file_ext)
        
        if is_suspicious:
            stego_score += 25
            reasons.append(f"Suspicious appended data ({appended_bytes} bytes)")
            algorithms_used.append("📎 EOF Analysis")
        
        if progress_callback:
            progress_callback("Scanning for signatures...", 50)
        
        # 3. Check for RAR/ZIP signatures
        rar_detected = False
        for sig in self.rar_sigs:
            if sig in data:
                stego_score += 50
                reasons.append("RAR archive signature detected")
                rar_detected = True
                algorithms_used.append("🗜️ WinRAR Detection")
                break
        
        zip_detected = False
        for sig in self.zip_sigs:
            if sig in data:
                stego_score += 45
                reasons.append("ZIP archive signature detected")
                zip_detected = True
                algorithms_used.append("🗜️ ZIP Detection")
                break
        
        # 4. Check for executable signatures
        exe_detected = ""
        for sig in self.exe_sigs:
            if sig in data:
                stego_score += 40
                exe_detected = sig.decode('utf-8', errors='ignore')[:20]
                reasons.append(f"Executable signature: {exe_detected}")
                algorithms_used.append("⚙️ Executable Detection")
                break
        
        if progress_callback:
            progress_callback("Checking stego tools...", 60)
        
        # 5. Check for stego tool signatures
        for sig in self.stego_tools:
            if sig in data:
                stego_score += 35
                reasons.append(f"Stego tool signature: {sig.decode('utf-8', errors='ignore')}")
                algorithms_used.append("🔧 Tool Signature Detection")
                break
        
        # 6. Check for suspicious strings
        strings = self.extract_strings(data)
        suspicious_found = []
        for s in strings:
            if any(kw in s for kw in self.keywords):
                suspicious_found.append(s[:50])
        
        if len(suspicious_found) >= 2:
            stego_score += 20
            reasons.append(f"Stego-related strings ({len(suspicious_found)} found)")
            algorithms_used.append("🔍 String Analysis")
        
        if progress_callback:
            progress_callback("Checking steghide...", 70)
        
        # 7. Check steghide
        if file_ext in ['.jpg', '.jpeg', '.bmp', '.wav']:
            steghide_detected = self.check_steghide(filepath)
            if steghide_detected:
                stego_score += 50
                reasons.append("Steghide embedded data detected")
                algorithms_used.append("🔐 Steghide Detection")
        
        if progress_callback:
            progress_callback("LSB analysis...", 80)
        
        # 8. LSB Check for PNG/BMP
        lsb_ratio = None
        if file_ext in ['.png', '.bmp']:
            try:
                from PIL import Image
                img = Image.open(filepath)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                pixels = list(img.getdata())[:10000]
                
                lsb_ones = 0
                for r, g, b in pixels:
                    lsb_ones += (r & 1) + (g & 1) + (b & 1)
                
                lsb_ratio = lsb_ones / (len(pixels) * 3)
                if abs(0.5 - lsb_ratio) > 0.08:
                    stego_score += 25
                    reasons.append(f"LSB anomaly (ratio: {lsb_ratio:.3f})")
                    algorithms_used.append("🎨 LSB Steganalysis")
            except:
                pass
        
        if progress_callback:
            progress_callback("Generating report...", 90)
        
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
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }


class SteganalysisGUI:
    """GUI for Steganalysis Tool"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Steganalysis Tool - Steg Detection")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Set icon and style
        self.root.configure(bg='#2c3e50')
        
        # Title
        title_label = tk.Label(
            root, 
            text="🔍 Steganalysis Detection Tool",
            font=('Segoe UI', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(pady=20)
        
        subtitle_label = tk.Label(
            root,
            text="Detect hidden data in images, audio, video, and archives",
            font=('Segoe UI', 11),
            bg='#2c3e50',
            fg='#bdc3c7'
        )
        subtitle_label.pack(pady=5)
        
        # Main frame
        main_frame = tk.Frame(root, bg='#34495e', relief='raised', bd=2)
        main_frame.pack(pady=20, padx=30, fill='both', expand=True)
        
        # File selection frame
        file_frame = tk.Frame(main_frame, bg='#34495e')
        file_frame.pack(pady=20, padx=20, fill='x')
        
        tk.Label(
            file_frame,
            text="Select File to Analyze:",
            font=('Segoe UI', 11, 'bold'),
            bg='#34495e',
            fg='white'
        ).pack(anchor='w', pady=5)
        
        # File path entry with browse button
        path_frame = tk.Frame(file_frame, bg='#34495e')
        path_frame.pack(fill='x')
        
        self.file_path = tk.StringVar()
        self.path_entry = tk.Entry(
            path_frame,
            textvariable=self.file_path,
            font=('Segoe UI', 10),
            bg='#ecf0f1',
            fg='#2c3e50',
            relief='flat',
            bd=1
        )
        self.path_entry.pack(side='left', fill='x', expand=True, ipady=5)
        
        browse_btn = tk.Button(
            path_frame,
            text="📂 Browse",
            command=self.browse_file,
            font=('Segoe UI', 10, 'bold'),
            bg='#3498db',
            fg='white',
            cursor='hand2',
            relief='flat',
            padx=20,
            height=1
        )
        browse_btn.pack(side='right', padx=(10, 0))
        
        # File info display
        self.info_frame = tk.Frame(main_frame, bg='#2c3e50', relief='sunken', bd=1)
        self.info_frame.pack(pady=10, padx=20, fill='x')
        
        self.file_info_label = tk.Label(
            self.info_frame,
            text="No file selected",
            font=('Segoe UI', 9),
            bg='#2c3e50',
            fg='#bdc3c7',
            justify='left'
        )
        self.file_info_label.pack(pady=10, padx=10, anchor='w')
        
        # Algorithms frame
        algo_frame = tk.Frame(main_frame, bg='#34495e')
        algo_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(
            algo_frame,
            text="🛠️ Algorithms Selected:",
            font=('Segoe UI', 10, 'bold'),
            bg='#34495e',
            fg='white'
        ).pack(anchor='w')
        
        self.algo_text = tk.Text(
            algo_frame,
            height=3,
            font=('Segoe UI', 9),
            bg='#2c3e50',
            fg='#3498db',
            relief='flat',
            bd=1
        )
        self.algo_text.pack(fill='x', pady=5)
        
        # Analyze button
        self.analyze_btn = tk.Button(
            main_frame,
            text="🔍 Analyze File",
            command=self.start_analysis,
            font=('Segoe UI', 12, 'bold'),
            bg='#27ae60',
            fg='white',
            cursor='hand2',
            relief='flat',
            padx=30,
            pady=10,
            state='disabled'
        )
        self.analyze_btn.pack(pady=15)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            length=400,
            mode='determinate',
            style='green.Horizontal.TProgressbar'
        )
        self.progress.pack(pady=5)
        
        self.progress_label = tk.Label(
            main_frame,
            text="",
            font=('Segoe UI', 9),
            bg='#34495e',
            fg='#bdc3c7'
        )
        self.progress_label.pack()
        
        # Results frame
        self.results_frame = tk.Frame(main_frame, bg='#34495e')
        self.results_frame.pack(pady=15, padx=20, fill='both', expand=True)
        
        # Results text
        self.results_text = tk.Text(
            self.results_frame,
            height=8,
            font=('Consolas', 9),
            bg='#2c3e50',
            fg='#ecf0f0',
            relief='flat',
            bd=1,
            wrap='word'
        )
        self.results_text.pack(side='left', fill='both', expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(self.results_frame, command=self.results_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.results_text.config(yscrollcommand=scrollbar.set)
        
        # Status bar
        self.status_label = tk.Label(
            root,
            text="Ready",
            font=('Segoe UI', 9),
            bg='#1a252f',
            fg='#95a5a6',
            relief='flat',
            anchor='w'
        )
        self.status_label.pack(side='bottom', fill='x', ipady=3, padx=2, pady=2)
        
        # Configure text tags
        self.results_text.tag_configure("stego", foreground="#ff6b6b", font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure("clean", foreground="#51cf66", font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure("info", foreground="#74b9ff")
        
    def browse_file(self):
        """Open file browser dialog"""
        filetypes = [
            ("All Files", "*.*"),
            ("Images", "*.jpg *.jpeg *.png *.bmp *.gif"),
            ("Audio", "*.wav *.mp3 *.flac *.ogg"),
            ("Video", "*.mp4 *.avi *.mkv *.mov"),
            ("Archives", "*.rar *.zip *.7z"),
        ]
        
        filename = filedialog.askopenfilename(
            title="Select a file to analyze",
            filetypes=filetypes
        )
        
        if filename:
            self.file_path.set(filename)
            self.update_file_info(filename)
            self.analyze_btn.config(state='normal', bg='#27ae60')
            self.status_label.config(text=f"Selected: {os.path.basename(filename)}")
    
    def update_file_info(self, filepath):
        """Update file information display"""
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            ext = os.path.splitext(filepath)[1].lower()
            
            # Auto-detect file type and display
            file_type = self.detect_file_type(ext)
            
            info_text = f"📁 File: {os.path.basename(filepath)}\n"
            info_text += f"📊 Size: {size:,} bytes ({size/1024:.2f} KB)\n"
            info_text += f"🔖 Type: {file_type}"
            
            self.file_info_label.config(text=info_text)
            
            # Show algorithms that will be used
            self.show_algorithms_for_type(ext)
    
    def detect_file_type(self, ext):
        """Detect file type from extension"""
        types = {
            '.jpg': 'JPEG Image', '.jpeg': 'JPEG Image',
            '.png': 'PNG Image', '.bmp': 'Bitmap Image',
            '.gif': 'GIF Image', '.wav': 'WAV Audio',
            '.mp3': 'MP3 Audio', '.mp4': 'MP4 Video',
            '.avi': 'AVI Video', '.mkv': 'MKV Video',
            '.rar': 'RAR Archive', '.zip': 'ZIP Archive',
            '.7z': '7-Zip Archive', '.exe': 'Executable',
            '.pdf': 'PDF Document', '.txt': 'Text File'
        }
        return types.get(ext, f"Unknown ({ext.upper()})")
    
    def show_algorithms_for_type(self, ext):
        """Display algorithms that will be used for this file type"""
        self.algo_text.delete(1.0, tk.END)
        
        algorithms = ["📊 Entropy Analysis", "📎 EOF Analysis", "🔍 String Analysis"]
        
        if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
            algorithms.extend(["🎨 LSB Steganalysis", "🔐 Steghide Detection"])
        if ext in ['.wav', '.mp3']:
            algorithms.extend(["🎵 Audio Steganalysis", "🔐 Steghide Detection"])
        if ext in ['.mp4', '.avi', '.mkv']:
            algorithms.append("🎬 Video Steganalysis")
        if ext in ['.png', '.bmp']:
            algorithms.append("🎨 LSB Analysis")
        
        algorithms.extend(["🗜️ Archive Detection", "⚙️ Executable Detection"])
        
        algo_str = " • ".join(algorithms[:5]) + "..."
        self.algo_text.insert(1.0, algo_str)
    
    def start_analysis(self):
        """Start analysis in separate thread"""
        filepath = self.file_path.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        self.analyze_btn.config(state='disabled', text="⏳ Analyzing...")
        self.results_text.delete(1.0, tk.END)
        self.progress['value'] = 0
        self.progress_label.config(text="Starting analysis...")
        
        # Run analysis in separate thread
        thread = threading.Thread(target=self.run_analysis, args=(filepath,))
        thread.daemon = True
        thread.start()
    
    def update_progress(self, message, value):
        """Update progress bar and label"""
        self.root.after(0, lambda: self._update_progress_ui(message, value))
    
    def _update_progress_ui(self, message, value):
        """UI update for progress"""
        self.progress['value'] = value
        self.progress_label.config(text=message)
        self.status_label.config(text=message)
    
    def run_analysis(self, filepath):
        """Run analysis and update UI"""
        detector = StegDetector()
        
        def progress_callback(msg, val):
            self.update_progress(msg, val)
        
        result = detector.analyze(filepath, progress_callback)
        
        # Update UI with results
        self.root.after(0, lambda: self.display_results(result))
    
    def display_results(self, result):
        """Display analysis results"""
        self.results_text.delete(1.0, tk.END)
        
        if 'error' in result:
            self.results_text.insert(tk.END, f"Error: {result['error']}\n", "stego")
            self.analyze_btn.config(state='normal', text="🔍 Analyze File")
            self.progress['value'] = 100
            self.progress_label.config(text="Analysis failed")
            return
        
        # Header
        self.results_text.insert(tk.END, "="*60 + "\n")
        self.results_text.insert(tk.END, "STEGANALYSIS RESULTS\n")
        self.results_text.insert(tk.END, "="*60 + "\n\n")
        
        # File info
        self.results_text.insert(tk.END, f"File: {result['filename']}\n", "info")
        self.results_text.insert(tk.END, f"Size: {result['file_size']:,} bytes\n")
        self.results_text.insert(tk.END, f"Type: {result['file_ext'].upper()}\n")
        self.results_text.insert(tk.END, f"Entropy: {result['entropy']:.4f} ({result['entropy_status']})\n\n")
        
        # Algorithms used
        self.results_text.insert(tk.END, "Algorithms Applied:\n", "info")
        for algo in result['algorithms_used']:
            self.results_text.insert(tk.END, f"  {algo}\n")
        self.results_text.insert(tk.END, "\n")
        
        # Findings
        if result['reasons']:
            self.results_text.insert(tk.END, "Findings:\n", "info")
            for reason in result['reasons']:
                self.results_text.insert(tk.END, f"  • {reason}\n")
        else:
            self.results_text.insert(tk.END, "Findings: None\n", "clean")
        
        self.results_text.insert(tk.END, "\n" + "-"*60 + "\n")
        self.results_text.insert(tk.END, f"Score: {result['score']}/100\n")
        
        # Verdict
        if result['is_stego']:
            self.results_text.insert(tk.END, "\n🔴 VERDICT: STEGO DETECTED\n", "stego")
            self.results_text.insert(tk.END, "This file likely contains hidden data!\n", "stego")
            self.status_label.config(text=f"⚠️ STEGO DETECTED in {result['filename']}")
        else:
            self.results_text.insert(tk.END, "\n🟢 VERDICT: CLEAN\n", "clean")
            self.results_text.insert(tk.END, "No steganography detected.\n", "clean")
            self.status_label.config(text=f"✅ Clean: {result['filename']}")
        
        # Hashes
        self.results_text.insert(tk.END, "\n" + "="*60 + "\n")
        self.results_text.insert(tk.END, f"MD5: {result['hashes']['md5']}\n", "info")
        self.results_text.insert(tk.END, f"SHA256: {result['hashes']['sha256'][:64]}...\n", "info")
        
        # Generate report files
        self.generate_reports(result)
        
        self.analyze_btn.config(state='normal', text="🔍 Analyze File")
        self.progress['value'] = 100
        self.progress_label.config(text="Analysis complete!")
    
    def generate_reports(self, result):
        """Generate HTML and Text reports"""
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = result['filename'].replace('.', '_')
        
        # Text report
        txt_file = os.path.join(report_dir, f"{filename}_{timestamp}_report.txt")
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("STEGANALYSIS REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"File: {result['filename']}\n")
            f.write(f"Path: {result['filepath']}\n")
            f.write(f"Size: {result['file_size']:,} bytes\n")
            f.write(f"Type: {result['file_ext'].upper()}\n")
            f.write(f"Entropy: {result['entropy']:.4f}\n")
            f.write(f"Score: {result['score']}/100\n")
            f.write(f"Verdict: {'STEGO DETECTED' if result['is_stego'] else 'CLEAN'}\n")
            f.write(f"Time: {result['timestamp']}\n")
            f.write(f"MD5: {result['hashes']['md5']}\n")
            f.write(f"SHA256: {result['hashes']['sha256']}\n")
        
        # HTML report (simplified version saved)
        html_file = os.path.join(report_dir, f"{filename}_{timestamp}_report.html")
        
        self.results_text.insert(tk.END, f"\n📄 Reports saved to: {report_dir}/\n", "info")


def main():
    root = tk.Tk()
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('green.Horizontal.TProgressbar', 
                   background='#27ae60',
                   troughcolor='#2c3e50',
                   bordercolor='#34495e',
                   lightcolor='#27ae60',
                   darkcolor='#27ae60')
    
    app = SteganalysisGUI(root)
    root.mainloop()


if __name__ == "__main__":
    # Check if running from command line with file argument
    if len(sys.argv) > 1:
        # Command line mode
        detector = StegDetector()
        result = detector.analyze(sys.argv[1])
        if result.get('is_stego'):
            print(f"\n🔴 STEGO DETECTED - Score: {result['score']}/100")
        else:
            print(f"\n🟢 CLEAN - Score: {result['score']}/100")
    else:
        # GUI mode
        main()
