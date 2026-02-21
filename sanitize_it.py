#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
=============================================================================
Sanitize-It: Zero-Trust Log & Code Purifier
=============================================================================
A massive, standalone Python application for sanitizing sensitive data 
(PII, Credentials, IPs, API Keys) from logs, source code, and text files.
Features both a Graphical User Interface (GUI) and a Command Line Interface (CLI).

Author: The Linux Leap Community & You
Version: 1.0.0 (Enterprise Python Architecture)
License: MIT
=============================================================================
"""

import sys
import re
import os
import json
import threading
import queue
import argparse
import difflib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# =========================================================================
# 1. CORE SANITIZATION ENGINE (REGEX DATABASE)
# =========================================================================

class SanitizeEngine:
    """Core engine responsible for finding and replacing sensitive data using Regex."""
    
    # Pre-compiled enterprise-grade regex patterns for sensitive data
    PATTERNS = {
        "AWS_ACCESS_KEY": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "AWS_SECRET_KEY": re.compile(r'\b(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b'),
        "IPV4_ADDRESS": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        "IPV6_ADDRESS": re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE),
        "EMAIL_ADDRESS": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'),
        "MAC_ADDRESS": re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'),
        "CREDIT_CARD": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        "URL_PASSWORD": re.compile(r'(https?|ftp|postgres|mysql)://([^:]+):([^@]+)@'),
        "JWT_TOKEN": re.compile(r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b'),
        "STRIPE_KEY": re.compile(r'\b(sk_live_[0-9a-zA-Z]{24})\b'),
        "SLACK_TOKEN": re.compile(r'\b(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b'),
        "GOOGLE_API": re.compile(r'\b(AIza[0-9A-Za-z_-]{35})\b'),
        "SSN_US": re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    }

    def __init__(self):
        # Maps to maintain consistent replacement (e.g., 192.168.1.1 is always REDACTED_IPV4_1)
        self.replacement_maps = {key: {} for key in self.PATTERNS.keys()}
        self.counters = {key: 1 for key in self.PATTERNS.keys()}
        self.active_rules = set(self.PATTERNS.keys()) # All active by default

    def reset_mappings(self):
        """Clears the mapping memory for a fresh sanitization run."""
        self.replacement_maps = {key: {} for key in self.PATTERNS.keys()}
        self.counters = {key: 1 for key in self.PATTERNS.keys()}

    def set_active_rules(self, rules: list):
        """Define which regex rules should be applied."""
        self.active_rules = set(rules)

    def _replace_match(self, match: re.Match, rule_name: str, consistent: bool) -> str:
        """Handles the replacement logic, ensuring consistent hashing if enabled."""
        original_text = match.group(0)
        
        # Special handling for passwords in URLs to preserve the rest of the URL
        if rule_name == "URL_PASSWORD":
            protocol = match.group(1)
            username = match.group(2)
            return f"{protocol}://{username}:[REDACTED_PASSWORD]@"

        if consistent:
            if original_text not in self.replacement_maps[rule_name]:
                self.replacement_maps[rule_name][original_text] = f"[REDACTED_{rule_name}_{self.counters[rule_name]}]"
                self.counters[rule_name] += 1
            return self.replacement_maps[rule_name][original_text]
        else:
            return f"[REDACTED_{rule_name}]"

    def process_text(self, text: str, consistent: bool = True) -> str:
        """Scans the text and replaces all matched patterns."""
        sanitized_text = text
        for rule_name in self.active_rules:
            if rule_name in self.PATTERNS:
                pattern = self.PATTERNS[rule_name]
                # Pass a lambda to re.sub to handle consistent replacement logic
                sanitized_text = pattern.sub(
                    lambda m, rn=rule_name, c=consistent: self._replace_match(m, rn, c), 
                    sanitized_text
                )
        return sanitized_text

    def get_stats(self) -> dict:
        """Returns statistics on what was redacted."""
        stats = {}
        for rule_name, item_map in self.replacement_maps.items():
            count = len(item_map)
            if count > 0:
                stats[rule_name] = count
        return stats


# =========================================================================
# 2. COMMAND LINE INTERFACE (CLI) LOGIC
# =========================================================================

def run_cli(args):
    """Executes the sanitization process via Terminal/Command Prompt."""
    print("🛡️ Sanitize-It CLI Engine Started...")
    
    engine = SanitizeEngine()
    
    # Filter rules if specified
    if args.rules:
        valid_rules = [r for r in args.rules.split(',') if r in engine.PATTERNS]
        if not valid_rules:
            print("❌ Error: No valid rules provided. Aborting.")
            sys.exit(1)
        engine.set_active_rules(valid_rules)
        print(f"⚙️ Active Rules: {', '.join(valid_rules)}")
    else:
        print(f"⚙️ Active Rules: ALL ({len(engine.PATTERNS)} rules)")

    # Read Input
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            raw_text = f.read()
    except FileNotFoundError:
        print(f"❌ Error: Input file '{args.input}' not found.")
        sys.exit(1)

    print(f"📄 Read {len(raw_text)} characters from {args.input}")
    
    # Process
    print("⏳ Scrubbing sensitive data...")
    clean_text = engine.process_text(raw_text, consistent=not args.no_consistent)
    
    # Write Output
    output_path = args.output if args.output else f"sanitized_{args.input}"
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(clean_text)
        print(f"✅ Success! Sanitized file saved to: {output_path}")
    except Exception as e:
        print(f"❌ Error saving output: {e}")
        sys.exit(1)

    # Print Stats
    stats = engine.get_stats()
    if stats:
        print("\n📊 Sanitization Report:")
        for rule, count in stats.items():
            print(f"  - {rule}: {count} unique items redacted")
    else:
        print("\n📊 Sanitization Report: No sensitive data found based on active rules.")

    # Show Diff if requested
    if args.diff:
        print("\n🔍 Diff Summary (Lines changed):")
        raw_lines = raw_text.splitlines()
        clean_lines = clean_text.splitlines()
        diff = difflib.unified_diff(raw_lines, clean_lines, fromfile='Original', tofile='Sanitized', lineterm='')
        for line in diff:
            if line.startswith('-') and not line.startswith('---'):
                print(f"\033[91m{line}\033[0m") # Red
            elif line.startswith('+') and not line.startswith('+++'):
                print(f"\033[92m{line}\033[0m") # Green


# =========================================================================
# 3. GRAPHICAL USER INTERFACE (GUI) - TKINTER
# =========================================================================

class SanitizeApp(tk.Tk):
    """The main Tkinter application class."""
    
    def __init__(self):
        super().__init__()
        
        self.engine = SanitizeEngine()
        self.title("🛡️ Sanitize-It | Zero-Trust Purifier")
        self.geometry("1200x800")
        self.minsize(900, 600)
        
        # Configure Dark Theme Colors
        self.colors = {
            "bg": "#0f172a",          # Dark Slate
            "panel": "#1e293b",       # Lighter Slate
            "text": "#f8fafc",        # White
            "muted": "#94a3b8",       # Gray
            "primary": "#10b981",     # Emerald Green
            "danger": "#ef4444",      # Red
            "code_bg": "#000000",
            "code_fg": "#a6accd"
        }
        
        self.configure(bg=self.colors["bg"])
        self.setup_styles()
        self.build_ui()
        
    def setup_styles(self):
        """Initializes ttk styles for custom dark mode aesthetic."""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background=self.colors["bg"])
        style.configure('Panel.TFrame', background=self.colors["panel"])
        
        style.configure('TLabel', background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 10))
        style.configure('Header.TLabel', font=("Segoe UI", 14, "bold"), foreground=self.colors["primary"])
        style.configure('Panel.TLabel', background=self.colors["panel"], foreground=self.colors["text"])
        
        style.configure('TButton', font=("Segoe UI", 10, "bold"), padding=6)
        style.configure('Primary.TButton', background=self.colors["primary"], foreground="#000000")
        style.map('Primary.TButton', background=[('active', '#059669')])
        
        style.configure('TCheckbutton', background=self.colors["panel"], foreground=self.colors["text"], font=("Segoe UI", 10))
        style.map('TCheckbutton', background=[('active', self.colors["panel"])])

        style.configure('TNotebook', background=self.colors["panel"], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.colors["bg"], foreground=self.colors["text"], padding=[15, 5], font=("Segoe UI", 10, "bold"))
        style.map('TNotebook.Tab', background=[('selected', self.colors["primary"])], foreground=[('selected', '#000')])

    def build_ui(self):
        """Constructs the application layout."""
        # Top Header
        header_frame = ttk.Frame(self, padding=(20, 15), style='Panel.TFrame')
        header_frame.pack(side=tk.TOP, fill=tk.X)
        
        ttk.Label(header_frame, text="🛡️ Sanitize-It", style='Header.TLabel').pack(side=tk.LEFT)
        ttk.Label(header_frame, text="100% Local. Zero Data Leaves Your PC.", style='Panel.TLabel', foreground=self.colors["muted"]).pack(side=tk.LEFT, padx=15)
        
        # Main PanedWindow (Left Sidebar | Right Content)
        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=self.colors["border"] if "border" in self.colors else "#333", borderwidth=0, sashwidth=2)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # --- LEFT SIDEBAR (SETTINGS) ---
        sidebar = ttk.Frame(paned, padding=20, style='Panel.TFrame', width=300)
        paned.add(sidebar, minsize=250)
        
        ttk.Label(sidebar, text="Configuration", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 15))
        
        # Consistency Checkbox
        self.var_consistent = tk.BooleanVar(value=True)
        cb_cons = ttk.Checkbutton(sidebar, text="Consistent Hashing\n(Keep structure intact)", variable=self.var_consistent)
        cb_cons.pack(anchor=tk.W, pady=(0, 20))
        
        ttk.Label(sidebar, text="Active Scrubber Rules", style='Panel.TLabel', font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Dynamic Checkboxes for Regex Rules
        self.rule_vars = {}
        rules_frame = ttk.Frame(sidebar, style='Panel.TFrame')
        rules_frame.pack(fill=tk.BOTH, expand=True)
        
        for rule_name in sorted(self.engine.PATTERNS.keys()):
            var = tk.BooleanVar(value=True)
            self.rule_vars[rule_name] = var
            cb = ttk.Checkbutton(rules_frame, text=rule_name.replace("_", " "), variable=var)
            cb.pack(anchor=tk.W, pady=3)
            
        # Select/Deselect All
        btn_frame = ttk.Frame(sidebar, style='Panel.TFrame')
        btn_frame.pack(fill=tk.X, pady=15)
        ttk.Button(btn_frame, text="All", command=lambda: self.toggle_all_rules(True), width=10).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(btn_frame, text="None", command=lambda: self.toggle_all_rules(False), width=10).pack(side=tk.LEFT)

        # Process Button
        self.btn_process = ttk.Button(sidebar, text="🚀 PURIFY DATA", style='Primary.TButton', command=self.start_processing_thread)
        self.btn_process.pack(fill=tk.X, side=tk.BOTTOM, pady=20)
        
        # --- RIGHT CONTENT (NOTEBOOK) ---
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, minsize=600)
        
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Input
        self.tab_input = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_input, text="1. Raw Input")
        self.build_text_tab(self.tab_input, "Paste your raw logs, JSON, or code here:", is_input=True)
        
        # Tab 2: Output
        self.tab_output = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_output, text="2. Sanitized Output")
        self.build_text_tab(self.tab_output, "Clean data ready for sharing:", is_input=False)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready. Waiting for input.")
        status_bar = ttk.Label(self, textvariable=self.status_var, background="#050505", foreground=self.colors["primary"], padding=5, font=("Segoe UI", 9, "bold"))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def build_text_tab(self, parent, label_text, is_input):
        """Helper to build text areas with action buttons."""
        top_bar = ttk.Frame(parent, padding=(10, 5))
        top_bar.pack(fill=tk.X)
        
        ttk.Label(top_bar, text=label_text).pack(side=tk.LEFT)
        
        if is_input:
            ttk.Button(top_bar, text="📁 Load File", command=self.load_file).pack(side=tk.RIGHT)
            ttk.Button(top_bar, text="🧹 Clear", command=lambda: self.text_in.delete('1.0', tk.END)).pack(side=tk.RIGHT, padx=5)
        else:
            ttk.Button(top_bar, text="💾 Save File", command=self.save_file).pack(side=tk.RIGHT)
            ttk.Button(top_bar, text="📋 Copy", command=self.copy_output).pack(side=tk.RIGHT, padx=5)
            
        # Custom styled ScrolledText
        txt = scrolledtext.ScrolledText(
            parent, 
            wrap=tk.WORD, 
            bg=self.colors["code_bg"], 
            fg=self.colors["code_fg"], 
            font=("Consolas", 11),
            insertbackground=self.colors["text"], # Cursor color
            padx=10, pady=10, borderwidth=0
        )
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        if is_input:
            self.text_in = txt
        else:
            self.text_out = txt

    def toggle_all_rules(self, state: bool):
        """Selects or deselects all regex rule checkboxes."""
        for var in self.rule_vars.values():
            var.set(state)

    def load_file(self):
        """Loads text from a local file."""
        filepath = filedialog.askopenfilename(title="Select Log File", filetypes=[("Text Files", "*.*")])
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                self.text_in.delete('1.0', tk.END)
                self.text_in.insert(tk.END, content)
                self.status_var.set(f"Loaded {len(content)} characters from {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("File Error", f"Could not read file:\n{e}")

    def save_file(self):
        """Saves sanitized output to a local file."""
        content = self.text_out.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "Nothing to save!")
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".log", initialfile="sanitized_output.log", title="Save Sanitized File")
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_var.set(f"Successfully saved to {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("File Error", f"Could not save file:\n{e}")

    def copy_output(self):
        """Copies output to system clipboard."""
        content = self.text_out.get('1.0', tk.END).strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self.status_var.set("✅ Copied to clipboard!")

    def start_processing_thread(self):
        """Initiates text processing in a separate thread to prevent GUI freezing."""
        raw_text = self.text_in.get('1.0', tk.END).strip()
        if not raw_text:
            messagebox.showinfo("Empty Input", "Please paste some text to sanitize first.")
            return

        # Gather active rules
        active_rules = [rule for rule, var in self.rule_vars.items() if var.get()]
        if not active_rules:
            messagebox.showwarning("No Rules", "Please select at least one scrubber rule.")
            return

        # UI Updates during processing
        self.btn_process.config(text="⏳ PROCESSING...", state=tk.DISABLED)
        self.status_var.set("Scrubbing data... Please wait.")
        self.engine.set_active_rules(active_rules)
        self.engine.reset_mappings()
        
        is_consistent = self.var_consistent.get()
        
        # Use queue to safely communicate back to the main Tkinter thread
        self.result_queue = queue.Queue()
        
        # Spawn thread
        t = threading.Thread(target=self.process_text_worker, args=(raw_text, is_consistent))
        t.daemon = True
        t.start()
        
        # Start checking queue
        self.check_queue()

    def process_text_worker(self, raw_text: str, consistent: bool):
        """The actual heavy-lifting function running in a background thread."""
        try:
            clean_text = self.engine.process_text(raw_text, consistent=consistent)
            stats = self.engine.get_stats()
            self.result_queue.put({"status": "success", "text": clean_text, "stats": stats})
        except Exception as e:
            self.result_queue.put({"status": "error", "message": str(e)})

    def check_queue(self):
        """Polls the queue to see if the background thread has finished."""
        try:
            msg = self.result_queue.get_nowait()
            self.handle_processing_result(msg)
        except queue.Empty:
            # If empty, check again in 100ms
            self.after(100, self.check_queue)

    def handle_processing_result(self, result: dict):
        """Updates GUI with results from the background thread."""
        self.btn_process.config(text="🚀 PURIFY DATA", state=tk.NORMAL)
        
        if result["status"] == "success":
            # Update output text area
            self.text_out.delete('1.0', tk.END)
            self.text_out.insert(tk.END, result["text"])
            
            # Switch to output tab automatically
            self.notebook.select(1)
            
            # Compile stats message
            stats = result["stats"]
            if stats:
                stat_str = " | ".join([f"{k}: {v}" for k, v in stats.items()])
                self.status_var.set(f"✅ Success! Redacted -> {stat_str}")
            else:
                self.status_var.set("✅ Scan complete. No sensitive data matched your active rules.")
                
        elif result["status"] == "error":
            messagebox.showerror("Processing Error", f"An error occurred:\n{result['message']}")
            self.status_var.set("❌ Error during processing.")


# =========================================================================
# 4. ENTRY POINT (MAIN)
# =========================================================================

def main():
    """Parses arguments to determine if CLI or GUI should be launched."""
    parser = argparse.ArgumentParser(description="Sanitize-It: Zero-Trust Log Purifier")
    
    # Optional arguments for CLI execution
    parser.add_argument('-i', '--input', type=str, help='Input file path for CLI mode')
    parser.add_argument('-o', '--output', type=str, help='Output file path for CLI mode')
    parser.add_argument('-r', '--rules', type=str, help='Comma-separated list of rules to apply (e.g., IPV4_ADDRESS,EMAIL_ADDRESS)')
    parser.add_argument('--no-consistent', action='store_true', help='Disable consistent hashing for replacements')
    parser.add_argument('--diff', action='store_true', help='Print a diff of changes to the terminal')
    
    args = parser.parse_args()
    
    # If input is provided, run as CLI. Otherwise, launch full Desktop GUI.
    if args.input:
        run_cli(args)
    else:
        app = SanitizeApp()
        app.mainloop()

if __name__ == "__main__":
    main()
