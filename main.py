import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, Listbox, Scrollbar, ttk
import subprocess
import os
import webbrowser
from pathlib import Path
from datetime import datetime
import threading
import time  # Importing the time module

class BanditAnalyzerUI:
    def __init__(self, master):
        self.master = master
        master.title("Lazy Analyzer UI")
        master.configure(bg='#f0f0f0')

        # Title Label
        self.title_label = tk.Label(master, text="Lazy Code Analyzer", font=("Helvetica", 24, "bold"), bg='#f0f0f0', fg='#333')
        self.title_label.pack(pady=20)

        # Frame for file selection
        self.file_frame = tk.Frame(master, bg='#f0f0f0')
        self.file_frame.pack(pady=10)

        self.label = tk.Label(self.file_frame, text="Select a ZIP file for analysis:", bg='#f0f0f0', fg='#555')
        self.label.pack(side=tk.LEFT)

        self.zip_file_path = tk.StringVar()
        self.zip_file_entry = tk.Entry(self.file_frame, textvariable=self.zip_file_path, width=40, font=("Helvetica", 12))
        self.zip_file_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_zip_file, bg='#4CAF50', fg='white', font=("Helvetica", 12), relief='raised', bd=2)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        # Analyze Button
        self.analyze_button = tk.Button(master, text="Run Analysis", command=self.start_analysis, bg='#2196F3', fg='white', font=("Helvetica", 12), relief='raised', bd=2)
        self.analyze_button.pack(pady=20)

        # Progress Bar
        self.progress_bar = ttk.Progressbar(master, length=300, mode='determinate')
        self.progress_bar.pack(pady=10)

        # Report Buttons
        self.report_frame = tk.Frame(master, bg='#f0f0f0')
        self.report_frame.pack(pady=10)

        self.report_button = tk.Button(self.report_frame, text="Open Latest Report", command=self.open_latest_report, bg='#FF9800', fg='white', font=("Helvetica", 12), relief='raised', bd=2)
        self.report_button.pack(side=tk.LEFT, padx=5)

        self.history_button = tk.Button(self.report_frame, text="Show Report History", command=self.show_report_history, bg='#9C27B0', fg='white', font=("Helvetica", 12), relief='raised', bd=2)
        self.history_button.pack(side=tk.LEFT, padx=5)

    def browse_zip_file(self):
        zip_file = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if zip_file:
            self.zip_file_path.set(zip_file)

    def start_analysis(self):
        zip_file = self.zip_file_path.get()
        if not zip_file:
            messagebox.showerror("Error", "Please select a ZIP file.")
            return

        self.progress_bar['value'] = 0
        self.progress_bar.start()
        self.master.update()

        # Run the analysis in a separate thread
        threading.Thread(target=self.run_analysis, args=(zip_file,)).start()

    def run_analysis(self, zip_file):
        reports_dir = Path("Analyzed-Reports")
        reports_dir.mkdir(exist_ok=True)

        # Generate filenames with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_report_path = reports_dir / f"bandit_report_{timestamp}.json"
        html_report_path = reports_dir / f"bandit_report_{timestamp}.html"

        # Run the Bandit analysis
        try:
            # Simulating progress (replace with actual analysis command)
            for i in range(101):  # Simulate progress from 0 to 100
                if i == 100:
                    subprocess.run(
                        ["python", "bandit_master.py", zip_file],
                        check=True
                    )
                self.progress_bar['value'] = i
                self.master.update()
                time.sleep(0.05)  # Simulate time taken for analysis

            messagebox.showinfo("Success ", "Analysis completed successfully! Reports are saved in the 'Analyzed-Reports' directory.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during analysis: {e}")
        finally:
            self.progress_bar.stop()
            self.progress_bar['value'] = 0

    def open_latest_report(self):
        reports_dir = Path("Analyzed-Reports")
        if reports_dir.exists() and any(reports_dir.glob("*.html")):
            latest_report = max(reports_dir.glob("*.html"), key=os.path.getctime)
            webbrowser.open(latest_report.resolve().as_uri())  # Convert to absolute path
        else:
            messagebox.showinfo("Info", "No reports found.")

    def show_report_history(self):
        reports_dir = Path("Analyzed-Reports")
        if reports_dir.exists() and any(reports_dir.glob("*.html")):
            history_window = Toplevel(self.master)
            history_window.title("Report History")
            history_window.geometry("400x300")

            listbox = Listbox(history_window)
            listbox.pack(fill=tk.BOTH, expand=True)

            for report in sorted(reports_dir.glob("*.html"), key=os.path.getctime):
                listbox.insert(tk.END, report.name)

            scrollbar = Scrollbar(history_window)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            listbox.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=listbox.yview)

            listbox.bind('<Double-1>', lambda event: webbrowser.open(reports_dir / listbox.get(listbox.curselection())))

        else:
            messagebox.showinfo("Info", "No report history found.")

if __name__ == "__main__":
    root = tk.Tk()
    app = BanditAnalyzerUI(root)
    root.mainloop()