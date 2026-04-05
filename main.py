"""
Windows Event Log Extractor - SOC Analysis Tool
Main entry point
"""

import sys
import os

# Ensure the package directory is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui import SOCExtractorApp
import tkinter as tk


def main():
    root = tk.Tk()
    app = SOCExtractorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
