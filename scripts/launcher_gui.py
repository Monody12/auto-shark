"""PyInstaller entry point for the AutoShark desktop application."""

import sys

from auto_shark.gui import run_gui

if __name__ == "__main__":
    sys.exit(run_gui())
