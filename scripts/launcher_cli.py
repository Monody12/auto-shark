"""PyInstaller entry point for the auto-shark command-line interface."""

import sys

from auto_shark.cli import main

if __name__ == "__main__":
    sys.exit(main())
