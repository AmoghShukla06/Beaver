"""Run with the project venv: python scripts/build_backend.py."""
import subprocess
import sys
subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "beaver-service", "--distpath", "backend-dist", "--paths", ".", "--exclude-module", "tkinter", "--exclude-module", "unittest", "--exclude-module", "pydoc", "backend/entry.py"], check=True)
