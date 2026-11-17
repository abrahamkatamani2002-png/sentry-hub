"""Vercel entry point: Vercel's Python runtime serves the WSGI object named `app`."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentryhub import create_app  # noqa: E402

app = create_app()
