"""Launch the ForensicLens Investigator Dashboard web server."""

from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

from forensiclens.dashboard import create_app


def _launch_browser(url: str) -> None:
    time.sleep(1.0)
    try:
        webbrowser.open_new_tab(url)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="ForensicLens Investigator Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Port to run web server on (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--evidence-root", default="dataset/raw", help="Path to evidence files directory")
    parser.add_argument("--video-root", default="dataset/raw/video", help="Path to video evidence directory")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch browser")
    args = parser.parse_args()

    app = create_app(
        evidence_root=args.evidence_root,
        video_root=args.video_root,
    )
    url = f"http://{args.host}:{args.port}"
    print(f"\n=======================================================")
    print(f" FORENSICLENS INVESTIGATOR DASHBOARD (SIH PS 26150)")
    print(f" Running at: {url}")
    print(f" Evidence Root: {args.evidence_root}")
    print(f" Video Root:    {args.video_root}")
    print(f"=======================================================\n")

    if not args.no_browser:
        threading.Thread(target=_launch_browser, args=(url,), daemon=True).start()

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
