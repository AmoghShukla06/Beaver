#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
npm ci
npm run build
printf 'Beaver is ready. Run npm start.\n'
