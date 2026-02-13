#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-main}"

case "$MODE" in
  main|cve|news|check) ;;
  *)
    echo "[Runner] Invalid mode: $MODE"
    echo "Usage: ./run.sh [main|cve|news|check]"
    exit 1
    ;;
esac

step() {
  local description="$1"
  shift
  echo "[Runner] ${description}..."
  "$@"
}

ensure_github_token() {
  if [[ "$MODE" != "main" && "$MODE" != "cve" ]]; then
    return
  fi

  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    return
  fi

  echo "[Runner] No GITHUB_TOKEN found. CVE fetching may be rate-limited."
  read -r -s -p "Enter GitHub token (or press Enter to continue without one): " entered_token
  echo
  if [[ -n "$entered_token" ]]; then
    export GITHUB_TOKEN="$entered_token"
    echo "[Runner] Token set for this run."
  else
    echo "[Runner] Continuing without token."
  fi
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
VENV_PYTHON="${VENV_DIR}/bin/python"
REQUIREMENTS_PATH="${REPO_ROOT}/requirements.txt"
REQUIREMENTS_STAMP_PATH="${VENV_DIR}/.requirements.sha256"

ensure_github_token

venv_created=0
if [[ ! -x "$VENV_PYTHON" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    step "Creating virtual environment with python3" python3 -m venv "$VENV_DIR"
  else
    step "Creating virtual environment with python" python -m venv "$VENV_DIR"
  fi
  venv_created=1
fi

requirements_hash="$("$VENV_PYTHON" -c "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path(r'${REQUIREMENTS_PATH}').read_bytes()).hexdigest())")"
stored_hash=""
if [[ -f "$REQUIREMENTS_STAMP_PATH" ]]; then
  stored_hash="$(head -n 1 "$REQUIREMENTS_STAMP_PATH" | tr -d '[:space:]')"
fi

if [[ "$venv_created" -eq 1 || "$requirements_hash" != "$stored_hash" ]]; then
  step "Upgrading pip" "$VENV_PYTHON" -m pip install --upgrade pip
  step "Installing dependencies" "$VENV_PYTHON" -m pip install -r "${REQUIREMENTS_PATH}"
  printf "%s\n" "$requirements_hash" > "$REQUIREMENTS_STAMP_PATH"
else
  echo "[Runner] Requirements unchanged. Skipping dependency install."
fi

case "$MODE" in
  main) SCRIPT="main.py" ;;
  cve) SCRIPT="cve_scraper.py" ;;
  news) SCRIPT="news_scraper.py" ;;
  check) SCRIPT="check_data.py" ;;
esac

step "Running ${SCRIPT}" "$VENV_PYTHON" "${REPO_ROOT}/${SCRIPT}"
