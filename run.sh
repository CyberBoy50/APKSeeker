#!/bin/sh
# APKSeeker launcher for Linux/macOS — setup, scan, test, doctor, build-apk, menu.
# Pure Python: works with no Android tools installed.
HERE=$(cd "$(dirname "$0")" && pwd)
if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh [setup | scan <apk> [flags] | test | doctor | build-apk | menu]"
    exit 2
fi
CMD=$1
shift
if [ "$CMD" = "setup" ]; then
    if [ ! -x "$HERE/venv/bin/python" ]; then
        echo "[*] Creating virtual environment (first time only)..."
        python3 -m venv "$HERE/venv" || { echo "[!] Could not create a venv."; exit 1; }
    fi
    echo "[*] APKSeeker needs no packages (standard library only)."
    echo "[+] Setup done. Test it: ./run.sh scan test_apks/test_bad.apk"
    exit 0
fi
if [ -x "$HERE/venv/bin/python" ]; then
    PY="$HERE/venv/bin/python"
else
    PY=python3
fi
case "$CMD" in
    scan) exec "$PY" "$HERE/apkseeker.py" "$@" ;;
    test) exec "$PY" "$HERE/test_apkseeker.py" ;;
    doctor) exec "$PY" "$HERE/apkseeker.py" --check ;;
    build-apk) exec "$PY" "$HERE/build_test_apk.py" ;;
    menu) exec "$PY" "$HERE/apkseeker.py" --menu ;;
    *) echo "[!] Unknown command: $CMD"; exit 2 ;;
esac
