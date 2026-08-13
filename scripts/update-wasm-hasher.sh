#!/usr/bin/env bash
# scripts/update-wasm-hasher.sh
#
# Rebuilds the wasm-hasher crate and patches the WASM_SHA256_B64 constant
# inside runtime/veilguard-verify.mjs.
#
# Usage:
#   ./scripts/update-wasm-hasher.sh           # from repo root
#   ./scripts/update-wasm-hasher.sh --opt     # also run wasm-opt (requires binaryen)
#
# CI runs this on every push that touches wasm-hasher/**.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="$REPO_ROOT/wasm-hasher"
WASM_OUT="$CRATE_DIR/target/wasm32-unknown-unknown/release/veil_guard_wasm_hasher.wasm"
TARGET_JS="$REPO_ROOT/runtime/veilguard-verify.mjs"
MARKER_START="// @generated — do not edit by hand"
OPT_WASM="$CRATE_DIR/target/wasm32-unknown-unknown/release/veil_guard_wasm_hasher_opt.wasm"

echo "🦀 Building wasm-hasher…"
(cd "$CRATE_DIR" && cargo build --target wasm32-unknown-unknown --release -q)

WASM_FILE="$WASM_OUT"

if [[ "${1:-}" == "--opt" ]]; then
  if command -v wasm-opt &>/dev/null; then
    echo "⚡ Running wasm-opt -Oz…"
    wasm-opt -Oz "$WASM_OUT" -o "$OPT_WASM"
    WASM_FILE="$OPT_WASM"
  else
    echo "⚠️  wasm-opt not found, skipping optimisation (install binaryen to enable)"
  fi
fi

echo "📐 Wasm size: $(wc -c < "$WASM_FILE") bytes"

B64="$(base64 -i "$WASM_FILE" | tr -d '\n')"

# Split into 72-char lines, each wrapped in single quotes and joined with ' +\n'
LINES=""
while IFS= read -r line; do
  LINES+="  '$line' +\n"
done < <(echo "$B64" | fold -w 72)
# Remove the trailing ' +\n' from the last line (drop the " +")
LINES="${LINES% +\\n}"
LINES+=";"

# Build the replacement block
NEW_BLOCK="$MARKER_START"$'\n'"const WASM_SHA256_B64 ="$'\n'"$(echo -e "$LINES")"

# Replace everything between the marker line and the next blank line that
# follows the last line of the constant (i.e. the line ending with a bare ';').
python3 - "$TARGET_JS" "$MARKER_START" "$NEW_BLOCK" <<'PYEOF'
import sys, re, pathlib

path = pathlib.Path(sys.argv[1])
marker = sys.argv[2]
replacement = sys.argv[3]

src = path.read_text(encoding='utf-8')

# Match: marker line + "const WASM_SHA256_B64 =" + continuation lines ending
# with " +" + final line ending with ";".
pattern = re.compile(
    r'// @generated[^\n]*\n'      # marker
    r'const WASM_SHA256_B64 =\n'  # const header
    r"(?:  '[^']*' \+\n)*"        # intermediate lines
    r"  '[^']*';",                # last line (no " +")
    re.MULTILINE,
)

new_src, n = pattern.subn(replacement, src)
if n == 0:
    print("ERROR: WASM_SHA256_B64 marker not found in", path, file=sys.stderr)
    sys.exit(1)

path.write_text(new_src, encoding='utf-8')
print(f"✅  Patched {path} ({n} replacement(s))")
PYEOF

echo "✅ Done — WASM_SHA256_B64 updated in $TARGET_JS"
