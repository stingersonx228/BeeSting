#!/bin/sh
# Installs the harness dependencies in ITS OWN directory. Copy pg-harness into a temporary
# folder and run setup.sh there, so node_modules never ends up in the skill or the project.
set -e
cd "$(dirname "$0")"
npm install --no-audit --no-fund --silent
# On macOS the binaries package sometimes arrives without its library symlinks — restore them.
for d in node_modules/@embedded-postgres/*/; do
  if [ -f "$d/scripts/hydrate-symlinks.js" ]; then
    (cd "$d" && node scripts/hydrate-symlinks.js >/dev/null 2>&1) || true
  fi
done
echo "pg-harness is ready: node $(pwd)/harness.mjs --repo <project path>"
