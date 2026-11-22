#!/bin/sh
# SRI hash (sha384) for CDN files. Usage: sh sri.sh URL [URL ...]
# Put into the tag: integrity="sha384-..." crossorigin="anonymous"
set -e
[ $# -gt 0 ] || { echo "Usage: sh sri.sh https://cdn.jsdelivr.net/npm/pkg@1.2.3/dist/pkg.js"; exit 1; }
for url in "$@"; do
  case "$url" in
    *@latest*|*@[0-9]/*|*@[0-9][0-9]/*) echo "⚠ $url — the version is not exact; the hash will break when the package updates" ;;
  esac
  hash=$(curl -fsSL "$url" | openssl dgst -sha384 -binary | openssl base64 -A)
  echo "$url"
  echo "  integrity=\"sha384-$hash\" crossorigin=\"anonymous\""
done
