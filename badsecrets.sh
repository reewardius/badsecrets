#!/bin/bash
DEBUG=false
OUTPUT_FILE=""

show_help() {
  echo "Usage: bash badsecrets_scan.sh [OPTIONS]"
  echo
  echo "Options:"
  echo "  -debug              Enable debug mode"
  echo "  -o, --output FILE   Write successful results to FILE"
  echo "  -help, -h           Show this help message"
  echo
}

# Проверка и установка badsecrets
if ! command -v badsecrets &>/dev/null; then
  echo "[*] badsecrets not found, installing..."
  if ! pip install badsecrets 2>&1; then
    echo "[!] Failed to install badsecrets. Try manually: pip install badsecrets"
    exit 1
  fi
  echo "[+] badsecrets installed successfully"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -debug) DEBUG=true; shift ;;
    -o|--output)
      OUTPUT_FILE="$2"
      if [[ -z "$OUTPUT_FILE" ]]; then
        echo "Error: Missing filename for -o|--output"
        exit 1
      fi
      shift 2
      ;;
    -help|-h) show_help; exit 0 ;;
    *) echo "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

if [[ -n "$OUTPUT_FILE" ]]; then
  > "$OUTPUT_FILE"
fi

while IFS= read -r target; do
  echo "[*] Checking: $target"

  unset cookie_map
  findings=$(echo "$target" | nuclei -t cookie-extractor.yaml -silent)

  if [ -n "$findings" ]; then
    mapfile -t pairs < <(echo "$findings" | grep -oP '[a-zA-Z0-9._-]+=[^;]+' | grep -viE '^(Path|Domain|Expires|HttpOnly|Secure|SameSite|Max-Age)=')

    declare -A cookie_map
    for pair in "${pairs[@]}"; do
      key=$(echo "$pair" | cut -d '=' -f1)
      value=$(echo "$pair" | cut -d '=' -f2-)
      cookie_map["$key"]="$value"
    done

    for key in "${!cookie_map[@]}"; do
      value="${cookie_map[$key]}"

      if [ -n "$value" ]; then
        if $DEBUG; then
          echo "[DEBUG] Testing cookie: $key=$value"
        fi

        output=$(badsecrets "$value" 2>&1)

        if echo "$output" | grep -qiE "(Found|secret|match|cracked)"; then
          result="[+] Target: $target | Cookie: $key=$value"
          echo "$result"
          echo "$output"

          if [[ -n "$OUTPUT_FILE" ]]; then
            clean_output=$(echo "$output" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
            {
              echo "$result"
              echo "$clean_output"
              echo "########## RESULT END ##########"
              echo
            } >> "$OUTPUT_FILE"
          fi
        fi
      fi
    done

    unset cookie_map
  fi
done < alive_http_services.txt
