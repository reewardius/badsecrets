#!/bin/bash
DEBUG=false
OUTPUT_FILE=""
INPUT_FILE=""
SINGLE_TARGET=""

show_help() {
  echo "Usage: bash badsecrets_scan.sh [OPTIONS]"
  echo
  echo "Options:"
  echo "  -debug              Enable debug mode"
  echo "  -f, --file FILE     File with URLs (default: alive_http_services.txt)"
  echo "  -u, --url URL       Single target URL"
  echo "  -o, --output FILE   Write successful results to FILE"
  echo "  -help, -h           Show this help message"
  echo
  echo "Examples:"
  echo "  bash badsecrets_scan.sh -f targets.txt"
  echo "  bash badsecrets_scan.sh -u http://example.com"
  echo "  bash badsecrets_scan.sh -f targets.txt -o results.txt -debug"
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
    -f|--file)
      INPUT_FILE="$2"
      if [[ -z "$INPUT_FILE" ]]; then
        echo "Error: Missing filename for -f|--file"
        exit 1
      fi
      shift 2
      ;;
    -u|--url)
      SINGLE_TARGET="$2"
      if [[ -z "$SINGLE_TARGET" ]]; then
        echo "Error: Missing URL for -u|--url"
        exit 1
      fi
      shift 2
      ;;
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

# Определяем источник целей
if [[ -n "$SINGLE_TARGET" && -n "$INPUT_FILE" ]]; then
  echo "Error: Use either -u or -f, not both"
  exit 1
elif [[ -n "$SINGLE_TARGET" ]]; then
  TARGETS="$SINGLE_TARGET"
elif [[ -n "$INPUT_FILE" ]]; then
  if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: File not found: $INPUT_FILE"
    exit 1
  fi
  TARGETS="$INPUT_FILE"
elif [[ -f "alive_http_services.txt" ]]; then
  echo "[*] No target specified, using default: alive_http_services.txt"
  TARGETS="alive_http_services.txt"
else
  echo "Error: No target specified. Use -u <url> or -f <file>"
  show_help
  exit 1
fi

if [[ -n "$OUTPUT_FILE" ]]; then
  > "$OUTPUT_FILE"
fi

process_target() {
  local target="$1"
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

        if echo "$output" | grep -q "Known Secret Found!"; then
          result="[+] Target: $target | Cookie: $key=$value"
          echo "$result"
          echo "$output"

          if [[ -n "$OUTPUT_FILE" ]]; then
            clean_output=$(echo "$output" \
              | sed 's/\x1B\[[0-9;]*[JKmsu]//g' \
              | grep -vE '^\s*[_\\|/ )]+\s*$|^Version\s*-|^\s*$')
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
}

# Запуск по одному URL или по файлу
if [[ -n "$SINGLE_TARGET" ]]; then
  process_target "$SINGLE_TARGET"
else
  while IFS= read -r target; do
    [[ -z "$target" || "$target" == "#"* ]] && continue
    process_target "$target"
  done < "$TARGETS"
fi
