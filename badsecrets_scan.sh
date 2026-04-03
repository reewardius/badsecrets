#!/bin/bash
# badsecrets_scan.sh — extract cookies via nuclei and crack weak secrets with badsecrets

DEBUG=false
HEADLESS=false
OUTPUT_FILE=""
INPUT_FILE=""
SINGLE_TARGET=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

show_help() {
  echo "Usage: bash badsecrets_scan.sh [OPTIONS]"
  echo
  echo "Options:"
  echo "  -debug              Enable debug mode (prints cookies found and tested)"
  echo "  -headless           Enable nuclei headless mode (Chromium, for JS-set cookies)"
  echo "  -f, --file FILE     File with target URLs (default: alive_http_services.txt)"
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

# Check if badsecrets is installed; install it if not
if ! command -v badsecrets &>/dev/null; then
  echo "[*] badsecrets not found, installing..."
  if ! pip install badsecrets 2>&1; then
    echo "[!] Failed to install badsecrets. Try manually: pip install badsecrets"
    exit 1
  fi
  echo "[+] badsecrets installed successfully"
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -debug) DEBUG=true; shift ;;
    -headless) HEADLESS=true; shift ;;
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

# Resolve target source: single URL, file, or default file
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

# Clear output file before scanning
if [[ -n "$OUTPUT_FILE" ]]; then
  > "$OUTPUT_FILE"
fi

# Process a single target URL
process_target() {
  local target="$1"

  # Skip target if it does not respond within 5 seconds
  if ! curl -sk --max-time 5 --output /dev/null "$target"; then
    printf "${GRAY}[*] Checking: %-50s [TIMEOUT]${NC}\n" "$target"
    return
  fi

  unset cookie_map

  # Build nuclei flags — append -headless if requested
  NUCLEI_FLAGS="-t cookie-extractor.yaml -silent"
  $HEADLESS && NUCLEI_FLAGS="$NUCLEI_FLAGS -headless"

  # Run nuclei to extract Set-Cookie values from the target
  findings=$(echo "$target" | nuclei $NUCLEI_FLAGS)

  if [ -z "$findings" ]; then
    printf "${GRAY}[*] Checking: %-50s [NO COOKIES]${NC}\n" "$target"
    return
  fi

  # Parse key=value pairs, filter out cookie attribute directives
  mapfile -t pairs < <(echo "$findings" | grep -oP '[a-zA-Z0-9._-]+=[^;]+' | grep -viE '^(Path|Domain|Expires|HttpOnly|Secure|SameSite|Max-Age)=')

  declare -A cookie_map
  for pair in "${pairs[@]}"; do
    key=$(echo "$pair" | cut -d '=' -f1)
    value=$(echo "$pair" | cut -d '=' -f2-)
    cookie_map["$key"]="$value"
  done

  local cookie_count=${#cookie_map[@]}

  # Print target line with cookie count
  if $DEBUG; then
    printf "${CYAN}[*] Checking: %-50s [COOKIES: %d]${NC}\n" "$target" "$cookie_count"
    echo -e "${CYAN}    ┌─ Cookies extracted:${NC}"
    for key in "${!cookie_map[@]}"; do
      local display_val="${cookie_map[$key]}"
      if [[ ${#display_val} -gt 70 ]]; then
        display_val="${display_val:0:67}..."
      fi
      echo -e "${CYAN}    │  ${BOLD}${key}${NC}${CYAN} = ${display_val}${NC}"
    done
    echo -e "${CYAN}    └─ Running badsecrets...${NC}"
  else
    printf "[*] Checking: %-50s [COOKIES: %d]\n" "$target" "$cookie_count"
  fi

  local found_secret=false

  for key in "${!cookie_map[@]}"; do
    value="${cookie_map[$key]}"

    if [ -n "$value" ]; then
      if $DEBUG; then
        echo -e "${GRAY}    [~] Testing: ${BOLD}${key}${NC}"
      fi

      # Run badsecrets against the raw cookie value
      output=$(badsecrets "$value" 2>&1)

      # Check for a successful crack
      if echo "$output" | grep -q "Known Secret Found!"; then
        found_secret=true

        # Extract key fields from badsecrets output
        local secret_val module severity
        secret_val=$(echo "$output" | grep "^Secret:"           | cut -d':' -f2- | xargs)
        module=$(echo "$output"     | grep "^Detecting Module:" | cut -d':' -f2- | xargs)
        severity=$(echo "$output"   | grep "^Severity:"         | cut -d':' -f2- | xargs)

        echo -e "${GREEN}${BOLD}[+] Checking: %-50s [YES — SECRET FOUND]${NC}" "$target"
        echo -e "${GREEN}    ┌─ Cookie   : ${BOLD}${key}${NC}"
        echo -e "${GREEN}    ├─ Module   : ${module}${NC}"
        echo -e "${GREEN}    ├─ Secret   : ${BOLD}${secret_val}${NC}"
        echo -e "${GREEN}    ├─ Severity : ${severity}${NC}"

        if $DEBUG; then
          local display_val="$value"
          if [[ ${#display_val} -gt 70 ]]; then
            display_val="${display_val:0:67}..."
          fi
          echo -e "${GREEN}    ├─ Value    : ${display_val}${NC}"
          echo -e "${GREEN}    └─ Full badsecrets output:${NC}"
          echo "$output" \
            | grep -vE '^\s*[_\\|/ )]+\s*$|^Version\s*-|^\s*$' \
            | while IFS= read -r line; do
                echo -e "${GREEN}       ${line}${NC}"
              done
        else
          local short_val="$value"
          if [[ ${#short_val} -gt 60 ]]; then
            short_val="${short_val:0:57}..."
          fi
          echo -e "${GREEN}    └─ Value    : ${short_val}${NC}"
        fi

        # Write to output file (strip ANSI codes and badsecrets banner/version line)
        if [[ -n "$OUTPUT_FILE" ]]; then
          clean_output=$(echo "$output" \
            | sed 's/\x1B\[[0-9;]*[JKmsu]//g' \
            | sed -n '/Known Secret Found!/,$p' \
            | grep -vE '^\s*$')
          {
            echo "[+] Target: $target | Cookie: $key=$value"
            echo "$clean_output"
            echo "########## RESULT END ##########"
            echo
          } >> "$OUTPUT_FILE"
        fi

      else
        if $DEBUG; then
          echo -e "${GRAY}    [~] No match for ${key}${NC}"
        fi
      fi
    fi
  done

  if ! $found_secret; then
    if $DEBUG; then
      echo -e "${YELLOW}    └─ No weak secrets found for any cookie${NC}"
    else
      echo -e "${YELLOW}    └─ No weak secrets found${NC}"
    fi
  fi

  unset cookie_map
}

# Run against single URL or iterate over file
if [[ -n "$SINGLE_TARGET" ]]; then
  process_target "$SINGLE_TARGET"
else
  while IFS= read -r target; do
    # Skip empty lines and comments
    [[ -z "$target" || "$target" == "#"* ]] && continue
    process_target "$target"
  done < "$TARGETS"
fi
