# badsecrets

Automated cookie secret cracker. Extracts cookies from live HTTP targets using nuclei, then tests each cookie value against known weak secrets using [badsecrets](https://github.com/blacklanternsecurity/badsecrets).

Supports Flask signed cookies, JWT tokens, ASP.NET machine keys, Django secrets, and more.

---

## Requirements

| Tool | Install |
|---|---|
| nuclei | https://github.com/projectdiscovery/nuclei |
| badsecrets | auto-installed by the script, or `pip install badsecrets` |
| cookie-extractor.yaml | must be present in the working directory |

---

## Usage

```bash
bash badsecrets_scan.sh [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `-u, --url URL` | Single target URL |
| `-f, --file FILE` | File with target URLs, one per line |
| `-o, --output FILE` | Write results to file (banner and version line stripped) |
| `-debug` | Print each cookie value being tested |
| `-help, -h` | Show help |

If neither `-u` nor `-f` is provided, the script falls back to `alive_http_services.txt` in the current directory.

---

## Examples

```bash
# Scan a single URL
bash badsecrets_scan.sh -u http://example.com

# Scan a list of URLs
bash badsecrets_scan.sh -f targets.txt

# Scan with debug output and save results
bash badsecrets_scan.sh -f targets.txt -o results.txt -debug

# Use default alive_http_services.txt
bash badsecrets_scan.sh -o results.txt
```

---

## Input file format

Plain text, one URL per line. Empty lines and lines starting with `#` are ignored.

```
http://target1.com
http://target2.com:8080
# this line is ignored
https://target3.com
```

---

## Output

Console output for each hit:

```
[+] Target: http://example.com | Cookie: session=eyJ1c2VyIjoiYWRtaW4...
Known Secret Found!
Detecting Module: Flask_SignedCookies
Product Type: Flask Signed Cookie
Product: eyJ1c2VyIjoiYWRtaW4...
Secret Type: Flask Password
Location: manual
Secret: secret
Severity: HIGH
Details: True
```

---

## How it works

```
targets file / single URL
        │
        ▼
  nuclei -t cookie-extractor.yaml
  (HTTP request → extract Set-Cookie header)
        │
        ▼
  bash parser
  (strip Path, Domain, Expires, HttpOnly, Secure, SameSite, Max-Age)
        │
        ▼
  for each cookie value:
    badsecrets <value>
        │
        ├── "Known Secret Found!" → print result, write to file
        └── no match → next cookie
```
