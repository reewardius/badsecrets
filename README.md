# badsecrets

Automated cookie secret cracker. Extracts cookies from live HTTP targets using nuclei, then tests each cookie value against known weak secrets using [badsecrets](https://github.com/blacklanternsecurity/badsecrets).

Supports Flask signed cookies, JWT tokens, ASP.NET machine keys, Django secrets, and more.

---

## Requirements

| Tool | Install |
|---|---|
| nuclei | https://github.com/projectdiscovery/nuclei |
| badsecrets | auto-installed by the script, or `pip install badsecrets` |
| cookie-extractor.yaml | custom nuclei template — must be present in the working directory |
| Chromium *(optional)* | required only for `-headless` mode |

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
| `-debug` | Print all extracted cookies and each badsecrets test |
| `-headless` | Enable nuclei headless mode (Chromium) for JS-set cookies |
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

# Enable headless mode for SPA targets
bash badsecrets_scan.sh -f targets.txt -headless

# Everything at once
bash badsecrets_scan.sh -f targets.txt -headless -debug -o results.txt
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

## Console output

### Normal mode

```
[*] Checking: https://timeout-target.com              [TIMEOUT]
[*] Checking: http://no-cookie-target.com             [NO COOKIES]
[*] Checking: http://live-target.com                  [COOKIES: 2]
    └─ No weak secrets found
[+] Checking: http://vuln-target.com                  [YES — SECRET FOUND]
    ┌─ Cookie   : session
    ├─ Module   : Flask_SignedCookies
    ├─ Secret   : secret
    ├─ Severity : HIGH
    └─ Value    : eyJ1c2VyIjoiYWRtaW4i...
```
<img width="945" height="471" alt="image" src="https://github.com/user-attachments/assets/52669cfa-59ba-4b91-b028-cf3b14692b4c" />


### Debug mode (`-debug`)

Shows all extracted cookie names/values before testing, and the result of each badsecrets call:

```
[*] Checking: http://live-target.com                  [COOKIES: 2]
    ┌─ Cookies extracted:
    │  session = eyJ1c2VyIjoiYWRtaW4iLCJsb2dnZWRfaW4iOnRydWV9...
    │  _csrf   = abc123xyz
    └─ Running badsecrets...
    [~] Testing: session
    [~] Testing: _csrf
    [~] No match for _csrf
    └─ No weak secrets found for any cookie

[+] Checking: http://vuln-target.com                  [YES — SECRET FOUND]
    ┌─ Cookie   : session
    ├─ Module   : Flask_SignedCookies
    ├─ Secret   : secret
    ├─ Severity : HIGH
    ├─ Value    : eyJ1c2VyIjoiYWRtaW4iLCJsb2dnZWRfaW4iOnRydWV9...
    └─ Full badsecrets output:
       Known Secret Found!
       Detecting Module: Flask_SignedCookies
       ...
```

---

## File output (`-o`)

Results are separated in file by a delimiter:

```
[+] Target: http://vuln-target.com | Cookie: session=eyJ1c2VyIjoiYWRtaW4...
Known Secret Found!
Detecting Module: Flask_SignedCookies
Product Type: Flask Signed Cookie
Product: eyJ1c2VyIjoiYWRtaW4...
Secret Type: Flask Password
Location: manual
Secret: secret
Severity: HIGH
Details: True
########## RESULT END ##########
```

---

## Headless mode (`-headless`)

Passes the `-headless` flag to nuclei, which launches a Chromium browser to render the page before extracting cookies.

Use this when:
- The target is a Single Page Application (SPA)
- Cookies are set via JavaScript (`document.cookie = "..."`) rather than HTTP `Set-Cookie` headers
- Authentication involves a JS-driven redirect that sets a session token

Do not use this when:
- The server sets cookies via HTTP headers on the first request (nuclei catches these without headless)
- Chromium is not installed on the scanning host
- Speed matters — headless mode is significantly slower

Requires Chromium to be installed and accessible to nuclei. If not found, nuclei will error out.

---

## How it works

```
targets file / single URL
        │
        ▼
  curl --max-time 5  →  no response → TIMEOUT, skip
        │
        ▼
  nuclei -t cookie-extractor.yaml [-headless]
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
        ├── "Known Secret Found!" → print result [green], write to file
        └── no match             → next cookie  [yellow if last]
```
