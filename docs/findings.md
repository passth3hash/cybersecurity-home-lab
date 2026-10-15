# Security Findings 

Contains security findings identified and validated during testing of the OWASP Juice Shop home lab.

Testing primarily followed a black-box approach, using application responses to investigate and validate suspected vulnerabilities. Source code analysis was used selectively where it provided additional context.

For testing I have used the following methodology: 

**Observation → Hypotheses → Validation → Impact → Result → Evidence**



## 1 — Broken Access Control 

Broken access control occurs when an application fails to enforce authorization correctly, allowing users to access resources or perform beyond their intended permissions.

### Finding 01 - Insecure Direct Object Reference (IDOR) - Basket access 
* **Severity:** High 
* **Category:** Broken Access Control 
* **Affected component:** Shopping basket 
* **Affected endpoint:** `GET /rest/basket/{id}` 
* **Testing approach:** Black-box 

#### Observation 
While testing the shopping basket feature, I noticed that the basket's unique ID number was visible directly in the URL when the application requested basket information.

#### Hypothesis 
I suspected that the application was trusting the ID number provided in the URL blindly, without verifying if the basket actually belonged to the logged-in user.

#### Validation 
To test this, I logged in as a regular user **(User ID 25, assigned to Basket ID 6)** and captured the traffic in Burp. I then performed the following tests using the exact same login session:

- GET /rest/basket/6 successfuly returned my own basket data.
- GET /rest/basket/1 **successfuly returned the basket data belonging to User ID 1**

The application did not require a change of user accounts or a different authorization token to view User 1's data.

#### Impact 
Any logged-in user can access the shopping activity and product selections of any customer simply by guessing or cycling through basket ID numbers. In a real world e-commerce application, exposing a customer's intent to buy violates data privacy regulations and damages customer trust. 

#### Result 
**Confirmed - unauthorized cross-user basket access.**

The issue was validated through black-box testing against the application. 

#### Evidence 
The initial request demonstrates a normal, authorized action where User 25 requests their own basket data (Basket ID 6) 

<details>
<summary>📸 <b>Baseline - Accessing my own basket</b></summary>

<img width="942" height="546" alt="IDOR" src="https://github.com/user-attachments/assets/b98a800c-fb01-4547-b06b-38a9f2814d33" />
  
</details>

The follow-up request shows the exploit. Keeping the exact same login session, the request parameter was changed to target Basket ID 1 (GET /rest/basket/1)

<details>
<summary>📸 <b>Validation - Accessing another user's basket</b></summary>

<img width="938" height="544" alt="IDOR1" src="https://github.com/user-attachments/assets/8473ca29-9947-4a26-8119-170bb00fa852" />

</details>

#### Remediation 
- Never rely on user-supplied IDs in the URL to fetch sensitive data. Instead, the server should read the user's secure login token (session/JWT) to determine      which basket belongs to them.
- Ensure that the same ownership verification logic is applied to all basket operations, including viewing, adding items, modifying quantities, and checking out.



### Finding 02 - Mass Data Exposure in Complaints endpoint
* **Severity:** Medium 
* **Category:** Broken Access Control  
* **Affected endpoint:** `GET /api/Complaints` 
* **Testing approach:** Black-box 

#### Observation 
While testing the customer feedback features, I noticed that the application uses a centralized API endpoint (`/api/Complaints/`) to fetch complaint logs. I wanted to verify if the application restricted the returned data to show only the complaints submitted by the logged-in user.

#### Hypothesis 
The testing targeted a potential lack of server-side data filtering, causing it to return the entire database collection of customer complaints to any authenticated user.

#### Validation 
To verify this behavior, I performed three distinct tests:

- **User Account A (User ID 25):** I sent a request to `GET /api/Complaints/`. The server responded with `200 OK` and returned a list containing complaints submitted by multiple other accounts (including User ID 3).
- **User Account B (User ID 26):** To ensure this wasn't an isolated glitch, I repeated the request using a completely separate user account. The server again returned all global complaints, including those from User ID 25.
- **Unauthenticated Check:**  I attempted to access the endpoint without a login token. The application successfully blocked the request with a `401 Unauthorized` response.

These results confirm that while the application checks *if* a user is logged in, it fails to check *who* is logged in before dumping the data.

#### Impact
Any registered user on the platform can view the feedback, private customer disputes, and personal accounts of all other users. Depending on what a customer writes in a complaint form (such as tracking numbers, names, or order details), this flaw results in an unauthorized leak of private data.

#### Result
**Confirmed — Authenticated mass data exposure of customer complaints.**

#### Evidence 
The visual proof confirming this mass data exposure is documented below:

First test account (User ID 25) - The initial test demonstrates that an authenticated user account receives a complete list of complaints submitted by multiple other global users.

<details>
<summary>📸 <b>User Account A (User ID 25) Data Exposure</b></summary>

<img width="939" height="548" alt="Mass data exposure" src="https://github.com/user-attachments/assets/45d845fc-89bf-471a-8a12-b87df4bf1812" />

</details>

Second test account (User ID 26) - The follow-up test confirms that this authorization bypass systematically impacts other accounts, allowing a completely different user to view the exact same global datasets.

<details>
<summary>📸 <b>User Account B (User ID 26) Data Exposure</b></summary>

<img width="940" height="547" alt="Mass data1" src="https://github.com/user-attachments/assets/2b1f41f4-6202-4c11-bae4-a82ad510a4cb" />

</details>

Unauthenticated Request Check - The final test proves that while the system lacks user-to-user boundaries, it successfully enforces basic login checks by rejecting requests missing a session token.


<details>
<summary>📸 <b>Unauthenticated Request (401 Unauthorized Response)</b></summary>

<img width="940" height="543" alt="Mass data2" src="https://github.com/user-attachments/assets/7cf4581c-f026-4942-9d44-03759f7a0b0f" />


</details>

#### Remediation
- Return only the complaints the user is authorized to view.
- If complaint listings are intended for administrators, implement strict Role-Based Access Control (RBAC) on the server to ensure only accounts with verified administrator privileges can access the `/api/Complaints/` path.



## 2 — Injection
Injection vulnerabilities occur when an application handles user input in an unsafe manner, allowing that input to alter the structure and execution of an underlying command or database query.

### Finding 03 — SQL Injection: Login Authentication Bypass
* **Severity:** Critical
* **Category:** Injection — SQL Injection
* **Affected Component:** Login Interface
* **Affected Endpoint:** `POST /rest/user/login`
* **Testing Approach:** Black-box testing

#### Observation
I initiated testing by sending a standard login request containing a valid email address and an incorrect password. The application returned a standard `401 Unauthorized` response.

Following this, I appended a single quote character (`'`) to the email value. The backend application responded with a `500 Internal Server Error` and exposed a raw, verbose database error message in the server response. This behavior strongly indicated that user input was being concatenated directly into database queries without sanitization.

#### Hypothesis
The testing targeted a potential SQL injection vulnerability within the login input fields, where malicious syntax could manipulate the logic of the backend SQL query to alter authentication enforcement.

#### Validation
To validate this vulnerability, I intercepted the login request and injected a classic SQL authentication bypass payload into the email field:

```json
{
  "email": "admin@juice-shop.op' OR 1=1--",
  "password": "test"
}
```
The database processed the injected payload, forcing the query evaluation to always return true (`1=1`) while commenting out (`--`) the password check entirely.
Instead of rejecting the request, the application returned a `200 OK` response status, generated an authenticated JSON Web Token (JWT), and granted full administrative access to the user session without requiring a valid password.

#### Impact
An unauthenticated user can exploit this structural flaw to bypass the authentication system and gain full administrative privileges over the application.

#### Result
**Confirmed — SQL injection resulting in administrative authentication bypass.**

#### Evidence
The visual timeline verifying the authentication bypass sequence is detailed below:

**Normal Login Failure** 
The initial test demonstrates the application successfully enforcing standard password verification under normal conditions.

<details>
<summary>📸 <b>401 Unauthorized Response (Incorrect Password)</b></summary>

<img width="939" height="548" alt="sql" src="https://github.com/user-attachments/assets/7010c10e-7798-451c-a6b5-e541af3c327a" />

</details>

**Verbose database error leak**
The second test shows the server processing the single quote string, crashing the backend query, and exposing raw database system details.

<details>
<summary>📸 <b>500 Internal Server Error (Database Information Leak)</b></summary>

<img width="939" height="589" alt="sql1" src="https://github.com/user-attachments/assets/7a22a07e-00ed-4a3c-ac67-63eab70ea7bd" />

</details>

**Successful Authentication Bypass Exploit** 
The final test documents the successful injection payload passing through, generating a `200 OK` status and an administrative token payload.

<details>
<summary>📸 <b>200 OK Response (Administrative Access Granted)</b></summary>

<img width="938" height="547" alt="sql2" src="https://github.com/user-attachments/assets/34c02d79-1de8-404c-b844-2b44e37721e3" />

</details>

#### Remediation
- Use parameterized SQL queries instead of building database queries by inserting user input directly into SQL statements.
- Handle database errors on the server and return generic error messages to users.

### Finding 04 - DOM-Based Cross-Site Scripting (XSS) 
* **Severity:** Medium
* **Category:** Injection — Cross-Site Scripting (DOM-Based XSS)
* **Affected Component:** Search Page
* **Affected Location:** `/#/search?q=` 
* **Testing Approach:** Gray-box (Black-box and source code review)

#### Observation
During black-box testing, the application search page interpreted HTML text supplied directly through the query parameter rather than rendering it as safe, literal plain text.

Initial input of a basic HTML structural tag (`<b>XSS-LAB-002</b>`) resulted in the application rendering the string in **bold**. Subsequent validation confirmed that client-side script execution context could be achieved through this vector.

#### Hypothesis
The search page may be inserting user-controlled input into the page in a way that allows HTML injection and JavaScript execution.

#### Validation
I tested the search page by entering non-malicious HTML and JavaScript test inputs to see how the website handled them:

- **HTML Test:** <b>XSS-LAB-002</b> — rendered as bold text, showing that the input was interpreted as HTML.
- **JavaScript Test:** An image-based XSS payload using `src=x` and an `onerror` event handler triggered a JavaScript alert in the browser.

After seeing this, I checked the website's source code and found the problem on line 11 of `search-result.component.html`:

```html
<span id="searchValue" [innerHTML]="searchValue"></span>
```

This code uses `[innerHTML]`, which tells the website to trust whatever the user types as real HTML. Since the payload runs completely in the browser and does not show up in the backend Burp Suite logs, this confirms it is a DOM-based XSS vulnerability.

#### Impact
An attacker could build a special link containing this payload and trick another user into clicking it. If the victim clicks the link, the attacker's script will run inside their browser session. Depending on the user's account privileges, this could allow the attacker to interact with the app as if they were that user or view sensitive information on the screen.

#### Result
**Confirmed — DOM-based XSS.**

Testing showed that the search page interprets HTML tags, and my image-based payload successfully triggered a browser alert. Looking at the frontend source code confirmed that the application uses an unsafe `[innerHTML]` binding to display the search query.

#### Evidence
Below is a visual timeline of verifying the XSS vulnerability: 

**HTML Interpretation:**

<details>
<summary>📸 <b> A screenshot showing the text rendering in bold, confirming the page reads HTML tags</b></summary>

<img width="1206" height="144" alt="XSS" src="https://github.com/user-attachments/assets/24e6d953-a83c-42b7-99fd-3a4bdecec387" />

</details>

**Script Execution:** 

<details>
<summary>📸 <b> A screenshot showing the JavaScript alert box popup triggered by the image payload.</b></summary>

<img width="1202" height="492" alt="XSS1" src="https://github.com/user-attachments/assets/52430112-623c-42c7-9d45-3b85cb7b443b" />

</details>

**Backend Verification:** 

<details>
<summary>📸 <b> A Burp Suite screenshot proving the payload never touches or reflects in the server's response.</b></summary>

<img width="941" height="589" alt="XSS2" src="https://github.com/user-attachments/assets/324d158f-9cea-4284-a862-32b917c11323" />

</details>

**Source Code inspection:** 

<details>
<summary>📸 <b> A screenshot of the frontend code highlighting the exact `[innerHTML]` line causing the bug.</b></summary>

<img width="846" height="123" alt="XSS3" src="https://github.com/user-attachments/assets/4c5f4725-5070-4ea8-bdca-5eb6ed666600" />

</details>

#### Remediation
- Avoid inserting untrusted input through innerHTML when plain-text rendering is sufficient.
- **For Angular:** Change the code from `[innerHTML]="searchValue"` to simple double curly brackets `{{ searchValue }}`. This tells the website to treat whatever the user types as normal, readable text instead of running it as live HTML code.



## 3 — Sensitive Data Exposure 
Sensitive data exposure occurs when an application reveals confidential or personal information to users who are not authorized to access it. This can include password hashes, personal details, authentication tokens or internal application data. 

### Finding 05 — Unauthenticated Access to Sensitive User Data
* **Severity:** High
* **Category:** Sensitive Data Exposure
* **Affected Component:** User Data API
* **Affected Location:**  `GET /rest/memories/`
* **Testing Approach:** Black-box

#### Observation
During testing, I found that the `/rest/memories/` endpoint returned user records without requiring authentication. The response contained sensitive information, including usernames, email addresses, password hashes, user roles, and other account-related fields.

#### Hypothesis
If the endpoint does not enforce authentication and authorization, an unauthenticated user may be able to retrieve sensitive information belonging to multiple application users.

#### Validation
I tested this vulnerability by sending a direct GET request to the /rest/memories/ endpoint using Burp Suite without including any login tokens or session cookies.
The server responded with a 200 OK status and dumped a large list of user accounts containing private details. To verify it wasn't a fluke, I cleared my cookies and repeated the test in a completely fresh private browser window. The data still loaded, confirming that anyone can access this information without logging in.

#### Impact
An attacker could easily download a list of all user accounts on the system. They could use the leaked email addresses for targeted phishing attacks or attempt to crack the exposed password hashes offline to take over accounts.

#### Result
**Confirmed — Unauthenticated access to sensitive user data.**

The endpoint returned multiple user records and sensitive fields without requiring authentication. The issue was reproduced in a fresh private browser session.

#### Evidence
Below is a visual timeline of verifying data exposure 

**Unauthenticated  API Request:**

<details>
<summary>📸 <b> A Burp Suite screenshot showing a successful request sent without any login tokens.</b></summary>

<img width="1024" height="533" alt="sensitive data exposure1" src="https://github.com/user-attachments/assets/d567c227-71af-4164-b704-259647caefa8" />

</details>

**Redacted Data Leak Excerpt:**

<details>
<summary>📸 <b> A cropped screenshot of the JSON response showing where fields like emails and password hashes were exposed (with all real values blurred out for safety).</b></summary>

<img width="942" height="588" alt="sensitive data exposure2" src="https://github.com/user-attachments/assets/5470f28a-a4c4-4d3a-a892-97535edc15bb" />

</details>

#### Remediation
- Require authentication for endpoints that expose private user information.
- Enforce server-side authorization so users can access only the data they are permitted to view.
- Return only the fields necessary for the endpoint's intended purpose.

### Finding 06 — Unauthenticated Access to Application Configuration
* **Severity:** Medium
* **Category:** Sensitive Data Exposure
* **Affected Component:** Application Configuration API
* **Affected Endpoint:** `GET /rest/admin/application-configuration` 
* **Testing Approach:** Black-box

#### Observation
While exploring the application's API endpoints using Burp Suite, I discovered that the `/rest/admin/application-configuration` address returned a large JSON response without requiring authentication. The response contained application settings, challenge-related configuration, social media links, a Google OAuth client ID, product data, and security-question-related information.

#### Hypothesis
The endpoint may expose sensitive configuration or security-related information to unauthenticated users because appropriate access controls may not be enforced.

#### Validation
I evaluated this issue by sending a direct `GET` request to the configuration endpoint using Burp Suite without attaching any active login tokens or cookies. The server responded with a `200 OK` status and returned a large file including security-question-related information.

#### Impact
Exposing sensitive configuration and security-related information may help an attacker understand the application's implementation and plan more targeted attacks. It gives them a map of how the application is built, what features are active, and how security questions are handled, making it much easier to plan more targeted attacks.

#### Result
**Confirmed — Unauthenticated access to application configuration.**

The endpoint returned a large configuration response without requiring authentication.

#### Evidence
Below is a visual timeline of verifying the configuration exposure

**Unauthenticated API Request:** 

<details>
<summary>📸 <b>A Burp Suite screenshot showing a successful request sent to the admin configuration endpoint without login credentials.</b></summary>

<img width="1029" height="585" alt="application configuration" src="https://github.com/user-attachments/assets/0fb56487-3fea-4576-946a-7d72c5286bed" />

</details>

**A Redacted Setup Data Excerpt:**

<details>
<summary>📸 <b>A redacted JSON excerpt showing representative configuration fields.</b></summary>

<img width="1028" height="588" alt="application configuration1" src="https://github.com/user-attachments/assets/906f063b-d399-4ca0-9de4-60d3df41ee30" />

</details>

#### Remediation
- Restrict this endpoint so that only logged-in administrators can access it, returning a 401 Unauthorized error to anyone else.
- Remove security-question answers, secrets, and other sensitive values from API responses.
- Review which configuration fields are intended to be publicly accessible.



## 4 — Business Logic 
Business logic vulnerabilities occur when an application fails to enforce the rules that govern how its features should work. Attackers may abuse these weaknesses to perform unauthorized actions, bypass restrictions or gain unintended benefits such as applying an unauthorized discount. 

### Finding 07 — Coupon Forgery Allows an Unauthorized 99% Discount
* **Severity:** Medium
* **Category:** Business Logic Flaw / Improper Input Validation
* **Affected Component:** Coupon and Checkout Functionality
* **Affected Endpoint:** `PUT /rest/basket/{basketId}/coupon/{couponCode}` 
* **Testing Approach:** Gray-box

#### Observation
While testing how the website handles discount codes at checkout, I found that I could manipulate the system into giving me a 99% discount, even though the legitimate promotional coupon I had observed offered a lower discount.

The application returned a successful response indicating a 99% discount, and the checkout order summary later showed the discounted price.

#### Hypothesis
The application creates its discount codes using a predictable format. Because the backend server does not double-check if the discount code was actually made by an administrator, a user can easily change the numbers inside the code to invent their own discount amount.

#### Validation
I inspected the coupon-generation and validation logic and found that coupon values were encoded using Z85. 

**Reading the Code:** I checked the application's backend files and discovered the coupon codes format consisted of an abbreviated month, a two-digit year, and a discount percentage, such as OCT26-99. The validation logic decoded the coupon, checked its format, and verified that the coupon's month and year matched the current month and year. However, I found no cryptographic integrity check to prevent someone from modifying the discount percentage and generating a new encoded value.

To validate the issue, I generated a coupon representing a 99% discount using a short Python proof of concept and submitted it through Burp Suite. The application returned `200 OK` with a response indicating `{"discount":99}`.

I then verified the business impact through the checkout flow. The order summary showed a product priced at €3.49, a promotion of €3.46, and a final total of €0.03, consistent with a 99% discount.

#### Impact
An attacker could use this trick to buy any product in the store for virtually free, causing massive financial loss for a real business. 

#### Result
**Confirmed — Forged coupon accepted with a 99% discount.**

The server accepted my modified coupon code, and the final checkout summary screen confirmed that the price dropped down to just 3 cents.

#### Evidence
Below is a visual timeline verifying the coupon forgery flaw.

**Manipulated API Response:**
<details>
<summary>📸 <b>A Burp Suite screenshot showing the coupon request returning a 200 OK and confirming a 99% discount.</b></summary>

<img width="1031" height="538" alt="forged ticket" src="https://github.com/user-attachments/assets/8aae15e2-3f75-4f48-97ce-2a3915ae0172" />

</details>

**Price Bypassed Checkout Summary:**
<details>
<summary>📸 <b>A screenshot of the checkout screen showing the original €3.49 price dropped to a final total of €0.03.</b></summary>

<img width="1032" height="587" alt="final price1" src="https://github.com/user-attachments/assets/c9654141-e3ac-49be-b140-0a961a03aa1f" />

</details>

**Python Code Tool:**
<details>
<summary>💻 <b>The simple Python proof-of-concept script used to encode the custom Z85 coupon values.</b></summary>

import base64

coupon = "OCT26-99"

encoded = base64.z85encode(coupon.encode())

print(encoded.decode())

</details>

#### Remediation
- Do not use simple, predictable formats like Z85 to handle discount data. Instead, coupon codes should be completely random, secret strings stored safely in a backend database.
- Never let the web browser dictate the discount percentage. The backend server must strictly control what each code is worth.
- Generate coupons using a cryptographically secure, server-controlled process.



## 5 — Security Misconfiguration 
Security misconfiguration occurs when an application or system is configured incorrectly or lacks appropiate security controls. This can expose sensitive files, reveal internal information or even allow users to bypass intended restrictions. 

### Finding 08 — Developer Backup Exposed Through File-Validation Bypass
* **Severity:** Low
* **Category:** Security Misconfiguration
* **Affected Component:** FTP File Access
* **Affected Endpoint:** `GET /ftp/package.json.bak` 
* **Testing Approach:** Black-box

#### Observation
While exploring the application's `/ftp/` directory, I discovered a backup file named `package.json.bak`. A direct request to this file was blocked with a message stating that only .md and .pdf files were allowed. 

A direct request to this file was blocked with a message stating that only .md and .pdf files were allowed.

#### Hypothesis
The file-access validation may be bypassable by manipulating the requested filename, allowing a file with a disallowed extension to be retrieved.

#### Validation
First, I requested the normal URL `/ftp/package.json.bak`. The server blocked me and returned a `403 Forbidden` error. Next, I added a URL trick (`%2500.md`) to the end of the filename: `/ftp/package.json.bak%2500.md`.

The file contained application general information about the application and its components. I did not identify credentials or other confirmed secrets in the exposed manifest.

A null byte essentially tells the server's backend code "stop reading the filename right here". 

#### Impact
Exposing backup files is risky because it reveals the exact blueprint of the application's backend. By looking at the stolen file, an attacker can see the exact versions of the software libraries used and look up public databases (like CVEs) to see if any of these specific versions have unpatched, known security bugs that can be used to take over the server.

#### Result
**Confirmed — The file checker was bypassed and a backup file was exposed.** 

The standard request was blocked, but the modified URL successfully downloaded the file.

#### Evidence
Below is a visual timeline of verifying the configuration exposure:

**Blocked Request (Baseline Test):**
<details>
<summary>📸 <b>A Burp Suite screenshot showing the original file request returning a 403 Forbidden error.</b></summary>

<img width="938" height="585" alt="secuirty misconfiguration" src="https://github.com/user-attachments/assets/34f8c4a9-1b9c-4445-906f-9902d5f35218" />

</details>

**Bypassed Filter Request:**
<details>
<summary>📸 <b>A Burp Suite screenshot showing the null byte trick successfully bypassing the filter and returning a 200 OK.</b></summary>

<img width="1157" height="756" alt="security misconfiguration1" src="https://github.com/user-attachments/assets/235f88f8-657f-447b-8185-e6e3c0da5e3d" />

</details>

**Exposed Backup Contents:**
<details>
<summary>📋 <b>Click to expand the full text manifest retrieved from the package.json.bak file.</b></summary>

```json
{
  "name": "juice-shop",
  "version": "6.2.0-SNAPSHOT",
  "description": "An intentionally insecure JavaScript Web Application",
  "dependencies": {
    "body-parser": "~1.18",
    "express": "~4.16",
    "express-jwt": "0.1.3",
    "js-yaml": "3.10",
    "sequelize": "~4",
    "sqlite3": "~3.1.13"
  }
}
```

</details>

#### Remediation
- Remove public backups and never store public backups (like `.bak`, `.old`, or `.zip`) in folders that can be accessed from the web browser.
- Fix the file filter so it cannot be tricked by URL characters like `%2500`. It should safely clean up and validate the filename before checking its extension.



## 6 — Cryptographic Failures 
Cryptographic failures occur when an application uses weak or inappropriate cryptographic methods to protect sensitive information. For example, using a fast, unsalted hash such as MD5 for passwords makes it easier for an attacker to recover passwords if the hashes are exposed.

### Finding 09 — Weak Password Hashing Using MD5
* **Severity:** Medium
* **Category:** Cryptographic Failures — Weak Password Hashing
* **Affected Component:** User Authentication and Password Storage
* **Affected Endpoint:** Password hashing function in `lib/insecurity.ts` and its use in `models/user.ts`
* **Testing Approach:** White-box

#### Observation
While reviewing the application's backend code, I found that the website uses the **MD5** algorithm to scramble (hash) user passwords before saving them to the database. 

MD5 is an old, general-purpose mathematical formula meant for checking file integrity, not for locking up secrets. It runs way too fast, which makes it an unsafe choice for protecting passwords.

#### Hypothesis
If an attacker manages to break into the database and steal the stored password hashes, the use of MD5 will make it very easy for them to reverse-engineer those hashes and steal the users' actual plaintext passwords using offline guessing tools.

#### Validation
I checked the application's source code files and confirmed the weakness directly in the logic:

- In `lib/insecurity.ts`, I found the exact function that tells Node.js to use `'md5'` to process text.
- In `models/user.ts`, I verified that this weak MD5 function is actively triggered whenever a user creates an account or changes their password.

Because the code itself explicitly shows MD5 being used, the vulnerability is fully confirmed. I did not need to crack an actual user's password to prove the system is structurally weak.

#### Impact
MD5 is fast to calculate and does not provide the password-specific protections offered by modern password-hashing algorithms. If an attacker obtains the stored password hashes, they can attempt to guess passwords offline and compare the resulting MD5 hashes.

This could expose users to account compromise, particularly if they use weak or reused passwords. The practical impact depends on whether an attacker can obtain the hashes and how resistant the passwords are to guessing.

#### Result
**Confirmed — The application uses an outdated and weak algorithm (MD5) for password security.** 

#### Evidence
Below is a look into the backend code exposing the weak configuration:

**The Insecure Hashing Function:**
<details>
<summary>📋 <b>Click to view the MD5 implementation code found in lib/insecurity.ts</b></summary>

```typescript
// This line takes the string data and processes it using the weak MD5 algorithm
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

</details>

**How the User Model Saves It:**
<details>
<summary>📋 <b>Click to view how the application applies the hash in models/user.ts</b></summary>

```typescript
// The application intercepts the plain password and runs it through the weak security.hash function
password: {
  type: DataTypes.STRING,
  set (clearTextPassword: string) {
    this.setDataValue('password', security.hash(clearTextPassword))
  }
},
```

</details>

#### Remediation
- Replace MD5 with a modern, slow, password-specific algorithm like **bcrypt**, **scrypt**, or **Argon2id**. These are designed to be intentionally slow to stop high-speed computer guessing attacks.
- Ensure the new library automatically adds a "salt" (a random string of extra characters) to each password before hashing it. This ensures that even if two users have the exact same password, their hashes will look completely different in the database.
- Force a safe password migration. The next time a user successfully logs in, grab their password, hash it using the new secure method, and overwrite the old MD5 hash.



## 7 — Improper JWT Validation
JSON Web Token (JWT) is a compact token used to transmit information between parties. Web applications commonly use JWTs to identify authenticated users and carry claims about them. A JWT can be digitally signed to help verify that its contents have not been modified.

### Finding 10 — Unsigned JWT Accepted (JWT None Algorithm Bypass)
* **Severity:** High
* **Category:** Improper Authentication / JWT Validation Failure
* **Affected Component:** JWT Authentication
* **Affected Endpoint:** Authentication-protected API endpoints
* **Testing Approach:** Black-box

#### Observation
During testing, I investigated how the application validates JSON Web Tokens (JWTs). I found that the application accepted a modified token that used the none (`"alg": "none"`) signing algorithm, which indicates that the token was not cryptographically signed.

#### Hypothesis
JSON Web Tokens use a cryptographic signature (like a wax seal on a letter) to prove they haven't been messed with. I guessed that if the website accepts tokens using the `none` algorithm, it means the server isn't enforcing that signature. If true, an attacker could change their user information inside the token to impersonate any user on the system without needing the server's secret key.

#### Validation
I modified a JWT in the lab environment by changing its header to use the none algorithm and adjusting its payload. I removed the signature, leaving just the header and payload dots. 

The server accepted the unsigned token without throwing an error and successfully triggered the Juice Shop challenge-success alert for the **JWT None Algorithm** challenge.

#### Impact
This is a high-severity issue because it completely breaks the website's security doors. If a web application trusts an unsigned token, an attacker can modify their token payload data—such as changing a user ID number or changing a role parameter from `"role": "customer"` to `"role": "admin"`. 

Because the server fails to double-check the signature, the attacker can instantly log into anyone else's account or gain full administrative controls over the entire platform.

#### Result
**Confirmed — The application fails to properly validate JWT signatures and accepts the insecure `none` algorithm.**

#### Evidence
The following evidence demonstrates that the application accepted an unsigned JWT during testing.

<details>
<summary>📸 <b>The JWT header was modified to use the none algorithm, and the email claim was changed to jwtn3d@juice-sh.op. The signature was removed, leaving an unsigned token.</b></summary>

<img width="1100" height="449" alt="usignedJWT1" src="https://github.com/user-attachments/assets/bd1f0bea-a31a-4dc8-8828-6b99a12028bc" />

</details>

**Challenge Success Confirmation:**
<details>
<summary>📸 <b>After submitting the modified token during testing, OWASP Juice Shop displayed the challenge-success notification and marked the Unsigned JWT challenge as solved.</b></summary>

<img width="1625" height="297" alt="unsignedJWT" src="https://github.com/user-attachments/assets/8f1317e2-e855-4f3e-bf3d-cde348a47d9f" />

</details>

#### Remediation
- Configure the application to reject unsigned JWTs. If a token specifies "alg": "none", the application must reject it rather than treating it as authenticated.
- Configure the JWT library to accept only the expected signing algorithm, such as RS256 or HS256, according to the application's design. Verify each token's signature using the appropriate key.

### Finding 11 — Forged Signed JWT (JWT algorithm confusion bypass) 
* **Severity:** High
* **Category:** Improper Authentication / Cryptographic Signature Bypass
* **Affected Component:** JWT Authentication
* **Affected Endpoint:** Authentication-protected API endpoints
* **Testing Approach:** White-box 

#### Observation
I wanted to push myself on this finding because, at first sight, it seemed very complicated and out of my reach. I decided to study how the underlying code works rather than relying on automated tools. 

During my enumeration, I discovered a publicly accessible directory on the server containing the website's public cryptographic RSA key file at `/encryptionkeys/jwt.pub`. I wanted to see what would happen if I changed the token's algorithm to HS256 and used this discovered key file to sign a fake token.

#### Hypothesis
According to documentation from **PortSwigger Web Security Academy** and **WorkOS**, this weakness is known as **Algorithm Confusion**. 

The application normally uses RS256, which signs tokens with a private key and verifies them with a public key. However, if the application also accepts HS256 unexpectedly, it may treat the public key as a secret password for checking an HMAC signature.

Because the public key is available to anyone, this could allow an attacker to create a token that passes signature verification without knowing the private key. I investigated whether this behavior was possible in the lab.

#### Validation
I took what I learned from reading PortSwigger and WorkOS and used a simple Python script template instead. I reviewed the script's main components, including how the token was assembled and how the signature was generated using the public key. I then used the resulting token during testing in Burp Suite.

OWASP Juice Shop displayed the challenge-success notification, confirming that the forged token was accepted in the tested challenge.

This exercise helped me understand how JWT algorithm confusion can occur and why applications must strictly validate token signatures and permitted signing methods.

<details>
<summary>🛠️ <b>View Code</b></summary>

```python
import base64
import hmac
import hashlib
import json
 
# Standard header specifying the algorithm confusion attack
header = {"alg": "HS256", "typ": "JWT"}
 
# Payload using the exact data format Juice Shop expects
payload = {
    "data": {
        "email": "rsa_lord@juice-sh.op"
    }
} 
 
# Base64url encoding helper function
def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data)
    return encoded.decode('utf-8').rstrip('=')
 
# The full public key 
public_key_bytes = b"""-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM3CosR73CBNcJsLv5E90NsFt6qN1uziQ484gbOoule8leXHFbyIzPQRozgEpSpiwhr6d2/c0CfZHEJ3m5tV0klxfjfM7oqjRMURnH/rmBjcETQ7qzIISZQ/iptJ3p7Gi78X5ZMhLNtDkUFU9WaGdiEb+SnC39wjErmJSfmGb7i1AgMBAAE=
-----END RSA PUBLIC KEY-----"""
 
# Pack and encode without extra spaces to match backend serialization
header_encoded = base64url_encode(json.dumps(header).encode('utf-8'))
payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
signing_input = f"{header_encoded}.{payload_encoded}".encode('utf-8')
 
# Cryptographically sign via HMAC-SHA256 using the key block as a symmetric password
signature = hmac.new(public_key_bytes, signing_input, hashlib.sha256).digest()
signature_encoded = base64url_encode(signature)
 
# Generate final token
forged_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
print(forged_token)
```

</details>

##### How the Script Works (Line-by-Line Breakdown)
These are the standard JSON data objects used when creating a JWT.

```python
header = {"alg": "HS256", "typ": "JWT"}

payload = {
    "data": {
        "email": "rsa_lord@juice-sh.op"
    }
}
```

**Encode the data using Base64URL**
This function converts the data into a text format that can be used in a JWT. 

```python
def base64url_encode(data):
    encoded = base64.urlsafe_b64encode(data)
    return encoded.decode('utf-8').rstrip('=')
```

**Load the Public RSA Key**
The script uses the application's RSA public key as the secret when creating the signature. This tests whether the application incorrectly accepts a token created using an unexpected signing method.

```python
public_key_bytes = b"""-----BEGIN RSA PUBLIC KEY-----
...
-----END RSA PUBLIC KEY-----"""
```

**Prepare the Header and Payload**
The script converts the header and payload into JSON text, then encodes them using the function above. The separators=(',', ':') setting removes unnecessary spaces from the payload. Finally, the encoded header and payload are joined with a dot to prepare them for signing.

```python
header_encoded = base64url_encode(json.dumps(header).encode('utf-8'))
payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
signing_input = f"{header_encoded}.{payload_encoded}".encode('utf-8')
```

**Create the signature**
The script uses Python's built-in hmac function and SHA-256 to create a signature. It uses the public RSA key as the secret for this calculation, testing whether the application incorrectly handles the difference between signing methods.

```python
signature = hmac.new(public_key_bytes, signing_input, hashlib.sha256).digest()
signature_encoded = base64url_encode(signature)
```

**Assemble the final JWT**
The final step joins the encoded header, encoded payload, and signature with dots to form the three-part JWT structure.

```python
forged_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
```

#### Impact
This vulnerability could allow an attacker to create forged JWTs without knowing the server's private signing key. If the application accepts these tokens for authentication, an attacker may be able to impersonate users or gain unauthorized access.

#### Result
**Confirmed — The forged signed JWT challenge accepted a token signed using HS256 with the application's public RSA key as the secret. This demonstrates an algorithm-validation weakness in the tested flow.**

#### Evidence
The following evidence shows the public RSA key used during my investigation and the successful completion of the Forged Signed JWT challenge.

<details>
<summary>📸 <b>Public RSA key retrieved from /encryptionkeys/jwt.pub</b></summary>

<img width="1766" height="166" alt="publicrsa" src="https://github.com/user-attachments/assets/39d9b413-6402-4ff5-8a36-72accf9b6e07" />

</details>

**Challenge Success Confirmation:**

<details>
<summary>📸 <b>OWASP Juice Shop confirms successful completion of the Forged Signed JWT challenge.</b></summary>

<img width="1652" height="877" alt="forged signed jwt" src="https://github.com/user-attachments/assets/b9196afc-a3be-4832-91ad-06627eb1406e" />

</details>

#### Remediation
- Configure JWT verification to accept only the expected algorithm, such as RS256. Reject tokens that use unexpected algorithms, including HS256 or none.
- Verify RS256 signatures using the trusted RSA public key. Never use that public key as an HMAC secret.




































































































































