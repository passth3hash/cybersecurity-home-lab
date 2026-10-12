# Security Findings 

Contains security findings identified and validated during testing of the isolated OWASP Juice Shop home lab.

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



## 2 — Sensitive Data Exposure 
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

























































