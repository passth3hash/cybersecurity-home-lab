# Security Findings 

Contains security findings identified and validated during testing of the isolated OWASP Juice Shop home lab.

For testing I have used the following methodology: 

**Observation → Hypotheses → Validation → Impact → Result → Evidence**



## Finding 01 - SQL Injection Authentication Bypass

**Severity: Critical**
**Category: Injection/SQL Injection**
**Affected endpoint: POST /rest/user/login**

### Observation 

Normal authentication requests rejected an invalid password:

POST /rest/user/login
Content-Type: application/json

{
  "email": "basil@juice-shop.op",
  "password": "admin"
}

The application returned: 

HTTP/1.1 401 Unauthorized

A single quote added to the email parameter caused the application to return an HTTP 500 reponse containing a SQLite error. This indicated that user-controlled input was reaching a SQL query without proper parameterization. 

### Hypothesis 

The login endpoint may be vulnerable to SQL injection because the supplied email value appears to be concatenated into the authentication query. 

### Validation 

A SQL injection payload was submitted in the email field while using a random password: 

{
  "email": "basil@juice-shop.op' OR '1'='1' --",
  "password": "test"
}

### Impact 

An unauthenticated user can manipulate the login query and bypass the authentication. 
The successful exploitation resulted in authentication as an administrative user without knowing the legitimate password. 

### Result 

**Confirmed - exploitable SQL injection with authentication bypass** 

The successful authentication bypass demonstrated that user-controlled input was being interpreted as part of the backend SQL query. No source-code analysis was required to establish exploitability.


Each finding follows: 

- Observation
- Hypothesis
- Validation
- Impact
- Evidence
- Remediation
