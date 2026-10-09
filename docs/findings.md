# Security Findings 

Contains security findings identified and validated during testing of the isolated OWASP Juice Shop home lab.

Testing primarily followed a black-box approach, using application responses to investigate and validate suspected vulnerabilities. Source code analysis was used selectively where it provided additional context.

For testing I have used the following methodology: 

**Observation → Hypotheses → Validation → Impact → Result → Evidence**



## 1 - Broken Access Control 

Broken access control occurs when an application fails to enforce authorization correctly, allowing users to access resources or perform beyond their intended permissions.

### Finding 01 - Insecure Direct Object Reference (IDOR) - Basket access 

**Severity:** High 
**Category:** Broken Access Control 
**Affected component:** Shopping basket 
**Affected endpoint:** GET /rest/basket/{id} 
**Testing approach:** Black-box 

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

<img width="1277" height="770" alt="IDOR" src="https://github.com/user-attachments/assets/69260bd6-59a2-45ff-a38d-0788c50ee6dc" />


#### Remediation 

- Verify on the server that the requested basket belongs to the authenticated user.
- Apply authorization checks consistently to basket retrieval, modification and checkout operations. 



