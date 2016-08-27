# Tic Tac Toe Squared Server

A server to handle authorization for marktai.com

This is written in Go

### Tech Stack:
 *  MySQL database to store user info
 *  Go server to interface with database and respond to requests
 *  NGINX server to reverse proxy (so separate apps are separate processes)

## API

Auth Headers = {""}

    URL | Paramaters | Return Value on Success
    --- | ---------- | -----------------------
    POST /login | body of {"User", "Password", "StayLoggedIn" (optional)} | {"Secret": string, "UserID": int, "Expiration": UTC RFC3339 date}
    POST /logout | Auth Headers (see below) | 200 code
    POST /verifySecret | body of {"User", "Secret"} | {"Secret": string, "UserID": int, "Expiration": UTC RFC3339 date}
    POST /users | body of {"User", "Password", "Email", "Recaptcha"} | {"UserID": int}
    GET /users/{userID}/register | query of code={Registration Code} | redirects to https://www.marktai.com/meta-tic-tac-toe/
    GET /users/{userID}/registered | Auth Headers (see below) | {"Registered": bool}
    POST /changePassword | {"User", "Password", "NewPassword"} | 200 code
    POST /authHeaders | Auth Headers (see below) | 200 code


### Auth Headers 
    Header | Value
    ------ | --------
    UserID | ID of user to authenticate
    Path | path of endpoint requested
    HMAC | encoded HMAC with SHA 256
    Encoding | encoding format for HMAC (if not provided, defaults to hex) 
    Time-Sent | seconds since epoch (fails if more than 10 seconds away from time received)

    The HMAC uses (seconds in epoch):(path including initial / and without the T9) as the message and the login secret (in base 64 parsed as a string) as a secret.

####Example:

I want to logout for user 54689, which is at https://www.marktai.com/T9/auth/logout

* UserID = 54689
* Secret = "3ar+0wLwgiltTXNZ/eprJ2NaWE7y5k+0r9ThN4+im8RHWH8ksB1xw4554hOTNF8H9rguMBfUaNRWztNQb+nz7A=="
* Path = "/logout"
* Time-Sent = 1472276742

This results in "1472276742:/logout" as the message, and the secret is "3ar+0wLwgiltTXNZ/eprJ2NaWE7y5k+0r9ThN4+im8RHWH8ksB1xw4554hOTNF8H9rguMBfUaNRWztNQb+nz7A=="

Therefore, the HMAC is "69aee4c4d9749a6e27c583af898840927975ea861b9d74dc54ef2e3cde14b7c4", verifiable at http://www.freeformatter.com/hmac-generator.html
