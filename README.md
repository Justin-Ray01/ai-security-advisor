# AI Security Advisor (C++)

An AI-style security analysis tool written in modern C++ that parses Linux authentication logs, evaluates suspicious activity, and generates risk-scored security reports in plain English.

---

## Features

- Detects SSH brute-force patterns
- Identifies top offending IP addresses
- Tracks targeted usernames
- Correlates failed logins followed by successful login
- Generates a 0–100 risk score
- Produces:
  - Structured findings output
  - Human-readable security advisory report

---


---

## Build

```bash
g++ -std=c++17 -O2 -Wall -Wextra -o ai_security_advisor src/main.cpp
./ai_security_advisor sample-logs/auth_sample.log --save
