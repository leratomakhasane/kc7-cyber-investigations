# CASE 04: CloutHaus - Afomiya Storm Phishing & Business Email Compromise

**Platform:** KC7 Cyber Investigations

**Date Completed:** 2026-03-16

**Tools Used:** Kusto Query Language (KQL), Azure Data Explorer, Log Analysis

**Difficulty:** Beginner → Intermediate

---

## Executive Summary

Afomiya Storm - an influencer partner at CloutHaus, got targeted through a pretty well put-together phishing scam. It started with an email pretending to be from Dior, tricked her into clicking a link and typing in her login details. Even though MFA saved her account at first, the attacker used OSINT stuff, answers to her security questions she accidentally shared on Instagram, to reset her password anyway. Once in, they set up email forwarding, stole her payment info, passport, bank statements, and sent all of it off to their own domain. This was a full Business Email Compromise (BEC) case from start to finish.

<br><br>

## Investigation Overview

**Who was affected?** <br>
Afomiya Storm - Influencer & Marketing Lead at CloutHaus 
 
**What happened?** <br>
Received a "brand collaboration" phishing email → clicked link → entered credentials on fake login page → attacker took over her account → created email forwarding rule → exfiltrated sensitive documents (bank info, passport, contracts)
 
**When did it happen?** <br>
April 10, 2024 - Phishing email sent → April 12 - Link clicked, credentials stolen → April 13–15 - Attacker active, data exfiltrated 
  
**Where did it happen?** <br>
Primary target: `afomiya_storm@clouthaus.com` → Email portal → Login from suspicious IP `182.45.67.89` (Jinan, China) → Forwarding rule set to `noreply@influencer-deals.net`
  
**How did they do it?** <br>
The threat actor sent a convincing "collaboration offer" email from `collabs@dior-partners.com`, and the link went to `super-brand-offer.com` (fake login page). Where the victim entered the password, there was no MFA enabled, and the attacker logged in. The attacker created an auto-forward rule, and all sensitive data is sent externally 
  
**Why was it possible?** <br>
The victim had no multi-factor authentication on email, the email security didn't flag external domains. No alerts on forwarding rule creation, and the user couldn't spot the lookalike domain

<br><br>

## Investigation Timeline & Findings

| Step | What I Was Looking For | KQL / Method | What I Found| Timestamp |
| --- | --- | --- | --- | --- |
| 1 | Afomiya's official CloutHaus email | `Employees \| where name contains "afomiya"` | `afomiya_storm@clouthaus.com` - username: afstorm, role: Influencer Partner | — |
| 2 | Her MFA status - was it on? | `Employees \| where name contains "afomiya" \| distinct mfa_enabled` | **MFA was DISABLED on her corporate account** - false | — |
| 3 | The suspicious email claiming to be Dior | `Email \| where recipient == "afomiya_storm@clouthaus.com" \| where subject contains "Partnership"` | Sender: `collabs@dior-partners.com`<br><br>Subject: `[EXTERNAL] Exclusive Partnership Opportunity with Dior` | — |
| 4 | The link inside the email | Pulled from email logs | `https://super-brand-offer.com/login` - fake login page | — |
| 5 | When she clicked the link | `OutboundNetworkEvents \| where url contains "super-brand-offer.com"` | `2025-04-03T11:20:00Z` | 2025-04-03T11:20:00Z |
| 6 | What IP was behind that fake site? | `PassiveDns \| where domain contains "super-brand-offer.com"` | `198.51.100.12` | — |
| 7 | What else lives on that IP? | `PassiveDns \| where ip == "198.51.100.12" \| distinct domain` | **3 domains total** - including `influencer-deals.net` and `dior-partners.com` | — |
| 8 | The actual account compromise - where did they log in from? | `AuthenticationEvents` - flagged unusual login | IP: `182.45.67.89` — Jinan, Shandong, China<br><br>Browser: Internet Explorer 5.0 - super old, definitely suspicious | ~1 hour after click |
| 9 | What other domains linked to that attacker IP? | `PassiveDns \| where ip == "182.45.67.89"` | `influencer-deals.net` and `dior-partners.com` - both fake brands | — |
| 10 | How did they get past her password? Security questions! | Authentication log review | Used answers from her Instagram Q&A: **Lalibela** and **Kidus** — both publicly shared | — |
| 11 | What saved her email from being taken over _at first_? | MFA status check on personal vs corporate | **Multi-Factor Authentication (MFA)** — the code sent to her phone. Even with the right answers, they couldn't get in without it. | — |
| 12 | Once they got in — where did they forward her emails? | `EmailForwardingRules` / `InboundNetworkEvents` | `noreply@influencer-deals.net` — everything sent there automatically | Post-compromise |
| 13 | What exactly did they steal? | `Email \| where sender == "afomiya_storm@clouthaus.com"` — forwarded items | Payment details form → `[EXTERNAL] [FORWARD] Afomiya's payment details – direct deposit form`<br><br>Passport scan → `[EXTERNAL] [FORWARD] Afomiya's passport scan – confidential`<br><br>Bank statement → `[EXTERNAL] [FORWARD] Re: Re: Re: Afomiya's bank statement – confidential` | Post-compromise |
| 14 | What else were they digging for? Recon | `InboundNetworkEvents \| where src_ip == "182.45.67.89"` | Her home address (via reverse image search of apartment view), Venmo/payment info, fake birthday party invite as a lure | Pre-compromise |



## Full Attack Chain & MITRE ATT&CK Mapping

### Full Attack Chain

| Phase | What Happened |
| --- | --- |
| **Initial Access - Phishing** | Email looked real, came from `collabs@dior-partners.com` - not Dior's actual domain. Subject line said "Exclusive Partnership Opportunity." |
| **Credential Harvesting** | Link went to `super-brand-offer.com/login` - fake login page that looked legit. She typed in her username `afstorm` and password - they caught them. |
| **Recon via Social Media** | Attacker used her public Instagram: email address, answers to security questions (Lalibela, Kidus), even her home address from apartment photos. Classic OSINT. |
| **Bypassing Protections** | Her personal email had MFA - that stopped them at first. But they used security question answers to reset things. Her _corporate account_ didn't even have MFA turned on - that was the big one. |
| **Account Takeover** | Logged in from China — `182.45.67.89` - using an ancient browser that no one actually uses. Should've triggered an alert but didn't. |
| **Persistence - Forwarding Rules** | Set emails to auto-forward to `noreply@influencer-deals.net`. Runs silently - they don't need to log back in. |
| **Data Exfiltration** | Grabbed her payment info, passport, bank statement - all forwarded out. Identity theft ready to go. |

### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | How It Appeared Here |
| --- | --- | --- | --- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Link | Brand deal email - personalised link to fake login page |
| **Reconnaissance** | T1585.001 | Gather Victim Personal Info: Social Media | Security question answers found on Instagram Q&A |
| **Credential Access** | T1555 | Credentials from Password Stores | Fake login page harvested her password |
| **Credential Access** | T1098.003 | Additional Email Delegate Permissions | Forwarding rule created - persistent access |
| **Persistence** | T1078.003 | Valid Accounts — Local Account | Used her real credentials - fully compromised account |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Sensitive docs forwarded to attacker domain |
| **Defense Evasion** | T1071.001 | Application Layer Protocol: Web Protocols | Used legitimate-looking email to bypass filters |

<br><br>

## Indicators Of Compromise

| Type | Indicator |
| --- | --- |
| Sender Email | `collabs@dior-partners.com` - NOT real Dior |
| Domain | `super-brand-offer.com` - phishing login page |
| Domain | `dior-partners.com` - fake brand domain |
| Domain | `influencer-deals.net` - attacker infrastructure/exfiltration |
| IP Address | `198.51.100.12` - phishing site host |
| IP Address | `182.45.67.89` - actual login from Jinan, China |
| Forwarding Address | `noreply@influencer-deals.net` - where her mail went |
| Suspicious UA | `MSIE 5.0; Windows NT 5.2` - extremely outdated browser |

<br><br>

## Root Cause Analysis

- **MFA was disabled on her corporate account.** This is the biggest one. If it was on, even with stolen credentials they get nothing.
- **Security questions are weak.** Answers were all over her social media. They're basically public info once someone researches you.
- **No domain checks.** Email came from `dior-partners.com` instead of `dior.com` - should've been flagged or obvious.
- **Oversharing on social media.** Q&A sessions, photos, personal details - attackers use this.

<br><br>

## Impact Assessment

- Credentials stolen - personal and corporate
- Email fully compromised - attacker could read, send, forward anything
- Sensitive personal data gone: passport, bank info, payment details - identity theft risk
- Auto-forwarding means they still get everything - ongoing access
- Reputational damage if they send emails from her account

<br><br>

## Recommendations & Remediations

| Priority | Fix | Why |
| --- | --- | --- |
| Critical | Turn on MFA everywhere - personal AND corporate | Stops 99% of these attacks instantly |
| Critical | Replace security questions with something else | Answers are too easy to find online |
| High | Train on spotting lookalike domains - `dior.com` vs `dior-partners.com` | Real brands use their real domain |
| High | Audit email forwarding rules - any external address gets flagged | Attacker relies on this staying hidden |
| Medium | Be careful what you share publicly - even "harmless" Q&As | It's all data to an attacker |
| Medium | Alert on impossible travel / weird browser / foreign IPs | That login from China in IE should've been blocked |

<br><br>

## Conclusion & What I Learned

This case showed me how dangerous a simple phishing email + social media recon can be. The attacker didn't need fancy malware — they just needed one person to click, some public info, and a system without MFA. What stuck with me most: **it's not always about super-hackers. Sometimes it's just doing the basics right - MFA, checking domains, being careful what you post - and that stops most of it.**

<br><br>

## Evidence & Queries

## Evidence Screenshots - Complete List
| # | File Name | What It Shows |
| --- | --- | --- |
| 01 | `01-corporate-mfa-status.png` | MFA configuration - showing it was disabled on the affected account |
| 02 | `02-dior-impersonation-email.png` | The convincing brand-impersonation phishing email sent to Afomiya |
| 03 | `03-phishing-link-visit.png` | Evidence the victim clicked the link and accessed the fake login page |
| 04 | `04-phishing-domain-passive-dns.png` | Passive DNS showing the phishing domain was recently registered |
| 05  | `05-related-domains-on-phishing-ip.png` | Multiple malicious domains hosted on the same attacker IP address |
| 06  | `06-suspicious-authentication-event.png` | Unauthorised login event from a suspicious/foreign IP location |
| 07  | `07-post-compromise-recon-urls.png` | URLs visited by the attacker after gaining access - recon and data collection |

- **All screenshots stored in:** [`evidence/screenshots/`](./evidence/screenshots/)

- **Full KQL queries:** [`evidence/kql-queries.txt`](./evidence/kql-queries.txt)

- **IOCs list:** [`IOCs.md`](./IOCs.md)
