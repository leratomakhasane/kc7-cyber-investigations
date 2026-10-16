# CASE 01 - A Rap Beef: An Intro to Security Investigations
**Platform:** KC7 Cyber

**Date:** 27 February 2025

**Tools:** KQL, Azure Data Explorer

**Difficulty:** Beginner

---

## Table of Contents
- [Executive Summary](#-executive-summary)
- [Investigation Overview](#-investigation-overview)
- [Investigation Timeline & Findings](#-investigation-timeline--findings)
- [Full Attack Chain & MITRE ATT&CK Mapping](#-full-attack-chain--mitre-attack-mapping)
- [Idicators Of Compromise](#-indicators-of-compromise)
- [Root Cause Analysis](#-root-cause-analysis)
- [Impact Assessment](#-impact-assessment)
- [Recommendations & Remediations](#-recommendations--remediations)
- [Conclusion & What I learned](#-conclusion--what-i-learned)
- [Evidence & KQL Findings](#-evidence--kql-findings)
<br><br>

## Executive Summary

Dwake, a rapper signed to OWL Records, got into a public feud with another artist, Present. In his diss track, Dwake accidentally revealed personal information, his mom's maiden name, `Washington` and his childhood pet, `Fluffy`. Present's label, Dollar Currency Records, hired a hacker who used this information to answer Dwake's security questions, reset his password, and take over his account. The attackers then launched a phishing campaign targeting OWL Records staff, tricked Dwake into clicking a link, stole his credentials, and eventually exfiltrated a zip file named `DwakesDirtySecrets.zip`. This case showed me how social engineering and oversharing personal information can lead to a full account compromise.
<br><br>

## Investigation Overview

**Who was affected?** Dwake Audrey - Lead Rapper at OWL Records.
**What happened?** Personal details revealed publicly in song lyrics were used to answer account security questions. The attacker reset the password, took over the email and social media accounts, then sent phishing messages to contacts. Sensitive information was gathered and archieved as `DwakesDiarySecrets.zip` before exfiltration.
**When did it happen?** Reconnaissance tracked back to April 10 from IP `18.66.52.227`. The password was reset April 11. The phishing campaign and data theft followed on April 15.
**Where did it happen?** OWL Records password reset portal - `dwake_audrey@owl-records.com` - linked instagram account - phishing domain - `betterlyrics4u.com`
**How did they do it?** Lyrics revealed the mother's maiden name `Washington` and the first pet's name `Fluffy`, the exact answers to the account recovery questions. The attacker used these to reset the password and bypass login entirely. Once inside, they sent phishing kinkss to Dwake's contacts and harvested private data.
**Why was it possible?** Security questions relied on publicly guessable information. No multi-factor authentication was required for password resets. No alerts were triggered for password changes from unknown locations.
<br><br>

## Investigation Timeline & Findings

| #   | What I Looked For                        | KQL / Method                                                                                                                                              | What I Found                                                                                                                     | Timestamp            |
| --- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| 1   | Who is the CEO of OWL Records?           | `Employees \| where role == "CEO"`                                                                                                                        | Sean Crater                                                                                                                      | —                    |
| 2   | Was someone probing OWL Records website? | `InboundNetworkEvents \| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00")) \| where src_ip has "18.66.52.227"` | 19 requests from suspicious IP - attacker recon                                                                                  | 2024-04-10 → 11      |
| 3   | What info were they searching for?       | Review URL paths in logs                                                                                                                                  | Email address - specifically looking for Dwake's contact                                                                         | —                    |
| 4   | What is Dwake's email address?           | Parse URL paths from logs                                                                                                                                 | `dwake_audrey@owl-records.com`                                                                                                   | —                    |
| 5   | Did they try password reset?             | Look for `reset-password` in URLs                                                                                                                         | Yes - accessed password reset page                                                                                               | —                    |
| 6   | What personal info did Dwake reveal?     | Analyse song lyrics                                                                                                                                       | Mom's maiden name = Washington; Childhood pet = Fluffy                                                                           | —                    |
| 7   | Did they use those answers to reset?     | `InboundNetworkEvents \| where url has_any("washington", "fluffy") \| where src_ip has "18.66.52.227"`                                                    | Full URL showing security questions answered - password reset successful                                                         | ~2024-04-11          |
| 8   | What domain is linked to attacker IP?    | `PassiveDns \| where ip == "18.66.52.227"`                                                                                                                | `betterlyrics4u.com` - phishing domain                                                                                           | —                    |
| 9   | Were phishing emails sent?               | `Email \| where link has "betterlyrics4u.com"`                                                                                                            | 13 emails sent - 2 sender addresses: `ghostwritersanonymous@protonmail.com` & `wemakebeatz@gmail.com`                            | -                    |
| 10  | Who was targeted most?                   | Join Email + Employees tables                                                                                                                             | Role = Rapper - specifically Dwake Audrey (Lead Rapper)                                                                          | -                    |
| 11  | What phishing email did Dwake receive?   | Filter emails to Dwake's address                                                                                                                          | Subject: `[EXTERNAL] RE: Need a ghostwriter for your next hit?` - Link: `http://betterlyrics4u.com/share/online/published/enter` | -                    |
| 12  | Did Dwake click the link?                | `OutboundNetworkEvents \| where url == "http://betterlyrics4u.com/share/online/published/enter" \| where src_ip == "10.10.0.5"`                           | Yes - clicked at 2024-04-15T12:03:12Z                                                                                            | 2024-04-15T12:03:12Z |
| 13  | Did attackers log in with stolen creds?  | `AuthenticationEvents \| where username == "dwaudrey" \| where src_ip == "18.66.52.227"`                                                                  | Successful Login - 2024-04-15T13:03:12Z                                                                                          | 2024-04-15T13:03:12Z |
| 14  | What did they do after login?            | `InboundNetworkEvents \| where url has "dwaudrey" \| where src_ip has "18.66.52.227"`                                                                     | 10 requests - searching through his email                                                                                        | Apr 12–May 1         |
| 15  | What did they steal?                     | Review file attachments / downloads                                                                                                                       | `DwakesDirtySecrets.zip` - sensitive data exfiltrated                                                                            | Post-compromise      |
<br><br>

## Full Attack Chain & MITRE ATT&CK Mapping

| Phase                                    | What Happened                                                                                                                 |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Reconnaissance - Public Info**         | Dwake's song lyrics revealed mother's maiden name ("Washington") and childhood pet ("Fluffy") - publicly available to anyone  |
| **Initial Access - Password Reset**      | Attacker used those exact answers on the security questions page → successfully reset Dwake's password &#8594; full account access  |
| **Phishing Campaign - Secondary Vector** | Registered `betterlyrics4u.com`, sent convincing "ghostwriter" emails to OWL Records staff - 13 emails total from 2 addresses |
| **Credential Harvesting**                | Dwake clicked the link &#8594; entered his credentials on the fake login page &#8594; attacker captured them                              |
| **Account Takeover**                     | Attacker logged in from IP 18.66.52.227 - successful authentication                                                           |
| **Data Collection**                      | Searched through Dwake's email - 10 requests looking for sensitive info                                                       |
| **Exfiltration**                         | Zipped up compromising material &#8594; `DwakesDirtySecrets.zip` — stolen and ready for retaliation                                 |
| **Impact**                               | Embarrassing post on his Instagram; threat against Present from the dark web - feud escalated beyond music                        |
<br><br>

### MITRE ATT&CK Mapping

| Tactic                | Technique ID | Technique Name                                    | How It Appeared Here                                 |
| --------------------- | ------------ | ------------------------------------------------- | ---------------------------------------------------- |
| **Reconnaissance**    | T1591.001    | Gather Victim Identity Info                       | Song lyrics revealed mother's maiden name & pet name |
| **Credential Access** | T1555.003    | Credentials from Password Stores - Password Reset | Security questions answered &#8594; password reset         |
| **Initial Access**    | T1566.001    | Phishing: Spearphishing Link                      | "Ghostwriter" email with fake login page link        |
| **User Execution**    | T1204.001    | Malicious Link                                    | Dwake clicked &#8594; entered credentials                  |
| **Credential Access** | T1145        | Credential Dumping                                | Captured login credentials on fake page              |
| **Lateral Movement**  | T1078.003    | Valid Accounts - Local Account                    | Used stolen creds → logged into Dwake's account      |
| **Collection**        | T1005        | Data from Local System                            | Searched email for sensitive/scandalous info         |
| **Exfiltration**      | T1041        | Exfiltration Over C2 Channel                      | Zipped data &#8594; `DwakesDirtySecrets.zip` - exfiltrated |
| **Impact**            | T1531        | Account Access Removal / Defacement               | Unauthorised Instagram post - reputational damage    |
<br><br>

## Indicators Of Compromise

| Type         | Indicator                                                                      |
| ------------ | ------------------------------------------------------------------------------ |
| IP Address   | `18.66.52.227` - Attacker recon, password reset, login                         |
| Domain       | `betterlyrics4u.com` - Phishing domain                                         |
| Sender Email | `ghostwritersanonymous@protonmail.com` - Phishing sender                       |
| Sender Email | `wemakebeatz@gmail.com` - Second phishing sender                               |
| URL          | `http://betterlyrics4u.com/share/online/published/enter` - Phishing login page |
| File         | `DwakesDirtySecrets.zip` - Exfiltrated data archive                            |
| Username     | `dwaudrey` - Compromised account                                               |
<br><br>

## Root Cause Analysis

- **Security questions = weak authentication.** The answers were literally in a song, publicly available. Any information that can be Googled or social engineered is **NOT** security.
- **No MFA on the account.** Password reset = full access. No second factor to stop it.
- **Oversharing personal information.** Even "harmless" personal details are security questions. Once public, they're useless as secrets.
- **Phishing email not detected.** The `ghostwriter` email was marked **CLEAN**, no alert, no filter, no warning.
- **Domain not flagged.** `betterlyrics4u.com` was suspicious but reached the inbox.
<br><br>

## Impact Assessment

- **Account fully compromised** - email, likely Instagram too
- **Reputational damage** - embarrassing post published from his account
- **Data stolen** - `DwakesDirtySecrets.zip`, material that can be used for blackmail or retaliation
- **Feud escalated** - physical or digital threat made agaisnt Present which created more problems
- **Company-wide risk** - 13 staff received the same phishing email, multiple potential entry points
<br><br>

## Recommendations & Remediations

| Priority | Action                                                          | Why It Helps                                                            |
| -------- | --------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Critical | Replace security questions with something private & unguessable | Answers should NOT be researchable or public info                       |
| Critical | Enable MFA on ALL accounts - no exceptions                      | Even with a password reset, they can't get in without the second factor |
| High     | Block newly registered or suspicious domains                    | `betterlyrics4u.com` should never have reached staff inboxes            |
| High     | Train on "context phishing" - emails that fit your role         | Ghostwriter offer = convincing to a rapper                              |
| Medium   | Warn users when links go to external domains                    | Visual warning when clicking non-company links                          |
| Medium   | Audit password reset logs - alert on question answers           | If someone answers security questions, send an alert immediately        |
<br><br>

## Conclusion & What I Learned

This case was a perfect example of how the simplest thing, something you say in public or post about in public, can become your biggest security weakness. Dwake didn't get hacked with fancy malware or zero-days. He got hacked because he told a story in a song. The attacker didn't need to break any encryption, they just listened. It really drove home that **security isn't just about technology. It's about what we share, what we use as secrets, and how we verify people.** MFA and good security questions would've stopped this whole thing before it even started.
<br><br>

## Evidence & Queries

- **Full KQL queries** : [`evidence/kql-queries.txt`](./evidence/kql-queries.txt)
- **Screenshots:** [`evidence/screenshots/`](./evidence/screenshots/)
- **IOCs list:** [`IOCs.md`](./IOCs.md)
