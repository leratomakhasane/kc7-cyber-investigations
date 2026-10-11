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



**## Executive Summary**

Dwake, a rapper signed to OWL Records, got into a public feud with another artist, Present. In his diss track, Dwake accidentally revealed personal information, his mom's maiden name `Washington` and his childhood pet `Fluffy`. Present's label, Dollar Currency Records, hired a hacker who used this information to answer Dwake's security questions, reset his password, and take over his account.The attackers then launched a phishing campaign targeting OWL Records staff, tricked Dwake into clicking a link, stole his credentials, and eventually exfiltrated a zip file named `DwakesDirtySecrets.zip`. This case showed me how social engineering and over sharing personal information can lead to a full account compromise.

---

## Investigation Overview


## Investigation Timeline & Findings
| #   | What I Looked For                        | KQL / Method                                                                                                                                              | What I Found                                                                                                                     | Timestamp            |
| --- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| 1   | Who is the CEO of OWL Records?           | `Employees \| where role == "CEO"`                                                                                                                        | Sean Crater                                                                                                                      | —                    |
| 2   | Was someone probing OWL Records website? | `InboundNetworkEvents \| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00")) \| where src_ip has "18.66.52.227"` | 19 requests from suspicious IP — attacker recon                                                                                  | 2024-04-10 → 11      |
| 3   | What info were they searching for?       | Review URL paths in logs                                                                                                                                  | Email address — specifically looking for Dwake's contact                                                                         | —                    |
| 4   | What is Dwake's email address?           | Parse URL paths from logs                                                                                                                                 | `dwake_audrey@owl-records.com`                                                                                                   | —                    |
| 5   | Did they try password reset?             | Look for `reset-password` in URLs                                                                                                                         | Yes — accessed password reset page                                                                                               | —                    |
| 6   | What personal info did Dwake reveal?     | Analyse song lyrics                                                                                                                                       | Mom's maiden name = Washington; Childhood pet = Fluffy                                                                           | —                    |
| 7   | Did they use those answers to reset?     | `InboundNetworkEvents \| where url has_any("washington", "fluffy") \| where src_ip has "18.66.52.227"`                                                    | Full URL showing security questions answered — password reset successful                                                         | ~2024-04-11          |
| 8   | What domain is linked to attacker IP?    | `PassiveDns \| where ip == "18.66.52.227"`                                                                                                                | `betterlyrics4u.com` — phishing domain                                                                                           | —                    |
| 9   | Were phishing emails sent?               | `Email \| where link has "betterlyrics4u.com"`                                                                                                            | 13 emails sent — 2 sender addresses: `ghostwritersanonymous@protonmail.com` & `wemakebeatz@gmail.com`                            | —                    |
| 10  | Who was targeted most?                   | Join Email + Employees tables                                                                                                                             | Role = Rapper — specifically Dwake Audrey (Lead Rapper)                                                                          | —                    |
| 11  | What phishing email did Dwake receive?   | Filter emails to Dwake's address                                                                                                                          | Subject: `[EXTERNAL] RE: Need a ghostwriter for your next hit?` — Link: `http://betterlyrics4u.com/share/online/published/enter` | —                    |
| 12  | Did Dwake click the link?                | `OutboundNetworkEvents \| where url == "http://betterlyrics4u.com/share/online/published/enter" \| where src_ip == "10.10.0.5"`                           | Yes — clicked at 2024-04-15T12:03:12Z                                                                                            | 2024-04-15T12:03:12Z |
| 13  | Did attackers log in with stolen creds?  | `AuthenticationEvents \| where username == "dwaudrey" \| where src_ip == "18.66.52.227"`                                                                  | Successful Login — 2024-04-15T13:03:12Z                                                                                          | 2024-04-15T13:03:12Z |
| 14  | What did they do after login?            | `InboundNetworkEvents \| where url has "dwaudrey" \| where src_ip has "18.66.52.227"`                                                                     | 10 requests — searching through his email                                                                                        | Apr 12–May 1         |
| 15  | What did they steal?                     | Review file attachments / downloads                                                                                                                       | `DwakesDirtySecrets.zip` — sensitive data exfiltrated                                                                            | Post-compromise      |

## Full Attack Chain & MITRE ATT&CK Mapping


## Indicators Of Compromise


## Root Cause Analysis


## Impact Assessment


## Recommendations & Remediations


## Conclusion & What I Learned


## Evidence & Queries
