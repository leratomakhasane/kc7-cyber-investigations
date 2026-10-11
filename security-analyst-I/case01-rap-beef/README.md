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

