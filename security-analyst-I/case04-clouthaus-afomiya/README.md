# CASE 04 - CloutHaus: Afomiya Storm Phishing & Business Email Compromise
**Platform:** KC7 Cyber

**Date:** 16 May 2026

**Tools:** KQL, Azure Data Explorer, Log Analysis

**Difficulty:** Beginner - Intermediate

---

## Table of Contents
- [Executive Summary](#executive-summary)
- [Investigation Overview](#investigation-overview)
- [Investigation Timeline & Findings](#investigation-timeline--findings)
- [Full Attack Chain & MITRE ATT&CK Mapping](#full-attack-chain--mitre-attck-mapping)
- [Indicators of Compromise](#indicators-of-compromise)
- [Root Cause Analysis](#root-cause-analysis)
- [Impact Assessment](#impact-assessment)
- [Recommendations & Remediations](#recommendations--remediations)
- [Conclusion & What I Learned](#conclusion--what-i-learned)
- [Evidence & KQL Findings](#evidence--kql-findings)
<br><br>

## Executive Summary

Afomiya Storm an influencer partner at CloutHaus, got targeted through a pretty well put-together phishing scam. It started with an email pretending to be from Dior, tricked her into clicking a link and typing in her login details. Even though MFA saved her account at first, the attacker used OSINT stuff, answers to her security questions she accidentally shared on Instagram, to reset her password anyway. Once in, they set up email forwarding, stole her payment info, passport, bank statements, and sent all of it off to their own domain. This was a full Business Email Compromise (BEC) case from start to finish.