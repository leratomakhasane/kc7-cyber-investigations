# Security Analyst Level I - KC7 Cyber Investigations

**Status:** ✅ 4 Fully Documented | 6 Total Level I Modules Completed
**Date Completed:** 25 May 2026
**Badge:** [`View Badge →`](./assets/badges/KC7_SA1.png) · [Verify Link](https://kc7cyber.com/badges/earned/63064)


This folder contains my portfolio from the **KC7 Cyber Security Analyst Level I** path. Below are the **4 investigations selected for full documentation**, chosen to demonstrate a diverse range of attack types, skills, and investigation workflows. The remaining 2 modules are foundational learning exercises that reinforce these skills.

---

## Selection Rationale - Why These 4 Cases?
Level I comprises **6 total modules**. I selected **these 4 for complete portfolio documentation** because each one demonstrates a **distinct attack category and core analyst skill set**, no unnecessary repetition, maximum coverage of what entry-level roles require:

| Fully Documented Case | Duration | Attack Type Demonstrated | Unique Skill Focus |
|---|---|---|---|
| **A Rap Beef: An Intro to Security Investigations** | ~1 hr | OSINT → Knowledge-Based Auth → Password Reset → Phishing Campaign | Public-data risk assessment, social engineering patterns, foundational investigation workflow |
| **A Scandal in Valdoria: A Political Mystery** | ~7 hrs | Spear Phishing → Macro Malware → PowerShell → C2 → Data Exfiltration | Endpoint log analysis, threat hunting, attribution tracing, DLP & exfiltration detection |
| **JoJo's Hospital: A Ransomware Investigation** | ~3 hrs | Malware Delivery → Lateral Movement → Network-Wide Encryption | Ransomware triage, impact scoping, backup/recovery gap analysis, incident containment |
| **CloutHaus: Social Media Leads to Compromise** | ~4 hrs | BEC / Spear Phishing → Credential Theft → Data Exfiltration | OSINT recon tracing, email forensics, forwarding rule detection, identity protection |

**The remaining 2 Level I modules** were completed as hands-on skill-building foundations, they teach essential tools and platform mechanics but do not introduce distinct incident types beyond what the cases above already demonstrate. Rather than duplicate overlapping content, I focused on producing **4 high-quality, complete investigations** that collectively cover the full Level I skill set.

*All 6 modules were completed; the 2 foundational modules are available to discuss upon request.*

---

## Fully Documented Portfolio Cases

### Case 01 - A Rap Beef: An Intro to Security Investigations

**Date Completed:** 27 February 2025
**Badge:** [`View Badge →`](./assets/badges/new_rap_beef_badge.png) · [Verify Link](https://kc7cyber.com/badges/earned/11842)
**Type:** OSINT → Security Question Abuse → Password Reset → Account Takeover
> Personal details revealed in public media are used to answer account recovery questions. The attacker resets the victim’s password, compromises their accounts, and launches a follow-up phishing campaign to steal further information.
>
> **Key Skills:** Foundational investigation workflow, publicly available information (PAI) risk, knowledge-based authentication weaknesses, password reset hardening.
>
> [`Case-01-A-Rap-Beef/`](./case01-rap-beef)

---

### Case 02 - A Scandal in Valdoria: A Political Mystery

**Date Completed:** 08 March 2025
**Badge:** [`View Badge →`](./assets/badges/valdoria-election.png) · [Verify Link](https://kc7cyber.com/badges/earned/12931)
**Type:** Spear Phishing → Malicious Macros → PowerShell → C2 Tunnels → Data Exfiltration
> A newspaper receives leaked material — but is it a hack, an insider, or something else? Two employees receive job-offer phishes that drop PowerShell backdoors, establishing remote command-and-control tunnels. You trace the attacker’s movement across multiple machines to uncover the full operation.
>
> **Key Skills:** Malicious Office document analysis, PowerShell threat hunting, reverse shell or C2 detection, file staging & exfiltration pattern identification.
>
> [`Case-02-A-Scandal-in-Valdoria/`](./case02-scandal-in-valdoria)


---

### Case 03 - JoJo's Hospital: A Ransomware Investigation

**Date Completed:** 01 April 2025
**Badge:** [`View Badge →`](./assets/badges/Jojo's_Badge.png) · [Verify Link](https://kc7cyber.com/badges/earned/14801)
**Type:** Malware Delivery → Lateral Movement → Mass File Encryption
> A healthcare facility is hit by ransomware. Starting from a malicious document, the attacker moves across the network, encrypts thousands of files, and deletes backups to prevent recovery. You scope the breach from initial access to full impact.
>
> **Key Skills:** Malware indicator identification, network-wide impact assessment, recovery gap analysis, endpoint & backup defence recommendations.
>
> [`Case-03-JoJos-Hospital/`](./case03-jojos-hospital)

---

### Case 04 - CloutHaus: Social Media Leads to Compromise

**Date Completed:** 16 March 2026
**Badge:** [`View Badge →`](./assets/badges/CH_Badge.png) · [Verify Link](https://kc7cyber.com/badges/earned/57392) 
**Type:** Spear Phishing → Credential Theft → Email Forwarding → Data Exfiltration
> A rising influencer is targeted through social media reconnaissance. The attacker uses a convincing brand collaboration email to harvest credentials, then maintains persistent access via email forwarding rules to steal sensitive documents.
>
> **Key Skills:** OSINT footprint analysis, email header & link forensics, unusual inbox rule detection, MFA & identity hardening.
>
> 📂 [`Case-04-CloutHaus/`](./case04-clouthaus-ofomiya)

---




## Additional Level I Modules - Completed Foundations
These 2 modules were fully completed as essential skill-building foundations. They focus on platform mechanics and tool fundamentals rather than distinct incident scenarios, so their concepts are integrated across the portfolio cases above:

| Module | Duration | Focus | How Skill Is Demonstrated | Badge |
|---|---|---|---| --- |
| **How to Play KC7** | ~1 hr | Platform orientation, investigation workflow | Applied consistently across all documented cases - standardised structure & evidence capture | |
| **VirusTotal Fundamentals** | ~3 hrs | IOC analysis, reputation scanning, threat intelligence | IOCs identified in every case are validated & ready for lookups; methodology applied throughout | [`View Badge →`](./assets/badges/Virustotal_badge.png) · [Verify Link](https://kc7cyber.com/badges/earned/63063) |

---

## Level I - Key Takeaways
- **Covered all core incident types** - phishing, BEC, ransomware, malware, credential abuse, data exfiltration
- **Built from foundations up** - workflow basics → tool skills → full end-to-end investigations
- **Documented to SOC standards** - 4W+1H framework, MITRE ATT&CK mapping, KQL detection queries, standalone IOCs
- **Practised prioritisation** - selected cases for diversity & depth rather than quantity
- **Ready to advance** - Level I foundations complete → moving to Level II advanced threats

---

**Next: Security Analyst Level II** 