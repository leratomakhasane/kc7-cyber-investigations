# CASE 02 - A Scandal in Valdoria: A Political Mystery
**Platform:** KC7 Cyber

**Date:** 08 March 2025

**Tools:** KQL, Azure Data Explorer, PowerShell analysis

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

The Valdorian Times newspaper published a fake, scandalous article accusing candidate Luffy of corruption, and it went out under the Editorial Intern's name. The attackers used a phishing campaign targeting staff, starting with Senior Editor Sonia Gose. When she clicked a malicious link, a PowerShell script ran that established an external tunnel using Plink. They then moved laterally to the Editorial Intern Ronnie McLovin's machine, dropped a fake document, renamed it to look like the real final draft, and emailed it to the printer. The attackers also stole data, compressing Ronnie's files into password-protected archives and exfiltrating them to a custom upload portal. This investigation showed me how phishing → PowerShell → C2 → lateral movement → data theft works in a real-world attack chain.
<br><br>

## Investigation Overview

**Who was affected?** Sonia Gose, Senior Editor, then Ronnie McLovin, Editorial Intern - both at The Valdorian Times.

**What happened?** Both received "job offer" emails containing malicious Word documents. When opened, macros executed PowerShell backdoors that established remote command-and-control tunnels. The attacker moved between machines, planted a falsified news article, and exfiltrated three password-protected archives of sensitive data.

**When did it happen?** Sonia compromised January 5. Ronnie compromised January 10. The fake article was published and data exfiltrated January 31.

**Where did it happen?** Sonia's workstation `UL0M-MACHINE` → Ronnie's workstation `A37A-DESKTOP`. C2 servers at `136.130.190.181` and `168.57.191.100`. Exfiltration via `hirejob.com`.

**How did they do it?** The malicious documents ran `hacktivist_manifesto.ps1` which established persistence via scheduled tasks and opened reverse SSH tunnels using Plink. The attacker downloaded a fake news story, renamed it to match the expected filename, and emailed it to the newsroom printer. Stolen files were archived and uploaded to an external domain.

**Why was it possible?** Macros were enabled by default. No restrictions blocked outbound SSH connections. PowerShell script execution was not monitored. No data loss prevention rules flagged large file uploads to unknown external domains.
<br><br>

## Investigation Timeline & Findings

| # | What I Looked For | KQL / Method | What I Found | Timestamp |
| --- | --- | --- | --- | --- |
| 1 | Who sent the fake article email? | `Email \| where recipient == "clark_kent@valdoriantimes.news" \| where subject contains "Final OpEd"` | Appeared from `ronnie_mclovin@valdoriantimes.news` - but Ronnie denies sending it | 2024-01-31 11:11:12Z |
| 2 | Suspicious email to Sonia Gose | `Email \| where recipient == "sonia_gose@valdoriantimes.news" \| where sender == "newspaper_jobs@gmail.com"` | Link: `https://promotionrecruit.com/published/Valdorian_Times_Editorial_Offer_Letter.docx` | 2024-01-05 09:42:05Z |
| 3 | Did Sonia click it? | `OutboundNetworkEvents \| where src_ip == "10.10.0.3" \| where url has "promotionrecruit.com"` | Yes — clicked at 2024-01-05 10:23:17Z | 2024-01-05 10:23:17Z |
| 4 | Malicious file downloaded | `FileCreationEvents \| where hostname == "UL0M-MACHINE" \| where filename == "Valdorian_Times_Editorial_Offer_Letter.docx"` | SHA256: `60b854332e393a6a2f0015383969c3ac705126a6b7829b762057a3994967a61f` | 2024-01-05 10:24:04Z |
| 5 | PowerShell script dropped | `FileCreationEvents \| where hostname == "UL0M-MACHINE" \| where filename has ".ps1"` | `hacktivist_manifesto.ps1` - created 1 min later | 2024-01-05 10:24:32Z |
| 6 | What the script does | ProcessEvents + script analysis | Creates scheduled task → runs every 5 mins → invokes Plink for reverse tunnel | — |
| 7 | C2 Connection established | `ProcessEvents \| where hostname == "UL0M-MACHINE" \| where process_commandline has "plink"` | IP: `136.130.190.181` — Username: `$had0w` — Password: `thruthW!llS3tUfree` | Post-script execution |
| 8 | Discovery commands run | Count whoami, ipconfig, hostname, etc. | 5 discovery commands - attacker mapping the machine | Jan 5 |
| 9 | Second phishing email to Ronnie | `Email \| where sender == "valdorias_best_recruiter@gmail.com" \| where recipient == "ronnie_mclovin@valdoriantimes.news"` | Subject: `[EXTERNAL] Breaking News: We're Hiring!` - Link: `promotionrecruit.org/share/Editorial_J0b_Openings_2024.docx` | 2024-01-10 08:48:16Z |
| 10 | Ronnie clicked the link | `OutboundNetworkEvents \| where src_ip == "10.10.0.19" \| where url has "Editorial_J0b_Openings"` | Yes - 2024-01-10 08:55:07Z | 2024-01-10 08:55:07Z |
| 11 | Plink on Ronnie's machine | `ProcessEvents \| where username == "romclovin" \| where process_commandline has "plink"` | IP: `168.57.191.100` - Same creds: `$had0w` / `thruthW!llS3tUfree` | Post-click |
| 12 | Fake story file downloaded | `OutboundNetworkEvents \| where src_ip == "10.10.0.19" \| where url has "fakestory.docx"` | `https://hire-recruit.org/files/fakescandal/2024/fakestory.docx` | 2024-01-31 ~09:47 |
| 13 | File renamed & planted | `ProcessEvents \| where hostname == "A37A-DESKTOP" \| where process_commandline has "fakestory.docx"` | Renamed to `OpEdFinal_to_print.docx` - moved to Documents folder                                                         | 2024-01-31 10:26:20Z    |
| 14 | Fake article emailed | `Email \| where sender == "ronnie_mclovin@valdoriantimes.news" \| where recipient == "clark_kent@valdoriantimes.news"` | Subject: `URGENT: Final OpEd Draft Edits` - sent 44 mins after file was planted | 2024-01-31 11:11:12Z |
| 15 | Data exfiltration - stolen files | `ProcessEvents \| where process_commandline has ".7z" or "curl"` | 3 password-protected archives → uploaded to `hirejob.com/exfil_processor/upload.php` | ~2024-01-31 10:30–11:00 |
<br><br>


## Full Attack Chain & MITRE ATT&CK Mapping

| Phase | What Happened |
| --- | --- |
| **Recon & Prep** | Attacker set up infrastructure - `promotionrecruit.com`, `promotionrecruit.org`, `hire-recruit.org`, `hirejob.com` - all themed around "jobs/hiring" to lure victims |
| **Initial Access - Phishing (Sonia)** | Email from `newspaper_jobs@gmail.com` - "Editorial Offer Letter" - Sonia clicked → downloaded `.docx` with embedded macro |
| **Execution - PowerShell Drop** | Doc ran → dropped `hacktivist_manifesto.ps1` - established persistence via scheduled task |
| **Command & Control - Reverse Tunnel** | PowerShell invoked Plink → outbound SSH tunnel to `136.130.190.181` - attacker had full interactive access |
| **Lateral Movement - Target Ronnie** | Used Sonia's access to gather intel → sent second phish to Ronnie from `valdorias_best_recruiter@gmail.com` |
| **Second Compromise - Ronnie** | Clicked → same PowerShell → Plink tunnel to `168.57.191.100` - full control of her machine |
| **Payload Delivery - Fake Article** | Downloaded `fakestory.docx` from `hire-recruit.org` → renamed to `OpEdFinal_to_print.docx` to look legitimate |
| **Unauthorised Publication** | Emailed the fake file to Clark Kent from Ronnie's account - printer received it as "final draft" → published |
| **Data Exfiltration** | Zipped Ronnie's Documents, Desktop, and memes into 3 password-protected archives → uploaded all to `hirejob.com` via curl |
<br>


### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | How It Appeared Here |
| --- | --- | --- | --- |
| **Reconnaissance** | T1589.001 | Gather Victim Org Info | Researched roles - Editorial Director, Intern, Printer - crafted targeted emails |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | "Job offer" doc - convincing, role-relevant lure |
| **Execution** | T1204.002 | Malicious File | Opened .docx → macro/PowerShell executed |
| **Persistence** | T1053.005 | Scheduled Task | schtasks /create - hourly execution - survives reboots |
| **Command & Control** | T1071.004 | Application Layer Protocol - SSH/Tunnel | Plink → reverse SSH tunnel - encrypted, outbound, looks like normal traffic |
| **Discovery** | T1087 / T1046 | Account Discovery + Network Scanning | whoami, ipconfig, hostname - 5 discovery commands total |
| **Lateral Movement** | T1021.001 | Remote Services - SSH/Tunnel | Moved from Sonia → Ronnie via second phish + same toolset |
| **Persistence** | T1098 | Additional Cloud Service - Email Rules | Used Ronnie's email to send forged document |
| **Collection** | T1005 | Data from Local System | Collected files from Documents, Desktop, other folders |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | 7zip archives → curl POST to [hirejob.com](https://hirejob.com "autolink") - encrypted + password protected |
| **Impact** | T1491.001 | Defacement - Internal Site|Fake article published - reputational + political impact |
<br><br>



## Indicators of Compromise

| Type | Indicator |
| --- | --- |
| Sender Email | `newspaper_jobs@gmail.com` - Phishing (Sonia) |
| Sender Email | `valdorias_best_recruiter@gmail.com` - Phishing (Ronnie) |
| Domain | `promotionrecruit.com` - Phishing domain |
| Domain | `promotionrecruit.org` - Phishing domain |
| Domain | `hire-recruit.org` - Payload hosting |
| Domain | `hirejob.com` - Exfiltration server |
| IP Address | `136.130.190.181` - C2 (Sonia's machine) |
| IP Address | `168.57.191.100` - C2 (Ronnie's machine) |
| File Hash | `60b854332e393a6a2f0015383969c3ac705126a6b7829b762057a3994967a61f` - malicious docx |
| File | `hacktivist_manifesto.ps1` - PowerShell backdoor |
| File | `fakestory.docx` → renamed to `OpEdFinal_to_print.docx` - fake article |
| File | `DankMemes.7z`, `MyStolenDataFromDocuments.7z`, `MyStolenDataFromDesktop.7z` - exfil archives |
| Credentials (attacker) | Username: `$had0w` - Password: `thruthW!llS3tUfree` |
| URL | `https://hirejob.com/exfil_processor/upload.php` - exfil endpoint |
<br><br>


## Root Cause Analysis

- **No macro blocking.** Word docs ran PowerShell scripts freely - macros should be disabled by default, especially from external sources.
- **No outbound filtering.** Plink created SSH tunnels to external IPs - this is unusual for a newspaper and should've been blocked or alerted.
- **Email impersonation not detected.** The email "from Ronnie" went out with no verification or alert.
- **Same password for everything.** Attacker used the same credentials across both machines - `$had0w / thruthW!llS3tUfree` - no credential uniqueness.
- **No file upload restrictions.** Employees can download and run arbitrary .exe/.ps1 files - no endpoint protection blocking Plink or PowerShell.
- **Insider threat detection missing.** Someone sending an email "from you" that you didn't send - should trigger an alert.
<br><br>


## Impact Assessment

- **Fake news published** - reached thousands before corrected - political influence, reputational damage to the paper
- **2 machines fully compromised** - Senior Editor + Editorial Intern - high-value targets
- **Data stolen and exfiltrated** - 3 password-protected archives - sensitive docs, internal files, personal data
- **Persistence established** - scheduled task runs hourly - attacker could come back anytime
- **Financial + reputational cost** - retractions, loss of trust, potential legal action from the politician
- **Election influence** - timed right before voting - potentially swayed public opinion
<br><br>

## Recommendations & Remediations

| Priority | Action | Why It Helps |
| --- | --- | --- |
| Critical | Block macros from external files - default to disabled | Stops the PowerShell drop - breaks the whole chain at Step 1 |
| Critical | Restrict outbound SSH or Plink - alert on tunnels | Reverse tunnels are rare for normal business - easy to detect |
| High | Implement email authentication - SPF/DKIM/DMARC | Prevents sending emails "from" your own domain without permission |
| High | Alert on scheduled task creation + PowerShell execution | Both are red flags - especially together from Office docs |
| High | Block/alert on .exe/.ps1 downloads from untrusted domains | Stops the tools from being downloaded in the first place |
| Medium | Verify "urgent" file requests - especially from senior staff | The "URGENT" subject line is a classic attacker tactic |
| Medium | Data Loss Prevention - alert on .zip/.7z + upload to unknown domains | 3 archives + curl to random site = clear exfil pattern |
<br><br>


## Conclusion & What I Learned

This case showed me how a single phishing email can snowball into a full breach - from one click → PowerShell → reverse tunnel → second victim → fake news → data theft. What really stood out was how the attackers used legitimate tools - PowerShell, Plink, 7zip, curl - nothing "malicious" on its own, but together they were deadly. That's why defense isn't just about blocking "bad files" - it's about spotting **suspicious behaviour**. And the scariest part? They didn't just steal data - they changed reality. They published a lie that people believed. That's the real power of these attacks - and why we defend.
<br><br>


## Evidence & Queries

### Evidence Screenshots - Complete List 
| # | File Name | What It Shows | 
| --- | --- | --- |
| 01 | `01-initial-phishing-email-to-sonia.png` | The original recruitment-themed phishing email sent to Sonia Gose |
| 02 | `02-sonia-clicked-phishing-link.png` | Evidence confirming the link was accessed and the victim interacted with the lure |
| 03 | `03-malicious-document-downloaded.png` | The malicious Word document saved locally — macros enabled |
| 04 | `04-powershell-script-and-scheduled-task.png` | PowerShell payload execution + scheduled task for persistence |
| 05 | `05-plink-reverse-tunnel-command.png` | Plink.exe command establishing outbound SSH tunnel to C2 server |
| 06 | `06-fake-story-file-placed.png` | The falsified article file renamed and staged on the victim's desktop |
| 07 | `07-fake-article-email-record.png` | Email log showing the fake story sent to the newsroom/printer distribution list |
| 08 | `08-data-archive-activity.png` | File creation logs showing archive files being built and exfiltrated |


- **All screenshots stored in:** [`evidence/screenshots/`](./evidence/screenshots/)
- **Full KQL queries:** [`evidence/kql-queries.txt`](./evidence/kql-queries.txt)
- **IOCs list:** [`IOCs.md`](./IOCs.md)

