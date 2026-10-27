# CASE 03 - JoJo's Hospital - LockByte Ransomware Attack
**Platform:** KC7 Cyber

**Date:** 01 April 2025

**Tools:** KQL, Azure Data Explorer, Log Analysis

**Difficulty:** Intermediate

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

JoJo's Hospital in Lexington got hit with a ransomware attack that happened in two stages. First someone clicked a fake ad for a chicken restaurant, downloaded a malicious file, and that gave attackers a way in. They moved around the network, stole patient records and other sensitive data, and eventually the LockByte ransomware group took over - encrypted thousands of files across the hospital and demanded $2 million to unlock them. They even said they backed up the backups so restoring wouldn't work. This was a full investigation tracing it from the very first click all the way through to the ransom note.
<br><br>


## Investigation Overview 

**Who was affected?** JoJo's Hospital - starting with Anthony Davis on `AMFB-MACHINE`, spreading to 321 hosts across the entire network. 
 
**What happened?** An employee opened a malicious Word document disguised as a promotional offer. The malware executed, established command-and-control, moved laterally across the network, encrypted 6,420 files with the `.encrypted` extension, and deleted backups to prevent recovery.
 
**When did it happen?** The phishing email arrived January 15. The infection began at 09:15 on January 16. Full network encryption ran from approximately 10:00 to 14:00 the same day. The ransom demand was posted shortly after. 
  
**Where did it happen?** Initial compromise on `AMFB-MACHINE` → spread across the hospital network. C2 communication to `93.238.22.122` on port 50050. Data exfiltration to `secure-health-access.com`. All department file shares were encrypted. 
  
**How did they do it?** The malicious `.docx` ran macros that executed PowerShell to download LockByte ransomware. A Cobalt Strike beacon established remote control. Shadow copies were deleted to remove restore points. The attacker moved via SMB and admin shares to hit every connected machine. 
  
**Why was it possible?** Macros were enabled by default. No network segmentation contained the spread. Endpoint detection did not block known ransomware. Backups were stored on the same network as the data - making them just as vulnerable.
<br><br>


## Investigation Timeline & Findings

| Step | What I Was Looking For | KQL / Method | What I Found | Timestamp |
| --- | --- | --- | --- | --- |
| 1 | How many files got encrypted? | `FileCreationEvents \| where filename endswith ".encrypted" \| count` | **6,420 files** - that's a lot | 2024-06-17 |
| 2 | How many different computers were hit? | `FileCreationEvents \| where filename endswith ".encrypted" \| distinct hostname \| count` | **321 unique hosts** - spread across the hospital | 2024-06-17 |
| 3 | Where was the ransom note left? | `FileCreationEvents \| where filename == "We_Have_Your_Data_Pay_Up.txt"` | On AMFB-MACHINE - SHA256: `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018`<br><br>Path: `C:\Users\andavis\Documents\...` | 2024-06-17 |
| 4 | Who owns that computer? | `Employees \| where hostname == "AMFB-MACHINE"` | **Anthony Davis** - employee at the hospital | — |
| 5 | What happened on Anthony's machine around that time? | `ProcessEvents \| where hostname == "AMFB-MACHINE" \| timestamp between (2024-06-17 .. 2024-06-18)` | 14 things ran - including `lockbyte_ransomer.exe` | 2024-06-17 |
| 6 | How did it spread to everyone else? | Looking at network share activity | Copied to `\\jojos-hospital.org` as `spread_ransomware.exe` - anyone opening that folder got infected | 2024-06-17 |
| 7 | What did they steal before encrypting? | File paths + zip archives | patient_data_1 → `\\jojos-hospital-server\important_data\patient_records`<br><br>patient_data_2 → `...\archive\patient-records`<br><br>patient_data_3 → `...\old-patient-data` | 2024-06-17 |
| 8 | Where did they send the stolen data? | Curl command in logs | Sent to **[secure-health-access.com](https://secure-health-access.com "autolink")** | 2024-06-17 |
| 9 | Where did the malware come from in the first place? | `OutboundNetworkEvents \| where url has "patient_data_exporter.exe"` | Downloaded from **[secure-health-access.com](https://secure-health-access.com "autolink")** @ `2024-06-17T14:22:29Z` | 2024-06-17T14:22:29Z |
| 10 | What other domains does this attacker use?           | `PassiveDns \| where domain == "secure-health-access.com"` | 2 IP addresses - found another domain: **[emr-help.net](https://emr-help.net "autolink")** | — |
| 11 | Were they snooping around the hospital site? | `InboundNetworkEvents \| where src_ip in ("attacker-IPs")` | 37 requests - searched patient records, security bypasses | Pre-May 20 |
| 12 | How did they get in originally? | Looking at web traffic for weird domains | Fake Raisin' Kane chicken ad - `raisinkanes.com` - 26 clicks, **24 different employees** fell for it | From May 1 onward |
| 13 | What did that fake site actually drop? | `FileCreationEvents` - downloaded files | `Raisin_Kane_Promo_Offer.docx` - SHA256: `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` - downloaded via Chrome @ `2024-05-01T09:56:50Z` | 2024-05-01T09:56:50Z |
| 14 | What happened after opening that doc? | `ProcessEvents` right after | `cobaltstrike.exe` ran - connected to **93.238.22.122:50050** - that's the attacker's command server | May 1 |
| 15 | How did they get to Anthony Davis' machine? | `AuthenticationEvents` + `ProcessEvents` | Logged in as Anthony Davis @ `2024-05-20T00:00:00Z` from IP `203.0.113.1` - his credentials were bought off the dark web | May 20 |
| 16 | Once inside - what did they do? | `ProcessEvents` - discovery commands | `systeminfo` ran 6 times, `advanced-ip-scanner.exe` mapped the whole network, stole `network_diagrams.pdf` and `credentials.txt` - zipped everything and sent it out | May–June |
| 17 | Cleanup - did they cover tracks? | Command-line logs | `cmd.exe /c del C:\Users\andavis\Documents\patientdata*.zip` - deleted local copies after sending | Post-exfiltration |
<br><br>


## Key Findings - Attack Chain & Evidence

### Key Findings

| Phase | What Happened |
| --- | --- |
| **Initial Access - Fake Ad** | Sponsored search result for "Raisin' Kane" chicken place - looked real, domain was `raisinkanes.com` (missing the 'g'). 24 employees clicked it. |
| **Payload Delivery** | Downloaded `Raisin_Kane_Promo_Offer.docx` - opened it, and out dropped `cobaltstrike.exe` - gives attackers remote control. |
| **Command & Control** | Connected to `93.238.22.122` on port 50050 - attacker now in the network. |
| **Recon & Lateral Movement** | Ran system commands, scanned the network, found Anthony Davis - bought his login from dark web - logged in as him. No MFA stopped them. |
| **Data Theft** | Ran `patient_data_exporter.exe` - grabbed 3 sets of patient records, network diagrams, credentials - zipped and sent to their own domains. |
| **Ransomware Deployment** | Brought in `lockbyte_ransomer.exe`, put it on a shared drive as `spread_ransomware.exe` - encrypted everything across 321 machines. |
| **Covering Tracks** | Deleted local zip files - but logs still showed what happened. |
| **Ransom Note** | $2,000,000 in Bitcoin - 72 hours - said backups are compromised too - don't call police or it all gets released. |
<br>


### MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | How It Appeared Here |
|---|---|---|---|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Link | Fake sponsored ad for "Raisin' Kane" - lookalike domain tricked employees |
| **User Execution** | T1204.002 | Malicious File | Opened .docx → executed embedded malware - Cobalt Strike |
| **Command & Control** | T1071.001 | Application Layer Protocol | Connected to 93.238.22.122:50050 - established C2 channel |
| **Discovery** | T1087.001 | Account Discovery - Local | Scanned network, enumerated users - found Anthony Davis |
| **Lateral Movement** | T1021.002 | Remote Services: SMB/Windows Admin Shares | Used stolen credentials to move laterally - no MFA to stop it |
| **Credential Access** | T1078 | Valid Accounts - Stolen Credentials | Purchased/bought credentials — fully legitimate access |
| **Collection** | T1005 | Data from Local System | Patient records, network maps, credentials collected |
| **Exfiltration** | T1048.003 | Exfiltration Over C2 Channel - Curl | Zipped files sent to secure-health-access.com |
| **Impact** | T1486 | Data Encrypted for Impact - LockByte | 6,420 files encrypted across 321 machines - .encrypted extension |
| **Impact** | T1490 | Inhibit System Recovery - Backups Deleted | Backups compromised — no easy restore path |
<br><br>



## Indicators of Compromise

| Type      | What It Is |
| --- | --- |
| Domain | `raisinkanes.com` - fake chicken ad phishing |
| Domain | `nothing-to-see-here.net` - redirect + exfiltration |
| Domain | `totally-legit-domain.com` - phishing redirect |
| Domain | `secure-health-access.com` - malware host + data exfiltration  |
| Domain | `emr-help.net` - more attacker infrastructure |
| File Hash | `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` - malicious docx |
| File Hash | `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018` - ransom note |
| File  | `cobaltstrike.exe` - remote control tool |
| File  | `patient_data_exporter.exe` - data theft tool |
| File  | `lockbyte_ransomer.exe` / `spread_ransomware.exe` - ransomware |
| IP:Port | `93.238.22.122:50050` - attacker C2 server |
| IP | `203.0.113.1` - where they logged in from as Anthony Davis |



## Root Cause & Impact Assessment

- **People clicked a fake ad.** That's the entry point. Social engineering still works way too well.
- **No MFA on accounts.** They had Anthony's password - done. MFA would've blocked it.
- **Network was flat.** Once one computer got infected, attackers could roam everywhere - no segmentation.
- **Backups weren't separate.** Attackers went after backups too - that's why the ransom was so effective.
- **Domain filtering missing.** Those obviously fake domains should've been blocked at the firewall.

**Impact:**

- 6,420 files encrypted - across 321 computers
- Patient records, SSNs, health info stolen - HIPAA nightmare
- $2 million ransom demand - 72 hours
- Backups compromised - can't just restore
- Hospital services disrupted - people's lives affected
- Reputation damage + regulatory trouble



## Recommendations & Remediations

| Priority | Fix | Why |
| --- | --- | --- |
| Critical | MFA everywhere - no exceptions | Stops account takeover even with stolen passwords |
| Critical | Offline, air-gapped backups - encrypted, immutable | Only real defense against ransomware that deletes backups |
| High | Network segmentation - separate patient, admin, backup systems | Breach stays small instead of spreading everywhere |
| High | Block lookalike domains + external email filtering | `raisinkanes.com` vs real - should never have reached staff |
| High | EDR / antivirus - block known malware like Cobalt Strike | Detect and kill the malware before it spreads |
| Medium | Security training - fake ads, phishing, red flags | 24 people clicked - education reduces that number |
| Medium | Password hygiene + monitor dark web for stolen creds | Anthony's password was for sale - should've been caught |
| Low | Threat hunt - watch for `.encrypted`, weird outbound curl | Early detection = less damage |
<br><br>



## Conclusion & What I Learned

This investigation showed me how layered a real attack can be. It wasn't just one thing - it was a chain: fake ad → click → malware → stolen credentials → spread → encrypt. And what hit me hardest: **the ransomware was actually the final step, not the first.** The attackers were inside for weeks, stealing data and mapping the network before anyone even noticed. Defense-in-depth isn't just a buzzword - it's the only way. If one thing fails - MFA, segmentation, backups - the whole building falls. This case really drove home how important the basics are.


## Evidence & Queries

### Evidence Screenshots - Complete List 

| # | File Name | What It Shows |
|---|---|---|
| 01 | `01-encrypted-file-events.png` | Logs showing files being renamed and encrypted on the network |
| 02 | `02-hosts-with-encrypted-files.png` | Scope of impact - number of hosts affected across the hospital |
| 03 | `03-ransom-note-file-record.png` | The ransom demand file left by the attacker on affected systems |
| 04 | `04-process-activity-on-affected-host.png` | Malware process execution on the initially compromised machine |
| 05 | `05-patient-data-exporter-network-event.png` | Outbound network traffic indicating data exfiltration in progress |
| 06 | `06-suspicious-infrastructure-passive-dns.png` | Passive DNS lookup identifying the attacker's C2 domain |
| 07 | `07-suspicious-bypass-request.png` | Requests attempting to bypass security controls to reach external servers |
| 08 | `08-patient-data-url-requests.png` | HTTP requests showing patient records being uploaded to external URLs | 


- **All screenshots stored in:** [`evidence/screenshots/`](./evidence/screenshots/)
- **Full KQL queries:** [`evidence/kql-queries.txt`](./evidence/kql-queries.txt)
- **IOCs list:** [`IOCs.md`](./IOCs.md)
