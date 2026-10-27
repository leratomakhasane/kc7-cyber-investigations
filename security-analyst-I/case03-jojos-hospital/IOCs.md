# IOCs - JoJo's Hospital: LockByte Ransomware

## IP Addresses
- `93.238.22.122` - C2 Server (Cobalt Strike beacon)
- `203.0.113.1` - Attacker login / lateral movement source
- `[secure-health-access.com IP]` - Data exfiltration server

## Domains
- `secure-health-access.com` - Exfiltration / C2 domain

## File Hashes — SHA256
- `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` - Raisin_Kane_Promo_Offer.docx (initial malware dropper)

## File Extensions
- `.encrypted` - LockByte encrypted file extension

## Malicious Files
- `Raisin_Kane_Promo_Offer.docx` - Initial phishing payload
- `lockbyte_ransomer.exe` - LockByte ransomware executable
- `spread_ransomware.exe` - Lateral movement / propagation tool
- `We_Have_Your_Data_Pay_Up.txt` - Ransom note
- `[random-name].encrypted` - All encrypted user files

## Network Indicators
- Port `50050` - Cobalt Strike C2 beacon port

## Compromised Hosts
- `AMFB-MACHINE` - Anthony Davis's workstation (initial breach point)
- 321 total hosts affected across the network

## Malicious Commands / Tools
- `cmd.exe /c del` - Shadow copy deletion / recovery inhibition
- `curl secure-health-access.com` - Data exfiltration
- SMB/Windows Admin Shares - Lateral movement vector

## Impact Scope
- 6,420 files encrypted
- 321 machines affected
- Backups deleted - no native recovery path