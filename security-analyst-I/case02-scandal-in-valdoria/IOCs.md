# IOCs — A Scandal in Valdoria

## Email Addresses
- `newspaper_jobs@gmail.com` - Initial phishing sender (Sonia)
- `valdorias_best_recruiter@gmail.com` - Second phishing sender (Ronnie)

## Domains
- `promotionrecruit.com` - Phishing domain (initial payload)
- `promotionrecruit.org` - Phishing domain (second payload)
- `hire-recruit.org` - Fake story file hosting
- `hirejob.com` - Data exfiltration server

## IP Addresses
- `136.130.190.181` - C2 server (Sonia's machine)
- `168.57.191.100` - C2 server (Ronnie's machine)

## File Hashes
- `60b854332e393a6a2f0015383969c3ac705126a6b7829b762057a3994967a61f` - Valdorian_Times_Editorial_Offer_Letter.docx (malicious)
- `5f8a7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f` - fakestory.docx

## Files
- `hacktivist_manifesto.ps1` - Malicious PowerShell script
- `fakestory.docx` → renamed to `OpEdFinal_to_print.docx` - Fake article
- `DankMemes.7z`, `MyStolenDataFromDocuments.7z`, `MyStolenDataFromDesktop.7z` - Exfiltration archives

## URLs
- `https://hirejob.com/exfil_processor/upload.php` - Exfiltration endpoint

## Attacker Credentials (observed)
- Username: `$had0w`
- Password: `thruthW!llS3tUfree`