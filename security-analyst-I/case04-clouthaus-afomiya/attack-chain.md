# Attack Chain — CloutHaus

## Phase 1: Recon & Preparation
- Attacker identified Afomiya Storm via public channels
- Gathered email, role, and security question answers from Instagram
- Registered fake domains: dior-partners.com, super-brand-offer.com
- Set up phishing page mimicking a login portal

## Phase 2: Initial Access - Phishing
- Sent personalised email from collabs@dior-partners.com
- Subject: "Exclusive Partnership Opportunity with Dior"
- Victim clicked link → landed on fake login page
- Credentials captured: username afstorm + password

## Phase 3: Bypass & Account Takeover
- Personal email had MFA - blocked initial access
- Used security question answers (Lalibela, Kidus) to reset corporate account password
- Corporate account had **no MFA** - full access granted
- Logged in from 182.45.67.89 (Jinan, China) via suspicious browser

## Phase 4: Persistence
- Created email forwarding rule → noreply@influencer-deals.net
- All incoming mail copied externally - ongoing, silent access

## Phase 5: Data Exfiltration
- Forwarded payment deposit form
- Forwarded passport scan
- Forwarded bank statements
- Identity theft complete - all sensitive data exfiltrated