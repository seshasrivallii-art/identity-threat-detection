# Response Playbooks

Each playbook follows triage, then containment, then recovery. Severity comes from the alert.

## Impossible travel (T1078)

**Triage**
1. Check both locations against the user's history (dashboard "Known profile"). Is either a VPN, cloud provider, or known travel?
2. Compare device ID and user agent between the two logins. A new device in the far location raises confidence.
3. Look at what happened after the suspicious login: mailbox rule creation, file downloads, MFA method changes, OAuth consent grants.
4. Contact the user through a channel other than email (phone, Teams call) to confirm.

**Containment (if not confirmed as legitimate)**
- Revoke all sessions and refresh tokens (Entra: `Revoke-MgUserSignInSession`; Okta: clear user sessions).
- Force a password reset and require MFA re-registration.
- Block the source IP / ASN in conditional access.

**Recovery**: remove any inbox rules, app consents, or MFA methods the attacker added. Add the location to watchlists.

## MFA fatigue / push bombing (T1621)

A burst of pushes means the attacker **already has the password**. Treat it as credential compromise even if the user never approved.

**Triage**
1. Did any push get approved? If yes, the account is compromised: go straight to containment.
2. Where did the pushes originate (IP, country, ASN)? Does it match the user?
3. Ask the user whether they approved a prompt they didn't start.

**Containment**
- Reset the password immediately (this stops new pushes).
- If a push was approved: revoke sessions and tokens, review activity since approval.
- Temporarily block the source IP.

**Recovery / hardening**: enforce number matching and additional context in Microsoft Authenticator or Okta Verify, rate-limit pushes, and move high-risk users to phishing-resistant MFA (FIDO2 / passkeys).

## Session hijacking (T1539 / T1550.004)

A stolen cookie bypasses passwords **and** MFA, so a password reset alone does not end it.

**Triage**
1. Confirm the session ID shows different country, ASN, or user agent from where it was issued.
2. Check the user's machine for infostealer malware and recent phishing clicks (AiTM kits like Evilginx steal cookies).
3. Review actions taken with the hijacked session.

**Containment**
- Revoke sessions and refresh tokens **first**, then reset the password.
- Isolate the endpoint if malware is suspected.

**Recovery / hardening**: token protection / binding (Entra token protection, Okta device-bound sessions), shorter session lifetimes for sensitive apps, compliant-device conditional access, phishing-resistant MFA.
