# mssql_epa_check

A tool to check the Extended Protection for Authentication (EPA) enforcement level on MSSQL servers.

No SQL login permissions required — only valid domain credentials are needed.

## Requirements

- Python 3.9+
- Impacket 0.12.0+

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Password authentication
python3 mssql_epa_check.py <target> -u <domain/username> -p <password>

# Hash authentication
python3 mssql_epa_check.py <target> -u <domain/username> -H <LMHASH:NTHASH>

# Custom port
python3 mssql_epa_check.py <target> -u <domain/username> -p <password> --port 1434
```

### Example

```bash
python3 mssql_epa_check.py 192.168.33.114 -u kanto.makkuro.local/alice -p 'P@ssword1'
```

## Sample Output

```
[*] Target: 192.168.33.114:1433
[*] User: kanto.makkuro.local\alice
[*] Force Encryption: No
[*] Prereq check: login_failed
[*] Testing Service Binding (SPN)...
[*]   Bogus SPN: untrusted_domain
[*]   Missing SPN: untrusted_domain

[+] Extended Protection: Required - SPN enforced, NTLM relay NOT possible (Secure)
```

## How It Works

### Step 1: TDS Encryption Check

Connects to the MSSQL server without authentication and checks the TDS PreLogin response for the Force Encryption setting. This determines whether CBT or SPN testing is used.

### Step 2: Prerequisite Check

Attempts login with correct parameters to verify that the supplied credentials are valid. Both `success` (has SQL login) and `login_failed` (no SQL login) are accepted as valid results, since EPA validation occurs at the NTLM level and does not require SQL login permissions.

### Step 3: EPA Testing

#### Force Encryption ON → Channel Binding Token (CBT) Test

1. Send a bogus CBT value
   - Accepted → EPA: **Off** (server does not validate CBT)
   - Rejected → Server validates CBT (Allowed or Required)
2. Send an empty CBT value (SPN remains correct)
   - Accepted → EPA: **Allowed** (server skips validation when CBT is absent)
   - Rejected → EPA: **Required** (server requires CBT)

When Force Encryption is ON, TLS is maintained for the entire session, so the server retains the `tls_unique` value and can validate CBT.

#### Force Encryption OFF → Service Principal Name (SPN) Test

1. Send a bogus SPN (`cifs` instead of `MSSQLSvc`)
   - Accepted → EPA: **Off** (server does not validate SPN)
   - Rejected → Server validates SPN (Allowed or Required)
2. Send with SPN removed from AV_PAIRS (CBT is automatically empty due to TLS teardown)
   - Accepted → EPA: **Allowed** (server skips validation when SPN is absent)
   - Rejected → EPA: **Required** (server requires SPN)

When Force Encryption is OFF, TLS is torn down after the login packet (TDS_LOGIN7) is sent, and the server discards the `tls_unique` value, making CBT validation impossible. Therefore, the tool tests SPN (MsvAvTargetName) instead, which does not depend on TLS.

## NTLM Relay Success Matrix

| # | NTLM Version | Force Encryption | Extended Protection | Result | Notes |
|---|---|---|---|---|---|
| 1 | NTLMv2 | Yes | Off | Success | EPA (CBT/SPN) not validated, relay possible |
| 2 | NTLMv2 | No | Off | Success | EPA (CBT/SPN) not validated, relay possible |
| 3 | NTLMv2 | Yes | Allowed | Fail | Victim's CBT (MsvAvChannelBindings) does not match the CBT computed from the server's TLS session |
| 4 | NTLMv2 | No | Allowed | Fail | TLS is torn down after login packet, server discards tls_unique so CBT validation is impossible. SPN (MsvAvTargetName) is validated and rejected due to mismatch |
| 5 | NTLMv2 | Yes | Required | Fail | Victim's CBT (MsvAvChannelBindings) does not match the CBT computed from the server's TLS session |
| 6 | NTLMv2 | No | Required | Fail | TLS is torn down after login packet, server discards tls_unique so CBT validation is impossible. SPN (MsvAvTargetName) is validated and rejected due to mismatch |
| 7 | NTLMv1 | Yes | Off | Success | EPA (CBT/SPN) not validated, relay possible |
| 8 | NTLMv1 | No | Off | Success | EPA (CBT/SPN) not validated, relay possible |
| 9 | NTLMv1 | Yes | Allowed | Success | NTLMv1 has no AV_PAIRS, so CBT/SPN are absent and validation is skipped |
| 10 | NTLMv1 | No | Allowed | Success | NTLMv1 has no AV_PAIRS, so CBT/SPN are absent and validation is skipped |
| 11 | NTLMv1 | Yes | Required | Fail | CBT/SPN are required but NTLMv1 cannot provide them |
| 12 | NTLMv1 | No | Required | Fail | CBT/SPN are required but NTLMv1 cannot provide them |

## References

- [RelayInformer](https://github.com/Tw1sm/RelayInformer) - EPA enforcement checker (logic reference for this tool)
