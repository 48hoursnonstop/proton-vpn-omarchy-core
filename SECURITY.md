# Security

Please report security issues privately through GitHub's **Report a
vulnerability** flow instead of opening a public issue. Do not include Proton
credentials, session tokens, VPN configuration secrets, or diagnostic logs
containing personal data in public reports.

Install release packages only through the signature-verifying guided installer
or verify them manually with `RELEASE-SIGNING-KEY.asc`. The expected primary
fingerprint is:

```text
4D01 24DE 0978 8D29 E3A8 798B 12BE 3422 BDA2 422C
```

The latest repository security review and its explicit residual limitations
are recorded in `reference/SECURITY_AUDIT_2026-08-28.md`.
