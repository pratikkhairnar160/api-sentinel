# Security Policy

## Responsible Use

APISentinel is a security assessment tool designed exclusively for **authorized penetration
testing** and **internal security audits**. Before using this tool against any system:

- Obtain **explicit written authorization** from the system owner
- Define a clear **scope** that includes only systems you are permitted to test
- Follow your organization's security testing policy and applicable laws

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active  |

## Reporting a Vulnerability in APISentinel

If you discover a security vulnerability in APISentinel itself (e.g., a bypass that
allows destructive API calls, data exfiltration, or privilege escalation):

1. **Do not** open a public GitHub issue
2. Email the maintainers at: `security@your-org.com`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

We will acknowledge receipt within **48 hours** and aim to release a patch within **7 days**
for critical issues.

## Safe Validation Design

All key validators in `src/validator/services/` are explicitly designed to be
non-destructive. The safety constraints are:

| Service   | Probe Used                        | Why Safe                              |
|-----------|-----------------------------------|---------------------------------------|
| AWS       | `STS:GetCallerIdentity`           | Identity-only, no resource access     |
| Google    | Geocode a public landmark         | Read-only, minimal cost               |
| Stripe    | Retrieve non-existent intent      | 404 = valid, 401 = invalid, no charge |
| GitHub    | `GET /user`                       | Read-only profile endpoint            |
| Slack     | `auth.test`                       | Returns auth status only              |
| SendGrid  | `GET /v3/scopes`                  | Lists permissions, no send action     |
| DB URIs   | Skipped entirely                  | Never probe database connections      |
| Passwords | Skipped entirely                  | Never probe hardcoded passwords       |

**These constraints must be maintained in all contributions.**

## Legal Notice

Unauthorized use of this tool against systems you do not own or have permission to test
may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK),
and equivalent laws in other jurisdictions.
