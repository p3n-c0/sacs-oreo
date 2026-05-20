# Security Policy

SACS Oreo is intended for authorized web application security assessment only.

## Responsible Use

Only run Oreo against systems where you have explicit written authorization. Users are solely responsible for ensuring they have proper authorization before scanning any target. Unauthorized scanning may violate applicable laws and regulations.

## Safe-Testing Philosophy

Oreo is designed around minimally invasive assessment techniques intended to reduce operational risk to target systems.

Oreo prioritizes exposure analysis, misconfiguration detection, and evidence-based reporting over exploit automation. Its scan modes are intended to make testing intensity explicit: passive, safe, and controlled active testing. The project is not intended to become an exploit launcher.

Contributions that add credential attacks, brute force, exploit chaining, authentication bypass, denial-of-service behavior, destructive payloads, or auth-abuse workflows will not be accepted.

## Reporting Security Issues

If you discover a vulnerability in Oreo itself, please open a private report with the maintainers or contact SecureAfrica Cyber Solutions directly.

Please do not publicly disclose vulnerabilities in Oreo until maintainers have had reasonable time to investigate and remediate the issue.

When reporting, include:

- affected version or commit
- reproduction steps
- expected impact
- suggested remediation, if known
