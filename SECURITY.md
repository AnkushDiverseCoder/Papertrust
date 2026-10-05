# Security policy

Papertrust is security software, so reports are taken seriously and handled privately.

## Reporting a problem

Please **do not open a public issue** for a security problem. Instead use GitHub's private reporting:
**Security** tab of this repository → **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. You will get an answer within a week. Once a fix is released, you will be credited in the release notes if you wish.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: the signing service, the keystore, request authentication, the key chain and the verification helpers in this repository.

Out of scope: problems that need the shared secret or keystore password to exploit, instances exposed to the internet against the README's advice, and vulnerabilities in Node.js, Chromium or the operating system themselves (please report those upstream).
