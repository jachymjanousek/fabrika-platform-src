# Sign-in with an email code (joat fork)

Status: implemented in the joat fork (`joat/email-code-sign-in`), to propose upstream.
Date: 2026-11-24.

## Why

The joat installation used Cloudflare Access (One-time PIN) as its only OIDC provider. That has three problems
for SaaS applications whose users are clients, not staff:

1. **Seats.** Each email that authenticates through Access takes a Zero Trust seat. The Free plan has 50.
2. **Exposure.** To let clients in without whitelisting, the Access policy must admit everyone. Cloudflare's
   security scan flags this as an overprovisioned policy.
3. **Sign-out.** IAM ends its own login, but the Access session stays. The next sign-in goes through Access
   without a PIN (partly mitigated by `fix(iam): a logout behind cloudflare access ends the access session too`).

Passwords are no solution: clients forget them. The person must prove only that they own the mailbox.
IAM can do that itself, because it already sends mail.

## What

A third, independent authentication method beside OIDC and password: **`email_code`**.

| Switch       | Variable                                               |
| ------------ | ------------------------------------------------------ |
| runtime      | `EMAIL_CODE_ENABLED` (`true`/`false`, default `false`) |
| installation | `FABRIKA_IAM_EMAIL_CODE_ENABLED`                       |

- At least one of OIDC, password and email code must be enabled.
- Email code needs an email sender. `EMAIL_CODE_ENABLED=true` with `FABRIKA_EMAIL_PROVIDER=none` fails the boot.

## Flow

```
GET  /auth/login                → email form (handoff fields hidden)
POST /auth/code                 → throttle → maybe issue + mail a code → code form, Set-Cookie attempt
POST /auth/code/verify          → 5 guesses per code → session (method email_code) → handoff 302
```

1. **Request.** The person enters an address. IAM always answers the same code form, whatever the address,
   so the answer does not tell whether an account exists. IAM issues and mails a code only when:
   - a user principal holds the mailbox and is not disabled (internal or external), or
   - no principal holds it and the human-admission allowlist admits it (`HUMAN_EMAIL_DOMAINS` /
     `HUMAN_EMAILS`, `*` = anyone).
     The mail goes out in `waitUntil`, so the answer time does not depend on the outcome.
2. **Attempt binding.** The answer sets `__Host-fabrika_code` (random 32 bytes, `HttpOnly`, `Secure`,
   `SameSite=Strict`, 10 min). Only the browser that asked can use the code. A refused address gets a cookie too,
   with no row behind it.
3. **Code.** 6 decimal digits from a CSPRNG, valid 10 minutes, single use. The row stores
   `SHA-256(attempt ":" code)`. The attempt plaintext is never stored, so a leaked table does not let anyone
   try the 10⁶ codes offline.
4. **Verify.** One statement increments `failures` only while the row is open (`consumed_at IS NULL`, not expired,
   `failures < 5`) and returns the row. So a code has at most 5 guesses, also under concurrent requests. On a match,
   a second statement consumes it (`consumed_at IS NULL` guard: single use under a race).
5. **Principal.**
   - Known by mailbox, not disabled: sign in. An invited principal is activated (the mailbox is proven).
   - Unknown and admitted: create an active **internal** user with no grants, as OIDC lazy-create does.
   - Otherwise: refused (the configuration changed between request and verify).
6. **Session.** `issueSession` with `authentication_method = 'email_code'`, `idp_sub = NULL`. The handoff to the
   application is the same as for password and OIDC, so sign-in across applications (Termin + Zakulisi) does not change.
   `sessionUsable` keeps an `email_code` session only while the method is enabled.

## Throttling

The existing `login_throttles` buckets (`recordLoginFailure` / `getLoginThrottle`), with new keys:

| Bucket                 | Key                                  | Limit per 15 min |
| ---------------------- | ------------------------------------ | ---------------- |
| sends per mailbox      | `email-code:account:<mailbox>`       | 5                |
| sends, deployment-wide | `email-code:global`                  | 500              |
| sends per client       | `email-code:client:<address>`        | 30               |
| verifies per client    | `email-code-verify:client:<address>` | 100              |

A blocked send answers the same code form and mails nothing.

## Data

New table `email_codes` (D1 and Postgres):

| column                                                |                                                                  |
| ----------------------------------------------------- | ---------------------------------------------------------------- |
| `attempt_hash`                                        | PK, SHA-256 of the cookie value                                  |
| `code_hash`                                           | SHA-256(attempt ":" code)                                        |
| `email`                                               | the normalized mailbox (no principal yet for a new person)       |
| `app`                                                 | the application of the presentation (language, name in the mail) |
| `failures`, `created_at`, `expires_at`, `consumed_at` |                                                                  |

The maintenance cron deletes rows that expired more than one day ago.

`sessions.authentication_method` admits `email_code`. SQLite cannot change a CHECK, so the D1 migration rebuilds
`sessions` as `0023_terminals.sql` did (dependent rows kept aside and restored). Postgres replaces the constraints.

## Mail

IAM's own catalog message `signInCode` (`en`, `cs`): the code in the subject and the body, its expiry, and
"ignore if you did not ask". It is not an application `MessageKind`, so applications cannot word it (no change
to `@fabrika/auth-core`'s template checker).

## Sign-out

With OIDC disabled, `/auth/logout` ends the IAM login and every application session. No other session exists,
so the next sign-in asks for a new code.

## Rejected

- **Magic link.** Mail scanners open links and can spend them. A link opened on a phone signs in the phone,
  not the computer that asked.
- **Code without attempt cookie.** A code then works in any browser. A phished person who reads the code out
  signs the attacker in. The cookie does not stop a live relay, but it stops a code that someone forwards.
- **Store the session as `password`.** It would tie the session to `PASSWORD_ENABLED` and show the wrong method
  in the console.
- **An external IdP with a free tier.** A third party holds client data, and sign-out needs that IdP's logout as well.

## Limits

- ADR-0051 says an external person authenticates by password only. Email code also admits a known external
  principal: proving the mailbox is what a password reset already proves.
- The migration number `0029` can clash with a future upstream `0029`. The migration runner records names,
  so both apply. Upstreaming removes the fork migration.
- `fabrika platform init` does not know `--auth-methods=email_code`. The operator sets
  `FABRIKA_IAM_EMAIL_CODE_ENABLED` in the GitHub Environment, and the sidecar workflow passes it to the IAM stage.
