# Sign-out back to the application (joat fork)

Status: implemented in the joat fork (`joat/sign-out-to-app`), to propose upstream.
Date: 2026-11-24.

## Why

Found while testing the email-code sign-in (`joat-email-code-sign-in.md`):

1. A person signed in with an account that has no role in an application gets the proxy's 403 page. Its only button,
   "Go to the start page", links to `/`. When `/` is the page that refused, the button loops.
2. There is no sign-out that returns to the application:
   - IAM's `/auth/logout` admits a return address on IAM's own origin only, so it always lands on the console. A
     client of a SaaS application has nothing to do there.
   - The proxy's `/__fabrika/auth/signout` ends only the application session. The IAM login stays, so the next
     request signs the same person in again without a question.

## What

### IAM: `/auth/logout?app=<id>&redirect=<url>`

- With `app`, the `redirect` must lie in that application's registered return origins (`resolveReturnUrl`, the same
  registry the handoff uses). An unregistered one answers the `unregistered_origin` page and signs nobody out.
- Without `app`, nothing changes: `safeRedirect` (IAM's own origin), else the installation's landing.
- `GET` still renders the same-origin confirmation form, which carries both values; only its `POST` ends the login.
  The form's `form-action` admits the application's origin, where the 302 goes.
- A provider logout (Cloudflare Access) still wins over any return address.

### Proxy: `/__fabrika/auth/signout?redirect=<path>&everywhere=1`

- Without `everywhere`, nothing changes (the terminal release).
- With `everywhere=1`, the proxy clears its session cookie and its cached token as before, then sends the browser to
  IAM's `/auth/logout?app=<audience>&redirect=<origin><path>`. The person confirms once; IAM ends the login and every
  application session made from it, and returns to the application, which asks for a sign-in again.
- The proxy step first is required: the cached access token would otherwise keep the old account for up to 5 minutes.

### Proxy: the 403 page of a signed-in person

When a session caller lacks the endpoint's permission (`insufficient_permission`), a page navigation gets:

- title "You cannot open this page", text "You are signed in with an account that has no access to this page. Sign in
  with another account, or ask whoever runs this application for access.";
- the button "Sign in with another account" → `/__fabrika/auth/signout?redirect=%2F&everywhere=1`.

Every other 403 (no endpoint, cross-site, a key caller) keeps the old page.

## Applications

An application's own "Sign out" link is `/__fabrika/auth/signout?redirect=/&everywhere=1`.

## Rejected

- **End the IAM login at `/auth/terminals/release`.** It is a cross-site `GET`; letting it end a personal login brings
  back the logout CSRF that the confirmation form removed.
- **Link the 403 page straight to IAM's logout.** The proxy's cached token would keep the old account after it.
