-- Sign-in with an email code (joat fork, docs/specs/joat-email-code-sign-in.md).
-- Postgres dialect; `../migrations/0029_email_code_sign_in.sql` states the same outcome.
CREATE TABLE email_codes (
	attempt_hash TEXT PRIMARY KEY,
	code_hash    TEXT NOT NULL,
	email        TEXT NOT NULL,
	app          TEXT,
	failures     INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	consumed_at  INTEGER
);

CREATE INDEX idx_email_codes_expires ON email_codes(expires_at);

-- A login by email code is a session method of its own, with no IdP subject.
ALTER TABLE sessions DROP CONSTRAINT sessions_authentication_method_check;

ALTER TABLE sessions ADD CONSTRAINT sessions_authentication_method_check
	CHECK (authentication_method IN ('oidc', 'password', 'local_dev', 'terminal_assertion', 'email_code'));

ALTER TABLE sessions DROP CONSTRAINT sessions_method_subject_check;

ALTER TABLE sessions ADD CONSTRAINT sessions_method_subject_check CHECK (
	(authentication_method IN ('oidc', 'local_dev') AND idp_sub IS NOT NULL)
	OR (authentication_method IN ('password', 'terminal_assertion', 'email_code') AND idp_sub IS NULL)
);
