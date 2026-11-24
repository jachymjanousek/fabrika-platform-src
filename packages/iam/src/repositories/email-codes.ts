import type { SqlDatabase } from '@fabrika/platform'
import { unixNow } from './sql'

/** One requested sign-in code (`email_codes`). Neither the attempt nor the code is stored in plain text. */
export interface EmailCodeRow {
	attempt_hash: string
	code_hash: string
	/** The normalized mailbox the code was sent to. */
	email: string
	/** The application the request came from; it picks the language and the name in the mail. */
	app: string | null
	failures: number
	created_at: number
	expires_at: number
	consumed_at: number | null
}

/**
 * The guesses one code admits. The bound holds under concurrent requests because `spendGuess` counts a guess and
 * reads the row in one statement.
 */
export const EMAIL_CODE_MAX_GUESSES = 5

/** Storage of sign-in codes. The handler decides who gets a code; this class only keeps the bounds. */
export class EmailCodeRepository {
	constructor(private readonly db: SqlDatabase) {}

	/** Store a new code. */
	async issue(input: { attemptHash: string; codeHash: string; email: string; app: string | null; expiresAt: number }): Promise<void> {
		await this.db
			.prepare(`INSERT INTO email_codes (attempt_hash, code_hash, email, app, failures, created_at, expires_at)
				VALUES (?, ?, ?, ?, 0, ?, ?)`)
			.bind(input.attemptHash, input.codeHash, input.email, input.app, unixNow(), input.expiresAt)
			.run()
	}

	/**
	 * Count one guess and return the row, or null when the code is spent, expired or out of guesses. The count and the
	 * read are one statement, so two concurrent guesses can never both see the last free one.
	 */
	async spendGuess(attemptHash: string): Promise<EmailCodeRow | null> {
		return this.db
			.prepare(`UPDATE email_codes SET failures = failures + 1
				WHERE attempt_hash = ? AND consumed_at IS NULL AND expires_at > ? AND failures < ?
				RETURNING *`)
			.bind(attemptHash, unixNow(), EMAIL_CODE_MAX_GUESSES)
			.first<EmailCodeRow>()
	}

	/** Mark a matched code used. False when another request used it first, which makes this one a refusal. */
	async consume(attemptHash: string): Promise<boolean> {
		const row = await this.db
			.prepare('UPDATE email_codes SET consumed_at = ? WHERE attempt_hash = ? AND consumed_at IS NULL RETURNING attempt_hash')
			.bind(unixNow(), attemptHash)
			.first<{ attempt_hash: string }>()
		return row !== null
	}

	/** Delete codes that expired before `olderThanSeconds`. A used or expired code is refused anyway; the row only holds an address. */
	async prune(olderThanSeconds: number): Promise<number> {
		const result = await this.db.prepare('DELETE FROM email_codes WHERE expires_at < ?').bind(olderThanSeconds).run()
		return result.meta.changes ?? 0
	}
}
