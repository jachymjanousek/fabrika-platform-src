import { Database } from 'bun:sqlite'
import { describe, expect, test } from 'bun:test'
import { migrationFile, migrationsBefore } from './helpers/migrations'

// 0029 rebuilds `sessions` on D1 to admit the `email_code` method. A live installation holds logins, child sessions,
// handoff codes and OAuth grants that hang off them: the rebuild must keep every row and every reference. Applied one
// statement at a time, as `wrangler d1 migrations apply` does.

const FILE = '0029_email_code_sign_in.sql'
const T = 1_782_896_400

function statementsOf(sql: string): string[] {
	return sql
		.split('\n')
		.filter((line) => !line.trimStart().startsWith('--'))
		.join('\n')
		.split(';')
		.map((statement) => statement.trim())
		.filter((statement) => statement !== '')
}

function count(db: Database, table: string): number {
	return db.query<{ n: number }, []>(`SELECT COUNT(*) AS n FROM ${table}`).get()?.n ?? 0
}

describe('0029: sessions admit the email_code method', () => {
	test('keeps every session, child session, handoff code and OAuth row, with their references', () => {
		const db = new Database(':memory:')
		db.exec('PRAGMA foreign_keys = ON')
		db.exec(migrationsBefore(FILE))
		db.run(
			`INSERT INTO principals (id, type, external_id, email, label, activated_at, created_at) VALUES ('p1', 'user', 's1', 'a@x.cz', 'a@x.cz', ${T}, ${T})`,
		)
		db.run(`INSERT INTO sessions (id, token_hash, principal_id, idp_sub, email, authentication_method, created_at, expires_at)
			VALUES ('root', 'h-root', 'p1', 's1', 'a@x.cz', 'oidc', ${T}, ${T + 3600})`)
		db.run(`INSERT INTO sessions (id, token_hash, principal_id, idp_sub, email, authentication_method, created_at, expires_at, app, parent_session_id)
			VALUES ('child', 'h-child', 'p1', 's1', 'a@x.cz', 'oidc', ${T}, ${T + 3600}, 'termin', 'root')`)
		db.run(`INSERT INTO auth_codes (id, code_hash, app, parent_session_id, return_url, expires_at, created_at)
			VALUES ('c1', 'code-hash', 'termin', 'root', 'https://termin.test/', ${T + 60}, ${T})`)
		db.run(`INSERT INTO oauth_grants (id, principal_id, session_id, client_id, app, resource, scopes, created_at, expires_at)
			VALUES ('g1', 'p1', 'root', 'client', 'termin', 'https://termin.test/mcp', 'mcp', ${T}, ${T + 3600})`)
		db.run(
			`INSERT INTO oauth_codes (token_hash, grant_id, redirect_uri, challenge, expires_at) VALUES ('oc', 'g1', 'https://c.test/cb', 'ch', ${T + 60})`,
		)
		db.run(`INSERT INTO oauth_refresh_tokens (token_hash, grant_id, expires_at) VALUES ('rt', 'g1', ${T + 3600})`)

		for (const statement of statementsOf(migrationFile(FILE))) db.run(statement)

		expect(count(db, 'sessions')).toBe(2)
		expect(count(db, 'auth_codes')).toBe(1)
		expect(count(db, 'oauth_grants')).toBe(1)
		expect(count(db, 'oauth_codes')).toBe(1)
		expect(count(db, 'oauth_refresh_tokens')).toBe(1)
		expect(db.query('PRAGMA foreign_key_check').all()).toEqual([])
		// The references still cascade: ending the root login ends everything that hangs off it.
		db.run(`DELETE FROM sessions WHERE id = 'root'`)
		for (const table of ['sessions', 'auth_codes', 'oauth_grants', 'oauth_codes', 'oauth_refresh_tokens']) expect(count(db, table)).toBe(0)
	})

	test('admits an email_code session without an IdP subject, and still refuses an OIDC one without', () => {
		const db = new Database(':memory:')
		db.exec('PRAGMA foreign_keys = ON')
		db.exec(migrationsBefore(FILE))
		for (const statement of statementsOf(migrationFile(FILE))) db.run(statement)
		db.run(`INSERT INTO principals (id, type, email, label, activated_at, created_at) VALUES ('p1', 'user', 'a@x.cz', 'a@x.cz', ${T}, ${T})`)
		db.run(`INSERT INTO sessions (id, token_hash, principal_id, email, authentication_method, created_at, expires_at)
			VALUES ('s1', 'h1', 'p1', 'a@x.cz', 'email_code', ${T}, ${T + 3600})`)
		expect(() =>
			db.run(`INSERT INTO sessions (id, token_hash, principal_id, email, authentication_method, created_at, expires_at)
			VALUES ('s2', 'h2', 'p1', 'a@x.cz', 'oidc', ${T}, ${T + 3600})`)
		).toThrow()
	})
})
