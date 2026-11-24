// The email-code statements on a REAL Postgres (joat fork): the guess counter, single use, the verified principal and
// the subjectless session. Skips cleanly when FABRIKA_TEST_POSTGRES_URL is unset.

import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { createPostgresIamRepositories, EMAIL_CODE_MAX_GUESSES, type IamRepositories } from '../db'
import { createPostgres, hasPostgres, type PostgresFixture, skipReason } from './helpers/postgres'

if (!hasPostgres) {
	console.warn(`email-code-postgres.test.ts ${skipReason}`)
}

let fixture: PostgresFixture | null = null
let db: IamRepositories

beforeAll(async () => {
	if (!hasPostgres) return
	fixture = await createPostgres('iam')
	db = createPostgresIamRepositories(fixture.db)
})

afterAll(async () => {
	await fixture?.close()
})

describe.skipIf(!hasPostgres)('email code on Postgres', () => {
	test('counts guesses in the read, and a code is consumed once', async () => {
		const expiresAt = Math.floor(Date.now() / 1000) + 600
		await db.emailCodes.issue({ attemptHash: 'attempt-1', codeHash: 'code-1', email: 'a@joat.test', app: null, expiresAt })
		for (let i = 1; i <= EMAIL_CODE_MAX_GUESSES; i++) expect((await db.emailCodes.spendGuess('attempt-1'))?.failures).toBe(i)
		expect(await db.emailCodes.spendGuess('attempt-1')).toBeNull()

		await db.emailCodes.issue({ attemptHash: 'attempt-2', codeHash: 'code-2', email: 'b@joat.test', app: 'termin', expiresAt })
		expect(typeof (await db.emailCodes.spendGuess('attempt-2'))?.expires_at).toBe('number')
		expect(await db.emailCodes.consume('attempt-2')).toBe(true)
		expect(await db.emailCodes.consume('attempt-2')).toBe(false)
		expect(await db.emailCodes.spendGuess('attempt-2')).toBeNull()
		expect(await db.emailCodes.prune(expiresAt + 1)).toBe(2)
	})

	test('a verified user is active, internal and holds a subjectless email_code session', async () => {
		const created = await db.principals.createVerifiedUser('New@Joat.test')
		expect(created.email).toBe('new@joat.test')
		expect(created.affiliation).toBe('internal')
		expect(created.activated_at).not.toBeNull()

		const invited = await db.principals.inviteUser('invited@joat.test')
		expect((await db.principals.activateVerifiedUser(invited.id))?.activated_at).not.toBeNull()
		// Activating again changes nothing and answers the row.
		expect((await db.principals.activateVerifiedUser(invited.id))?.id).toBe(invited.id)

		const sessionId = await db.sessions.createSession({
			tokenHash: 'token-hash',
			principalId: created.id,
			email: created.email,
			authenticationMethod: 'email_code',
			expiresAt: Math.floor(Date.now() / 1000) + 3600,
		})
		expect((await db.sessions.getActiveSessionByHash('token-hash'))?.id).toBe(sessionId)
	})
})
