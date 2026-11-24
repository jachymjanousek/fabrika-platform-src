// A signed-in person whose account has no access reads a page that offers another account (joat fork,
// docs/specs/joat-sign-out-to-app.md). "Go to the start page" looped when the start page itself was refused.

import { SESSION_COOKIE } from '@fabrika/auth-core'
import { describe, expect, test } from 'bun:test'
import { AUTH_SIGNOUT_PATH } from '../constants'
import { errorPage, SIGNED_IN_FORBIDDEN_PAGE } from '../pages'
import { createVerifyService } from '../service'
import { contractAppWith, endpointRow, FakeIam, ISSUER, signToken, verifyRequest } from './helpers'

const ROOT = endpointRow({
	id: 'app.spa',
	kind: 'spa',
	method: 'GET',
	path: '/*',
	callers: ['human'],
	requirement: { kind: 'member' },
	admission: null,
})
const NAVIGATE = { 'Sec-Fetch-Mode': 'navigate' }

async function verifyWithoutAccess() {
	// A user token with no permission at the application: `member` refuses it.
	const token = await signToken({ type: 'user', permissions: [] })
	const iam = new FakeIam({ mintToken: () => ({ ok: true, token, expiresAt: Math.floor(Date.now() / 1000) + 300 }) })
	return createVerifyService({ manifest: { apps: [contractAppWith([ROOT])] }, iam, issuer: ISSUER })
}

describe('the 403 of a signed-in person without access', () => {
	test('offers to sign in with another account, through the sign-out that ends the IAM login', async () => {
		const verify = await verifyWithoutAccess()
		const response = await verify(verifyRequest({ path: '/', cookie: `${SESSION_COOKIE}=session`, headers: NAVIGATE }))
		expect(response.status).toBe(403)
		const body = await response.text()
		expect(body).toContain(SIGNED_IN_FORBIDDEN_PAGE.title)
		expect(body).toContain(`href="${AUTH_SIGNOUT_PATH}?redirect=%2F&everywhere=1"`)
		expect(body).not.toContain('Go to the start page')
	})

	test('a program reads the short text, and a caller without a session keeps the old page', async () => {
		const verify = await verifyWithoutAccess()
		const program = await verify(verifyRequest({ path: '/', cookie: `${SESSION_COOKIE}=session` }))
		expect(program.status).toBe(403)
		expect(await program.text()).toBe('forbidden')
		const unknown = await verify(verifyRequest({ path: '/../x', cookie: `${SESSION_COOKIE}=session`, headers: NAVIGATE }))
		expect(await unknown.text()).toBe(errorPage(400))
	})
})
