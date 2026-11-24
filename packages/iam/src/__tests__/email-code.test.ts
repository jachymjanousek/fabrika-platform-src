// Sign-in with an email code (joat fork, docs/specs/joat-email-code-sign-in.md).
//
// The properties under test: the answer to a request never tells whether an address can sign in; a code works only
// once, only for five guesses, only for ten minutes and only in the browser that asked; and a proven mailbox signs in
// as its principal, or as a new internal one when the allowlist admits it.

import { AUTH_CALLBACK_PATH, AUTH_HANDOFF_CHALLENGE_PARAM, AUTH_HANDOFF_STATE_PARAM, SESSION_COOKIE } from '@fabrika/auth-core'
import type { EmailDeliveryResult, EmailMessage, EmailSender } from '@fabrika/email'
import { unusedDatabase } from '@fabrika/platform/testing'
import { describe, expect, test } from 'bun:test'
import { EMAIL_CODE_COOKIE } from '../auth/email-code'
import { handleAuth } from '../auth/routes'
import type { RequestContext } from '../env'
import { pkceChallenge } from '../oidc'
import { hashToken } from '../secret'
import { buildServices } from '../services'
import { createHarness, seedUser } from './helpers/harness'

const ISSUER = 'http://localhost:18191'
const APP_ORIGIN = 'https://termin.test'
const AUTH_ENV = { FABRIKA_IAM_SIGNING_KEYS: '', ENVIRONMENT: 'local' }

class CapturingEmail implements EmailSender {
	readonly capabilities = { idempotent: true, confirmation: 'sync', maxBatch: 1 } satisfies EmailSender['capabilities']
	readonly messages: EmailMessage[] = []

	async send(message: EmailMessage): Promise<EmailDeliveryResult> {
		this.messages.push(message)
		return { status: 'accepted', provider: 'test', messageId: `message-${this.messages.length}` }
	}
}

class TestContext implements RequestContext {
	readonly pending: Promise<unknown>[] = []
	readonly waitUntil = (promise: Promise<unknown>): void => {
		this.pending.push(promise)
	}
	async drain(): Promise<void> {
		await Promise.all(this.pending)
	}
}

function setup(options: { password?: boolean; oidc?: boolean; emailCode?: boolean; domains?: string[] } = {}) {
	const h = createHarness()
	const email = new CapturingEmail()
	const services = h.makeServices({
		issuer: ISSUER,
		authentication: { oidc: options.oidc ?? false, password: options.password ?? false, emailCode: options.emailCode ?? true },
		email,
		human: { emailDomains: options.domains ?? ['*'] },
	})
	return { h, email, services }
}

function post(path: string, fields: Record<string, string>, cookie: string | null = null, headers: Record<string, string> = {}): Request {
	return new Request(`${ISSUER}${path}`, {
		method: 'POST',
		headers: {
			Origin: ISSUER,
			'Sec-Fetch-Site': 'same-origin',
			'Content-Type': 'application/x-www-form-urlencoded',
			'CF-Connecting-IP': '192.0.2.10',
			...(cookie === null ? {} : { Cookie: `${EMAIL_CODE_COOKIE}=${cookie}` }),
			...headers,
		},
		body: new URLSearchParams(fields),
	})
}

function cookieValue(response: Response, name: string): string | null {
	for (const header of response.headers.getSetCookie()) {
		if (!header.startsWith(`${name}=`)) continue
		return header.slice(name.length + 1).split(';')[0] ?? null
	}
	return null
}

/** The code in the last mail. */
function mailedCode(email: CapturingEmail): string {
	const message = email.messages.at(-1)
	const code = message?.text.match(/^\d{6}$/m)?.[0]
	if (code === undefined) throw new Error('no code was mailed')
	return code
}

type Setup = ReturnType<typeof setup>

/** Ask for a code for `address`; answers the attempt cookie the browser now holds. */
async function requestCode(s: Setup, address: string, fields: Record<string, string> = {}): Promise<{ attempt: string; response: Response }> {
	const ctx = new TestContext()
	const response = await handleAuth(post('/auth/code', { email: address, ...fields }), s.services, AUTH_ENV, ctx, '192.0.2.10')
	await ctx.drain()
	const attempt = cookieValue(response, EMAIL_CODE_COOKIE)
	if (attempt === null) throw new Error('no attempt cookie')
	return { attempt, response }
}

async function verify(s: Setup, attempt: string | null, code: string, fields: Record<string, string> = {}): Promise<Response> {
	const ctx = new TestContext()
	const response = await handleAuth(post('/auth/code/verify', { code, ...fields }, attempt), s.services, AUTH_ENV, ctx, '192.0.2.10')
	await ctx.drain()
	return response
}

/** Any six digits but `code`. */
function otherCode(code: string): string {
	return code === '000000' ? '111111' : '000000'
}

describe('the boot', () => {
	test('refuses the email code without an email sender, and admits it as the only method with one', () => {
		const h = createHarness()
		const env = {
			DB: unusedDatabase,
			REPOSITORIES: h.repositories,
			HUMAN_EMAIL_DOMAINS: '["*"]',
			HUMAN_EMAILS: '[]',
			IAM_BOOTSTRAP_ADMINS: '[]',
			ENVIRONMENT: 'local',
			ISSUER,
			FABRIKA_IAM_SIGNING_KEYS: '',
			FABRIKA_IAM_PROVISIONING_KEY: '',
			OIDC_ENABLED: 'false',
			PASSWORD_ENABLED: 'false',
			EMAIL_CODE_ENABLED: 'true',
		}
		expect(() => buildServices(env)).toThrow('EMAIL_CODE_ENABLED needs an email sender')
		expect(buildServices({ ...env, EMAIL_SENDER: new CapturingEmail() }).config.authentication.emailCode.enabled).toBe(true)
		expect(() => buildServices({ ...env, EMAIL_CODE_ENABLED: 'false' })).toThrow('At least one authentication method must be enabled')
	})
})

describe('the sign-in page', () => {
	test('offers the email code first, and the password one link away when the installation enables it', async () => {
		const both = setup({ password: true })
		const page = await (await handleAuth(new Request(`${ISSUER}/auth/login`), both.services, AUTH_ENV, new TestContext())).text()
		expect(page).toContain('action="/auth/code"')
		expect(page).toContain('method=password')
		const password = await handleAuth(new Request(`${ISSUER}/auth/login?method=password`), both.services, AUTH_ENV, new TestContext())
		expect(await password.text()).toContain('autocomplete="current-password"')

		const codeOnly = setup()
		const only = await (await handleAuth(new Request(`${ISSUER}/auth/login?method=password`), codeOnly.services, AUTH_ENV, new TestContext()))
			.text()
		expect(only).toContain('action="/auth/code"')
		expect(only).not.toContain('method=password')
	})

	test('answers 404 for both forms while the method is off', async () => {
		const off = setup({ emailCode: false, password: true })
		expect((await handleAuth(post('/auth/code', { email: 'a@b.test' }), off.services, AUTH_ENV, new TestContext())).status).toBe(404)
		expect((await handleAuth(post('/auth/code/verify', { code: '123456' }), off.services, AUTH_ENV, new TestContext())).status).toBe(404)
	})

	test('refuses a cross-origin post', async () => {
		const s = setup()
		const response = await handleAuth(
			post('/auth/code', { email: 'a@b.test' }, null, { Origin: 'https://evil.test' }),
			s.services,
			AUTH_ENV,
			new TestContext(),
		)
		expect(response.status).toBe(403)
		expect(s.email.messages).toHaveLength(0)
	})
})

describe('requesting a code', () => {
	test('answers the same page for an address that can sign in and for one that cannot', async () => {
		const s = setup({ domains: ['joat.test'] })
		const admitted = await requestCode(s, 'client@joat.test')
		const refused = await requestCode(s, 'stranger@elsewhere.test')
		// Equal but for the per-response CSP nonce.
		const withoutNonce = async (response: Response) => (await response.text()).replaceAll(/nonce="[0-9a-f]+"/g, '')
		expect(await withoutNonce(refused.response)).toBe(await withoutNonce(admitted.response))
		expect(refused.response.status).toBe(admitted.response.status)
		// Only the admitted address got a mail, and only it has a code behind its cookie.
		expect(s.email.messages.map((message) => message.to)).toEqual(['client@joat.test'])
		expect(s.h.sqlite.query('SELECT email FROM email_codes').all()).toEqual([{ email: 'client@joat.test' }])
	})

	test('mails nothing to a disabled principal', async () => {
		const s = setup()
		seedUser(s.h.sqlite, { email: 'gone@joat.test', sub: 'gone', disabled: true })
		await requestCode(s, 'gone@joat.test')
		expect(s.email.messages).toHaveLength(0)
	})

	test('mails at most five codes per mailbox in a window, and answers the same page after that', async () => {
		const s = setup()
		for (let i = 0; i < 7; i++) await requestCode(s, 'busy@joat.test')
		expect(s.email.messages).toHaveLength(5)
	})

	test('stores neither the code nor the attempt in plain text', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'client@joat.test')
		const code = mailedCode(s.email)
		const row = s.h.sqlite.query<{ attempt_hash: string; code_hash: string }, []>('SELECT attempt_hash, code_hash FROM email_codes').get()
		expect(row?.attempt_hash).toBe(await hashToken(attempt))
		expect(row?.code_hash).toBe(await hashToken(`${attempt}:${code}`))
		expect(row?.code_hash).not.toBe(await hashToken(code))
	})
})

describe('verifying a code', () => {
	test('signs a new admitted address in as a new active internal user, with an email_code session', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'Client@Joat.test')
		const response = await verify(s, attempt, mailedCode(s.email))
		expect(response.status).toBe(302)
		const token = cookieValue(response, SESSION_COOKIE)
		const session = await s.h.repositories.sessions.getActiveSessionByHash(await hashToken(token ?? ''))
		expect(session?.authentication_method).toBe('email_code')
		expect(session?.idp_sub).toBeNull()
		const principal = await s.h.repositories.principals.getUserByEmail('client@joat.test')
		expect(principal?.affiliation).toBe('internal')
		expect(principal?.activated_at).not.toBeNull()
		expect(principal?.id).toBe(session?.principal_id)
		// The attempt cookie ends with the sign-in.
		expect(response.headers.getSetCookie().some((c) => c.startsWith(`${EMAIL_CODE_COOKIE}=;`))).toBe(true)
	})

	test('signs a known principal in as itself, and activates an invited one', async () => {
		const s = setup({ domains: [] })
		const known = seedUser(s.h.sqlite, { email: 'known@joat.test', sub: 'known-sub' })
		const invited = await s.h.repositories.principals.inviteUser('invited@joat.test')
		for (const [address, id] of [['known@joat.test', known], ['invited@joat.test', invited.id]] as const) {
			const { attempt } = await requestCode(s, address)
			const response = await verify(s, attempt, mailedCode(s.email))
			expect(response.status).toBe(302)
			const session = await s.h.repositories.sessions.getActiveSessionByHash(await hashToken(cookieValue(response, SESSION_COOKIE) ?? ''))
			expect(session?.principal_id).toBe(id)
		}
		expect((await s.h.repositories.principals.getPrincipalById(invited.id))?.activated_at).not.toBeNull()
	})

	test('a code works once', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'client@joat.test')
		const code = mailedCode(s.email)
		expect((await verify(s, attempt, code)).status).toBe(302)
		expect((await verify(s, attempt, code)).status).toBe(401)
	})

	test('a code admits five guesses: after five wrong ones the right one is refused', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'client@joat.test')
		const code = mailedCode(s.email)
		for (let i = 0; i < 5; i++) expect((await verify(s, attempt, otherCode(code))).status).toBe(401)
		expect((await verify(s, attempt, code)).status).toBe(401)
	})

	test('a code works only in the browser that asked for it', async () => {
		const s = setup()
		await requestCode(s, 'client@joat.test')
		const code = mailedCode(s.email)
		expect((await verify(s, null, code)).status).toBe(401)
		const other = await requestCode(s, 'attacker@joat.test')
		expect((await verify(s, other.attempt, code)).status).toBe(401)
	})

	test('an expired code is refused', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'client@joat.test')
		s.h.sqlite.run('UPDATE email_codes SET expires_at = expires_at - 3600')
		expect((await verify(s, attempt, mailedCode(s.email))).status).toBe(401)
	})

	test('a principal disabled after the mail is refused', async () => {
		const s = setup()
		const id = seedUser(s.h.sqlite, { email: 'soon-gone@joat.test', sub: 'soon-gone' })
		const { attempt } = await requestCode(s, 'soon-gone@joat.test')
		s.h.sqlite.run('UPDATE principals SET disabled_at = 1 WHERE id = ?', [id])
		expect((await verify(s, attempt, mailedCode(s.email))).status).toBe(401)
	})

	test('accepts the code with a space in it, as a mail client may group it', async () => {
		const s = setup()
		const { attempt } = await requestCode(s, 'client@joat.test')
		const code = mailedCode(s.email)
		expect((await verify(s, attempt, `${code.slice(0, 3)} ${code.slice(3)}`)).status).toBe(302)
	})

	test("lands on the application's callback when the sign-in is a handoff", async () => {
		const s = setup()
		await s.services.repositories.handoff.setReturnOrigins('termin', [APP_ORIGIN])
		const handoff = {
			app: 'termin',
			redirect: `${APP_ORIGIN}/ensembles`,
			[AUTH_HANDOFF_STATE_PARAM]: 'state-state-state1',
			[AUTH_HANDOFF_CHALLENGE_PARAM]: await pkceChallenge('browser-held-verifier-browser-held-verifier-1'),
		}
		const { attempt, response } = await requestCode(s, 'client@joat.test', handoff)
		// The code form keeps the handoff and admits the 302 to the application in `form-action`.
		expect(await response.text()).toContain('name="app" value="termin"')
		expect(response.headers.get('Content-Security-Policy')).toContain(APP_ORIGIN)
		const signedIn = await verify(s, attempt, mailedCode(s.email), handoff)
		expect(signedIn.status).toBe(302)
		const location = new URL(signedIn.headers.get('Location') ?? '')
		expect(location.origin).toBe(APP_ORIGIN)
		expect(location.pathname).toBe(AUTH_CALLBACK_PATH)
	})
})
