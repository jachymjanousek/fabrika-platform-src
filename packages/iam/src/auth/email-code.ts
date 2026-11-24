/**
 * Sign-in with a code IAM mails to the person (joat fork, `docs/specs/joat-email-code-sign-in.md`).
 *
 * The mailbox is the whole credential, as it is for a password reset: no password to forget and no IdP that counts
 * seats. Three rules carry the security:
 *   1. the answer to a request is the same for every address, and the work that differs runs after it (`waitUntil`);
 *   2. a code works only in the browser that asked for it (the attempt cookie), and the stored hash needs that cookie;
 *   3. a code admits five guesses, counted in the statement that reads it.
 */
import { AUTH_HANDOFF_CHALLENGE_PARAM, AUTH_HANDOFF_STATE_PARAM } from '@fabrika/auth-core'
import { z } from 'zod'
import { type AppPresentation, presentationFor } from '../app-presentation'
import { catalogFor } from '../catalog'
import { type AuditEventInput, type PrincipalRow } from '../db'
import { normalizeEmailIdentity } from '../email-identity'
import { type RequestContext } from '../env'
import { admitted } from '../human-admission'
import { logError } from '../log'
import { EMAIL_SEND_DEADLINE_MS } from '../messages'
import { randomToken } from '../oidc'
import { authFailurePage, emailCodeEntryPage, type SignInFields } from '../password-pages'
import { hashToken, timingSafeEqualHex } from '../secret'
import { type Services } from '../services'
import { clearCookie, readCookie, serializeCookie } from './cookies'
import { type Handoff, handoffOf, handoffRedirectOr, loginDestinationFields, readHandoff } from './handoff'
import { readForm, sameOrigin, stringValue } from './http'
import { issueSession, type LoginRefusal, refuseLogin } from './sessions'

/** How long a mailed code is valid. Short, because a code has only 10⁶ values. */
export const EMAIL_CODE_TTL_SECONDS = 10 * 60

/** The browser's half of an attempt. `__Host-`: IAM's host only, `Secure`, `Path=/`. */
export const EMAIL_CODE_COOKIE = '__Host-fabrika_code'

const WINDOW_SECONDS = 15 * 60
const BLOCK_SECONDS = 15 * 60
/** Codes one mailbox may request per window: enough for a lost mail, too few to flood the inbox. */
const ACCOUNT_MAX_SENDS = 5
const GLOBAL_MAX_SENDS = 500
const CLIENT_MAX_SENDS = 30
const CLIENT_MAX_VERIFIES = 100

const emailSchema = z.string().transform(normalizeEmailIdentity).pipe(z.string().min(1).max(254).includes('@'))
/** Six digits; a space in the middle is what a person copies from a mail client that groups them. */
const codeSchema = z.string().transform((value) => value.replaceAll(/\s/g, '')).pipe(z.string().regex(/^\d{6}$/))

/** A request for a code: always the code form and a fresh attempt cookie, whatever the address. */
export async function handleEmailCodeRequest(
	request: Request,
	services: Services,
	ctx: RequestContext,
	clientAddress: string | null,
	requestId: string,
): Promise<Response> {
	const read = await readSignIn(request, services, requestId)
	if (read instanceof Response) return read
	const { form, fields } = read
	const parsed = emailSchema.safeParse(form.get('email'))
	const attempt = randomToken(32)
	const page = emailCodeEntryPage({ ...fields, minutes: EMAIL_CODE_TTL_SECONDS / 60 })
	page.headers.append('Set-Cookie', attemptCookie(attempt))
	if (!parsed.success) return page
	const email = parsed.data

	const accountKey = await hashToken(`email-code:account:${email}`)
	const globalKey = await hashToken('email-code:global')
	const [accountThrottle, globalThrottle, clientOverLimit] = await Promise.all([
		services.repositories.passwords.getLoginThrottle(accountKey),
		services.repositories.passwords.getLoginThrottle(globalKey),
		clientBlocked(services, 'email-code', clientAddress, CLIENT_MAX_SENDS),
	])
	const now = Math.floor(Date.now() / 1000)
	if (clientOverLimit || (accountThrottle?.blocked_until ?? 0) > now || (globalThrottle?.blocked_until ?? 0) > now) {
		// The same page as a sent code, so a block says nothing about the address either.
		return page
	}
	await Promise.all([
		countAttempt(services, accountKey, ACCOUNT_MAX_SENDS),
		countAttempt(services, globalKey, GLOBAL_MAX_SENDS),
	])
	ctx.waitUntil(
		sendCode(services, { email, attempt, presentation: fields.presentation }).catch((err) =>
			logError(`a sign-in code could not be sent for request '${requestId}'`, err)
		),
	)
	return page
}

/** A code for a mailbox that may sign in, or nothing. Runs after the answer, so its time says nothing either. */
async function sendCode(
	services: Services,
	input: { email: string; attempt: string; presentation: AppPresentation },
): Promise<void> {
	if (services.email === null) return
	const principal = await services.repositories.principals.getUserByEmail(input.email)
	if (principal !== null ? principal.disabled_at !== null : !admitted(input.email, services.config)) return
	const code = sixDigits()
	const attemptHash = await hashToken(input.attempt)
	await services.repositories.emailCodes.issue({
		attemptHash,
		codeHash: await codeHash(input.attempt, code),
		email: input.email,
		app: input.presentation.app,
		expiresAt: Math.floor(Date.now() / 1000) + EMAIL_CODE_TTL_SECONDS,
	})
	const rendered = catalogFor(input.presentation.locale).signInCode({
		appName: input.presentation.displayName,
		code,
		minutes: EMAIL_CODE_TTL_SECONDS / 60,
	})
	await services.email.send(
		{
			to: input.email,
			subject: rendered.subject,
			text: rendered.text,
			html: rendered.html,
			idempotencyKey: `iam-email-code-${attemptHash.slice(0, 32)}`,
		},
		AbortSignal.timeout(EMAIL_SEND_DEADLINE_MS),
	)
}

/** The code form's answer: a session and the handoff's 302, or the same form with a refusal. */
export async function handleEmailCodeVerify(
	request: Request,
	services: Services,
	ctx: RequestContext,
	clientAddress: string | null,
	requestId: string,
): Promise<Response> {
	const read = await readSignIn(request, services, requestId)
	if (read instanceof Response) return read
	const { form, fields, handoff, redirect } = read
	const invalid = (reason: LoginRefusal, principalId: string | null = null) =>
		refuseLogin(
			services,
			{ requestId, principalId, reason },
			() => emailCodeEntryPage({ ...fields, minutes: EMAIL_CODE_TTL_SECONDS / 60, invalid: true }),
		)

	const attempt = readCookie(request.headers.get('Cookie'), EMAIL_CODE_COOKIE)
	const code = codeSchema.safeParse(form.get('code') ?? '')
	if (await clientBlocked(services, 'email-code-verify', clientAddress, CLIENT_MAX_VERIFIES)) return invalid('email_code_throttled')
	if (attempt === null || attempt.length > 128 || !code.success) return invalid('email_code_invalid')

	const attemptHash = await hashToken(attempt)
	const row = await services.repositories.emailCodes.spendGuess(attemptHash)
	if (row === null) return invalid('email_code_invalid')
	if (!timingSafeEqualHex(await codeHash(attempt, code.data), row.code_hash)) return invalid('email_code_invalid')
	if (!await services.repositories.emailCodes.consume(attemptHash)) return invalid('email_code_invalid')

	const principal = await verifiedPrincipal(services, row.email, requestId)
	if (principal === null) return invalid('email_code_refused')
	const session = await issueSession(request, services, ctx, {
		principalId: principal.id,
		email: principal.email,
		authenticationMethod: 'email_code',
		redirect,
		reason: 'email_code_login',
		requestId,
		handoff,
	})
	if (session.status === 302) session.headers.append('Set-Cookie', clearCookie(EMAIL_CODE_COOKIE, { path: '/' }))
	return session
}

/**
 * The principal a proven mailbox signs in as: the one that holds it (an invited one is activated), or a new internal
 * user when the allowlist admits the address. Null when neither applies, which happens only when the configuration or
 * the principal changed after the code was sent.
 */
async function verifiedPrincipal(services: Services, email: string, requestId: string): Promise<PrincipalRow | null> {
	const known = await services.repositories.principals.getUserByEmail(email)
	if (known !== null) {
		if (known.disabled_at !== null) return null
		if (known.activated_at !== null) return known
		return services.repositories.principals.activateVerifiedUser(known.id, codeEvent(requestId, known.id, 'iam.principal.activate'))
	}
	if (!admitted(email, services.config)) return null
	try {
		return await services.repositories.principals.createVerifiedUser(email, (id) => codeEvent(requestId, id, 'iam.principal.create'))
	} catch {
		// Two codes for one new mailbox, used at once: the other request created it.
		const raced = await services.repositories.principals.getUserByEmail(email)
		return raced === null || raced.disabled_at !== null ? null : raced
	}
}

interface SignIn {
	readonly form: URLSearchParams
	readonly fields: SignInFields
	readonly handoff: Handoff | null
	readonly redirect: string | null
}

/** The checks both forms share: the method is on, the post is same-origin, and the handoff is read again. */
async function readSignIn(request: Request, services: Services, requestId: string): Promise<SignIn | Response> {
	if (!services.config.authentication.emailCode.enabled) return new Response('Not found', { status: 404 })
	const refused = async (reason: LoginRefusal, failure: Parameters<typeof authFailurePage>[1], status: number, app: string | null) => {
		const presentation = await presentationFor(services, app)
		return refuseLogin(services, { requestId, principalId: null, reason }, () => authFailurePage(presentation, failure, status))
	}
	if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: { Allow: 'POST' } })
	if (!sameOrigin(request, services.config)) return refused('login_cross_origin', { kind: 'cross_origin' }, 403, null)
	const form = await readForm(request)
	if (form === null) return refused('email_code_invalid', { kind: 'malformed_form' }, 400, null)
	const app = stringValue(form.get('app'))
	const reading = await readHandoff(
		services,
		app,
		stringValue(form.get('redirect')),
		stringValue(form.get(AUTH_HANDOFF_STATE_PARAM)),
		stringValue(form.get(AUTH_HANDOFF_CHALLENGE_PARAM)),
	)
	if (reading.kind === 'refused') return refused('handoff_refused', reading.failure, 400, app)
	const handoff = handoffOf(reading)
	const redirect = handoffRedirectOr(handoff, stringValue(form.get('redirect')), services)
	const presentation = await presentationFor(services, handoff?.app ?? null)
	const fields: SignInFields = { presentation, redirect, ...await loginDestinationFields(services, handoff, redirect) }
	return { form, fields, handoff, redirect }
}

/** A uniform six-digit code: rejection sampling, so no value is likelier than another. */
function sixDigits(): string {
	const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000
	const buffer = new Uint32Array(1)
	for (;;) {
		crypto.getRandomValues(buffer)
		const value = buffer[0] ?? limit
		if (value < limit) return String(value % 1_000_000).padStart(6, '0')
	}
}

/** The stored hash of a code. It needs the attempt, which only the browser holds, so the table alone tests nothing. */
function codeHash(attempt: string, code: string): Promise<string> {
	return hashToken(`${attempt}:${code}`)
}

function attemptCookie(attempt: string): string {
	// Strict: the code form posts from IAM's own page, and no other site has a reason to send it.
	return serializeCookie(EMAIL_CODE_COOKIE, attempt, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: EMAIL_CODE_TTL_SECONDS, path: '/' })
}

/** The per-client bucket, as `clientBlocked` in `password.ts`: one statement that counts every attempt. */
async function clientBlocked(services: Services, purpose: string, clientAddress: string | null, maxAttempts: number): Promise<boolean> {
	if (clientAddress === null) return false
	const row = await services.repositories.passwords.recordLoginFailure({
		loginKeyHash: await hashToken(`${purpose}:client:${clientAddress}`),
		windowSeconds: WINDOW_SECONDS,
		maxAttempts,
		blockSeconds: BLOCK_SECONDS,
	})
	return (row.blocked_until ?? 0) > Math.floor(Date.now() / 1000)
}

async function countAttempt(services: Services, loginKeyHash: string, maxAttempts: number): Promise<void> {
	await services.repositories.passwords.recordLoginFailure({ loginKeyHash, windowSeconds: WINDOW_SECONDS, maxAttempts, blockSeconds: BLOCK_SECONDS })
}

/** The record of a change a code sign-in made: the person is not signed in yet, so the actor is anonymous. */
function codeEvent(requestId: string, principalId: string, action: string): AuditEventInput {
	return {
		requestId,
		principalId: null,
		principalLabel: 'email-code',
		app: 'propustka',
		action,
		resourceType: 'principal',
		resourceId: principalId,
		metadata: { method: 'email_code' },
	}
}
