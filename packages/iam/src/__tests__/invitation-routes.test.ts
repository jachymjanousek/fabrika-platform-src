import { SESSION_COOKIE } from '@fabrika/auth-core'
import { describe, expect, test } from 'bun:test'
import { handleAuth } from '../auth/routes'
import { assignMember, createScope, requestDelegation } from '../membership'
import { createHarness, type Harness } from './helpers/harness'
import {
	APP,
	CALLER_ENV,
	CapturingEmail,
	CREATE_ENDPOINT,
	INVITE_ENDPOINT,
	type MembershipFixture,
	membershipFixture,
	ORIGIN,
} from './helpers/membership'

// The page an invitation link opens on IAM's own host. It accepts for the principal signed in there,
// same-origin only, and the one-time token arrives in the form — copied from the link's fragment.

interface Invited {
	h: Harness
	f: MembershipFixture
	token: string
	scope: { type: string; value: string }
}

async function invited(): Promise<Invited> {
	const h = createHarness()
	const email = new CapturingEmail()
	const f = await membershipFixture(h.repositories, { email })
	const owner = await f.person('owner')
	await f.repositories.grants.createGrant({ principalId: owner.id, app: APP, roleKey: 'starter' })
	const call = async (endpoint: string, requestId: string) => {
		const base = { app: APP, credential: await owner.token(), requestId }
		const grant = await requestDelegation(f.services, CALLER_ENV, f.ctx, { ...base, endpoint })
		if (!grant.ok) throw new Error('no delegation')
		return { ...base, delegation: grant.grant }
	}
	const created = await createScope(f.services, CALLER_ENV, f.ctx, { ...(await call(CREATE_ENDPOINT, 'req-create')), dimension: 'workspace' })
	if (!created.ok) throw new Error('no workspace')
	await assignMember(f.services, CALLER_ENV, f.ctx, {
		...(await call(INVITE_ENDPOINT, 'req-invite')),
		scope: created.scope,
		role: 'editor',
		member: { email: 'invitee@example.test' },
	})
	return { h, f, token: email.lastToken(), scope: created.scope }
}

function accept(token: string, headers: Record<string, string> = {}): Request {
	return new Request(`${ORIGIN}/auth/invitations/accept`, {
		method: 'POST',
		headers: { Origin: 'null', 'Sec-Fetch-Site': 'same-origin', 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
		body: new URLSearchParams({ token }),
	})
}

async function signedIn(i: Invited, name: string): Promise<{ id: string; cookie: string }> {
	const person = await i.f.person(name)
	return { id: person.id, cookie: `${SESSION_COOKIE}=${await i.h.signSession(person.id)}` }
}

const send = (i: Invited, request: Request): Promise<Response> => handleAuth(request, i.f.services, CALLER_ENV, i.f.ctx)

describe('/auth/invitations/accept', () => {
	test('the link opens a form that takes its token from the fragment', async () => {
		const i = await invited()
		const page = await send(i, new Request(`${ORIGIN}/auth/invitations/accept`))
		expect(page.status).toBe(200)
		const html = await page.text()
		expect(html).toContain('id="action-token"')
		expect(html).toContain("getElementById('action-token')")
		expect(page.headers.get('referrer-policy')).toBe('no-referrer')
	})

	test('the invited mailbox owner, signed in here, accepts once', async () => {
		const i = await invited()
		const invitee = await signedIn(i, 'invitee')
		const response = await send(i, accept(i.token, { Cookie: invitee.cookie }))
		expect(response.status).toBe(200)
		expect(await response.text()).toContain('Invitation accepted')
		expect((await i.f.repositories.membership.listRoleGrantsAt(APP, invitee.id, i.scope)).map((grant) => grant.role_key)).toEqual(['editor'])
		expect((await send(i, accept(i.token, { Cookie: invitee.cookie }))).status).toBe(400)
	})

	test('another signed-in principal cannot accept with the link', async () => {
		const i = await invited()
		const colleague = await signedIn(i, 'colleague')
		const response = await send(i, accept(i.token, { Cookie: colleague.cookie }))
		expect(response.status).toBe(403)
		expect(await response.text()).not.toContain('invitee@example.test')
	})

	test('without a session the page asks to sign in and accepts nothing', async () => {
		const i = await invited()
		const response = await send(i, accept(i.token))
		expect(response.status).toBe(401)
		expect(await response.text()).toContain('/auth/login?redirect=')
	})

	test("without a session, an application's landing is not the sign-in: IAM's own sign-in comes back and resumes", async () => {
		const i = await invited()
		// The application has a registered origin; before, "Sign in" led there, its proxy refused the browser without the
		// role, and the invitation stayed open.
		await i.f.repositories.handoff.setReturnOrigins(APP, ['https://app.example.test'])
		const response = await send(i, accept(i.token))
		expect(response.status).toBe(401)
		const html = await response.text()
		expect(html).toContain(`${ORIGIN}/auth/login?redirect=`)
		expect(html).not.toContain('href="https://app.example.test')
		// The token rides in the page for the script to keep in sessionStorage, never in the sign-in URL.
		expect(html).toContain(`id="resume-invitation" type="hidden" value="${i.token}"`)
		expect(html).not.toContain(`redirect=${encodeURIComponent(i.token)}`)
		expect(html.split('/auth/login?redirect=')[1]?.split('"')[0]).not.toContain(i.token)
		expect(html).toContain("sessionStorage.setItem('fabrika.invitation'")
		expect(await i.f.repositories.membership.listRoleGrantsAt(APP, (await i.f.person('invitee')).id, i.scope)).toEqual([])
	})

	test('the invitation page resubmits a kept token once, and a fresh link replaces it', async () => {
		const i = await invited()
		const html = await (await send(i, new Request(`${ORIGIN}/auth/invitations/accept`))).text()
		expect(html).toContain('id="invitation-form"')
		expect(html).toContain("sessionStorage.getItem('fabrika.invitation')")
		expect(html).toContain("sessionStorage.removeItem('fabrika.invitation');actionToken.value=kept;invitationForm.submit()")
	})

	test('a cross-site post and a malformed token are refused', async () => {
		const i = await invited()
		const invitee = await signedIn(i, 'invitee')
		expect((await send(i, accept(i.token, { Cookie: invitee.cookie, 'Sec-Fetch-Site': 'cross-site' }))).status).toBe(403)
		expect((await send(i, accept('short', { Cookie: invitee.cookie }))).status).toBe(400)
		expect(await i.f.repositories.membership.listRoleGrantsAt(APP, invitee.id, i.scope)).toEqual([])
	})
})
