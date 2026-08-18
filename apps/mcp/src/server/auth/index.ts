import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose"
import { sessionInfoSchema, type SessionInfo } from "../../shared/types"

const FETCH_TIMEOUT_MS = 30_000

export interface AuthUser {
	userId: string
	organizationId: string
	bearerToken: string
	oauthClientId?: string
	scopes: string[]
	expiresAt?: number
}

const remoteJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function authIssuer(apiUrl: string): string {
	return `${apiUrl.replace(/\/+$/, "")}/api/auth`
}

function getRemoteJwks(jwksUrl: string) {
	let keySet = remoteJwks.get(jwksUrl)
	if (!keySet) {
		keySet = createRemoteJWKSet(new URL(jwksUrl))
		remoteJwks.set(jwksUrl, keySet)
	}
	return keySet
}

export async function fetchSession(
	bearerToken: string,
	apiUrl: string,
): Promise<SessionInfo> {
	const response = await fetch(`${apiUrl.replace(/\/+$/, "")}/v3/session`, {
		method: "GET",
		headers: { Authorization: `Bearer ${bearerToken}` },
		signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
	})

	if (!response.ok) {
		throw Object.assign(
			new Error(`Session request failed with status ${response.status}`),
			{ status: response.status },
		)
	}

	const result = sessionInfoSchema.safeParse(await response.json())
	if (!result.success) {
		throw new Error("Invalid session response")
	}

	return result.data
}

async function apiKeysEqual(
	actual: string,
	expected: string,
): Promise<boolean> {
	const encoder = new TextEncoder()
	const [actualDigest, expectedDigest] = await Promise.all([
		crypto.subtle.digest("SHA-256", encoder.encode(actual)),
		crypto.subtle.digest("SHA-256", encoder.encode(expected)),
	])
	const actualBytes = new Uint8Array(actualDigest)
	const expectedBytes = new Uint8Array(expectedDigest)
	let difference = 0
	for (let index = 0; index < actualBytes.length; index++) {
		difference |= actualBytes[index] ^ expectedBytes[index]
	}
	return difference === 0
}

export async function validateLocalApiKey(
	token: string,
	configuredApiKey: string | undefined,
	apiUrl: string,
): Promise<AuthUser | null> {
	if (!configuredApiKey || !(await apiKeysEqual(token, configuredApiKey))) {
		return null
	}

	try {
		const session = await fetchSession(token, apiUrl)
		const organization = Reflect.get(session, "org")
		const organizationId =
			organization && typeof organization === "object"
				? Reflect.get(organization, "id")
				: undefined
		if (typeof organizationId !== "string" || organizationId.length === 0) {
			return null
		}

		return {
			userId: session.user.id,
			organizationId,
			bearerToken: token,
			scopes: ["local"],
		}
	} catch (error) {
		console.error("Local API key validation error:", error)
		return null
	}
}

export async function validateOAuthToken(
	token: string,
	apiUrl: string,
	audience: string,
	keySet?: JWTVerifyGetKey,
): Promise<AuthUser | null> {
	try {
		const issuer = authIssuer(apiUrl)
		const verifier = keySet ?? getRemoteJwks(`${issuer}/jwks`)
		const { payload } = await jwtVerify(token, verifier, {
			issuer,
			audience,
		})
		if (typeof payload.sub !== "string" || payload.sub.length === 0) {
			return null
		}
		if (
			typeof payload.organization_id !== "string" ||
			payload.organization_id.length === 0
		) {
			return null
		}

		const rawScopes = payload.scope ?? payload.scopes
		const scopes = Array.isArray(rawScopes)
			? rawScopes.filter((scope): scope is string => typeof scope === "string")
			: typeof rawScopes === "string"
				? rawScopes.split(/\s+/).filter(Boolean)
				: []

		return {
			userId: payload.sub,
			organizationId: payload.organization_id,
			bearerToken: token,
			oauthClientId:
				typeof payload.azp === "string"
					? payload.azp
					: typeof payload.client_id === "string"
						? payload.client_id
						: undefined,
			scopes,
			expiresAt: payload.exp,
		}
	} catch (error) {
		console.error("OAuth token validation error:", error)
		return null
	}
}
