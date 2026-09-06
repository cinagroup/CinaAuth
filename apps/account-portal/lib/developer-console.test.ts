import { describe, expect, it } from "vitest";
import {
	canRotateDeveloperSecret,
	parseDeveloperRedirectUris,
	toDeveloperOAuthClient,
	toDeveloperOAuthConsent,
	validateDeveloperClientName,
} from "./developer-console";

describe("developer console policy", () => {
	it("accepts HTTPS web callbacks", () => {
		expect(
			parseDeveloperRedirectUris(
				"https://app.example.com/oauth/callback",
				"web",
			),
		).toEqual({
			uris: ["https://app.example.com/oauth/callback"],
			error: null,
		});
	});

	it("accepts native custom schemes and removes duplicate callbacks", () => {
		expect(
			parseDeveloperRedirectUris(
				`com.cinagroup.app:/oauth/callback
com.cinagroup.app:/oauth/callback`,
				"native",
			),
		).toEqual({
			uris: ["com.cinagroup.app:/oauth/callback"],
			error: null,
		});
	});

	it("rejects insecure, credentialed, fragmented, and dangerous callbacks", () => {
		for (const callback of [
			"http://app.example.com/callback",
			"https://user:secret@app.example.com/callback",
			"https://app.example.com/callback#fragment",
			"javascript:alert(1)",
		]) {
			expect(parseDeveloperRedirectUris(callback, "web").error).not.toBeNull();
		}
	});

	it("validates client names without silently truncating them", () => {
		expect(validateDeveloperClientName("  Cina App  ")).toEqual({
			name: "Cina App",
			error: null,
		});
		expect(validateDeveloperClientName(" ").error).not.toBeNull();
		expect(validateDeveloperClientName("x".repeat(101)).error).not.toBeNull();
	});

	it("matches the 1.7 web and native redirect registration rules", () => {
		for (const uri of [
			"http://localhost:3000/callback",
			"https://127.0.0.1/callback",
			"https://localhost./callback",
		]) {
			expect(parseDeveloperRedirectUris(uri, "web").error).not.toBeNull();
		}
		for (const uri of [
			"cinaapp://oauth/callback",
			"com.cinagroup.app://oauth/callback",
			"http://127.1/callback",
			"https://localhost/callback",
			"com.cinagroup.app:/callback#",
		]) {
			expect(parseDeveloperRedirectUris(uri, "native").error).not.toBeNull();
		}
		for (const uri of [
			"http://localhost:3000/callback",
			"http://127.0.0.1:8080/callback",
			"http://[::1]:8080/callback",
			"com.cinagroup.app:/callback",
		]) {
			expect(parseDeveloperRedirectUris(uri, "native").error).toBeNull();
		}
	});

	it("maps canonical client metadata without removed public and type fields", () => {
		const source = {
			client_id: "native-client",
			redirect_uris: ["com.cinagroup.app:/callback"],
			token_endpoint_auth_method: "none" as const,
			application_type: "native" as const,
		};
		const client = toDeveloperOAuthClient(source);
		expect(client).toMatchObject({ public: true, type: "native" });
		expect(canRotateDeveloperSecret(client)).toBe(false);
	});

	it("maps OAuth records into serializable view models", () => {
		const client = toDeveloperOAuthClient({
			client_id: "client-1",
			client_name: "Cina App",
			client_id_issued_at: Date.parse("2026-08-10T00:00:00.000Z") / 1000,
			redirect_uris: ["https://app.example.com/callback"],
			scope: "openid profile",
			token_endpoint_auth_method: "client_secret_basic",
			grant_types: ["authorization_code"],
			response_types: ["code"],
			public: false,
			type: "web",
			disabled: false,
		});
		expect(client.createdAt).toBe("2026-08-10T00:00:00.000Z");
		expect(client.scopes).toEqual(["openid", "profile"]);
		expect(canRotateDeveloperSecret(client)).toBe(true);

		const consent = toDeveloperOAuthConsent({
			id: "consent-1",
			clientId: "client-1",
			userId: "user-1",
			scopes: ["openid"],
			createdAt: new Date("2026-08-10T00:00:00.000Z"),
			updatedAt: new Date("2026-08-10T00:05:00.000Z"),
		});
		expect(consent.createdAt).toBe("2026-08-10T00:00:00.000Z");
		expect(consent.updatedAt).toBe("2026-08-10T00:05:00.000Z");
	});

	it("does not offer shared-secret rotation for private-key clients", () => {
		expect(
			canRotateDeveloperSecret(
				toDeveloperOAuthClient({
					client_id: "private-key-client",
					redirect_uris: ["https://app.example.com/callback"],
					token_endpoint_auth_method: "private_key_jwt",
				}),
			),
		).toBe(false);
	});

	it("does not offer secret rotation for native public clients", () => {
		expect(
			canRotateDeveloperSecret(
				toDeveloperOAuthClient({
					client_id: "native-client",
					redirect_uris: ["cinaapp://oauth/callback"],
					token_endpoint_auth_method: "none",
					public: true,
					type: "native",
				}),
			),
		).toBe(false);
	});
});
