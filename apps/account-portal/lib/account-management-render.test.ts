// @vitest-environment happy-dom

import type { ComponentProps } from "react";
import { act, createElement } from "react";
import type { Root } from "react-dom/client";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeveloperConsole } from "@/app/dashboard/developer/developer-console";
import { OrganizationConsole } from "@/app/dashboard/organization/organization-console";
import { SecurityCenter } from "@/app/dashboard/security/security-center";
import { CORE_AUTH_CAPABILITIES } from "./auth-capabilities";
import { dashboardMessages } from "./dashboard-i18n";

const mocks = vi.hoisted(() => ({
	signOut: vi.fn(),
	push: vi.fn(),
	refresh: vi.fn(),
	error: vi.fn(),
	success: vi.fn(),
}));
vi.mock("next/navigation", () => ({
	useRouter: () => ({ push: mocks.push, refresh: mocks.refresh }),
}));
vi.mock("@/lib/auth-client", () => ({
	authClient: { signOut: mocks.signOut },
}));
vi.mock("sonner", () => ({
	toast: { error: mocks.error, success: mocks.success },
}));
vi.mock("@/components/dashboard/use-dashboard-i18n", () => ({
	useDashboardI18n: () => ({ locale: "en", messages: dashboardMessages.en }),
}));
vi.mock("@/components/forms/two-factor-disable-form", () => ({
	TwoFactorDisableForm: () => null,
}));
vi.mock("@/components/forms/two-factor-enable-form", () => ({
	TwoFactorEnableForm: () => null,
}));
vi.mock("@/components/wallet/reown-wallet-entry", () => ({
	ReownWalletEntry: () => null,
}));
vi.mock("@/lib/cinaauth-siwe-client", () => ({
	cinaAuthSiweProtocolClient: {},
}));
vi.mock("@/components/forms/create-organization-form", () => ({
	CreateOrganizationForm: () => null,
}));
vi.mock("@/components/forms/invite-member-form", () => ({
	InviteMemberForm: () => null,
}));
vi.mock("@/data/organization/invitation-cancel-mutation", () => ({
	useInvitationCancelMutation: () => ({}),
}));
vi.mock("@/data/organization/member-remove-mutation", () => ({
	useMemberRemoveMutation: () => ({}),
}));
vi.mock("@/data/organization/organization-active-mutation", () => ({
	useOrganizationActiveMutation: () => ({}),
}));
vi.mock("@/data/organization/organization-leave-mutation", () => ({
	useOrganizationLeaveMutation: () => ({}),
}));
vi.mock("@/app/dashboard/organization/advanced-organization-card", () => ({
	AdvancedMemberRoleEditor: () => null,
	AdvancedOrganizationCard: () => null,
}));
vi.mock("@/app/dashboard/organization/enterprise-connections-card", () => ({
	EnterpriseConnectionsCard: () => null,
}));
vi.mock("@/app/dashboard/organization/organization-audit-card", () => ({
	OrganizationAuditCard: () => null,
}));

const date = "2026-09-01T00:00:00.000Z";
const developerProps: ComponentProps<typeof DeveloperConsole> = {
	currentSessionCreatedAt: date,
	emailVerified: true,
	initialClients: [],
	initialConsents: [],
	dataUnavailable: { clients: false, consents: false },
};
const securityProps: ComponentProps<typeof SecurityCenter> = {
	user: {
		name: "Test account",
		email: "test@example.com",
		emailVerified: true,
		twoFactorEnabled: false,
	},
	currentSessionCreatedAt: date,
	initialSessions: [],
	initialAccounts: [],
	initialPasskeys: [],
	initialApiKeys: [],
	initialWallets: [],
	configuredProviders: [],
	walletCapabilities: CORE_AUTH_CAPABILITIES,
	walletCookie: null,
	providerLinkFailed: false,
	dataUnavailable: {
		sessions: false,
		accounts: false,
		passkeys: false,
		apiKeys: false,
		wallets: false,
	},
};
const organizationProps: ComponentProps<typeof OrganizationConsole> = {
	currentUser: {
		id: "user-1",
		name: "Test account",
		email: "test@example.com",
		image: null,
	},
	currentSessionCreatedAt: date,
	initialOrganizations: [],
	initialOrganization: null,
	initialTeams: [],
	initialDynamicRoles: [],
	initialEntitlements: null,
	entitlementsUnavailable: false,
	advancedOrganizationDataUnavailable: { teams: false, roles: false },
	initialAuditPage: { rows: [], total: 0, limit: 20, offset: 0 },
	auditUnavailable: false,
	initialSSOProviders: [],
	initialSCIMProviders: [],
	enterpriseDataUnavailable: { sso: false, scim: false },
	dataUnavailable: { organizations: false, organization: false },
};
const managementPage = (page: "security" | "developer" | "organization") =>
	page === "security"
		? createElement(SecurityCenter, securityProps)
		: page === "developer"
			? createElement(DeveloperConsole, developerProps)
			: createElement(OrganizationConsole, organizationProps);

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
	vi.clearAllMocks();
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.append(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

/** @see https://nextjs.org/docs/app/api-reference/functions/use-router#userouter */
describe("management pages after a server refresh", () => {
	/** @see https://github.com/cinagroup/cinaauth/blob/main/docs/content/docs/plugins/oauth-provider.mdx */
	it.each([
		{ operation: "save", initialOffline: false, toggle: false },
		{ operation: "enable offline access", initialOffline: false, toggle: true },
		{ operation: "disable offline access", initialOffline: true, toggle: true },
	])("preserves unrelated grants when editing a client: $operation", async ({
		initialOffline,
		toggle,
	}) => {
		const client = {
			client_id: "mixed-grants",
			client_name: "Mixed grants",
			redirect_uris: ["https://example.com/callback"],
			scope: initialOffline ? "openid offline_access" : "openid",
			token_endpoint_auth_method: "client_secret_basic",
			grant_types: ["authorization_code", "client_credentials"],
			response_types: ["code"],
			application_type: "web",
		};
		const request = vi
			.fn()
			.mockResolvedValue(
				Response.json({ ...client, client_name: "Saved application" }),
			);
		vi.stubGlobal("fetch", request);
		const props: ComponentProps<typeof DeveloperConsole> = {
			...developerProps,
			currentSessionCreatedAt: new Date().toISOString(),
			initialClients: [
				{
					clientId: client.client_id,
					name: client.client_name,
					createdAt: date,
					redirectUris: client.redirect_uris,
					scopes: client.scope.split(" "),
					tokenEndpointAuthMethod: "client_secret_basic",
					grantTypes: initialOffline
						? ["authorization_code", "client_credentials", "refresh_token"]
						: ["authorization_code", "client_credentials"],
					responseTypes: ["code"],
					public: false,
					type: "web",
					disabled: false,
				},
			],
		};
		await act(async () => root.render(createElement(DeveloperConsole, props)));
		const edit = Array.from(container.querySelectorAll("button")).find(
			(button) => button.textContent?.trim() === dashboardMessages.en.edit,
		)!;
		await act(async () => edit.click());
		if (toggle) {
			const offlineScope = Array.from(document.querySelectorAll("label"))
				.find((label) => label.textContent?.includes("offline_access"))!
				.querySelector<HTMLButtonElement>("[role=checkbox]")!;
			await act(async () => offlineScope.click());
		}
		const save = Array.from(document.querySelectorAll("button")).find(
			(button) =>
				button.textContent?.trim() === dashboardMessages.en.saveChanges,
		)!;
		await act(async () => save.click());
		expect(request).toHaveBeenCalledTimes(1);
		const body = JSON.parse(request.mock.calls[0]![1].body) as {
			update: {
				scope: string;
				grant_types?: string[];
				response_types?: string[];
			};
		};
		if (body.update.grant_types)
			expect(body.update.grant_types).toContain("client_credentials");
		expect(body.update.response_types).toBeUndefined();
		if (toggle) {
			expect(body.update.grant_types?.includes("refresh_token")).toBe(
				!initialOffline,
			);
			expect(body.update.scope.split(" ").includes("offline_access")).toBe(
				!initialOffline,
			);
		} else {
			expect(body.update.grant_types).toBeUndefined();
		}
		await act(async () => root.render(createElement(DeveloperConsole, props)));
		expect(container.textContent).toContain("Saved application");
		await act(async () =>
			root.render(
				createElement(DeveloperConsole, { ...props, initialClients: [] }),
			),
		);
		expect(container.textContent).not.toContain("Saved application");
	});

	it("replaces developer clients and consent grants with the new server snapshot", async () => {
		await act(async () =>
			root.render(createElement(DeveloperConsole, developerProps)),
		);
		await act(async () =>
			root.render(
				createElement(DeveloperConsole, {
					...developerProps,
					initialClients: [
						{
							clientId: "refreshed-client",
							name: "Recovered application",
							createdAt: date,
							redirectUris: ["https://example.com/callback"],
							scopes: ["openid"],
							tokenEndpointAuthMethod: "client_secret_basic",
							grantTypes: ["authorization_code"],
							responseTypes: ["code"],
							public: false,
							type: "web",
							disabled: false,
						},
					],
					initialConsents: [
						{
							id: "grant-1",
							clientId: "recovered-consent",
							userId: "user-1",
							referenceId: null,
							scopes: ["openid"],
							createdAt: date,
							updatedAt: date,
						},
					],
				}),
			),
		);
		expect(container.textContent).toContain("Recovered application");
		expect(container.textContent).toContain("recovered-consent");
		await act(async () =>
			root.render(
				createElement(DeveloperConsole, {
					...developerProps,
					initialClients: [],
					initialConsents: [],
				}),
			),
		);
		expect(container.textContent).not.toContain("Recovered application");
		expect(container.textContent).not.toContain("recovered-consent");
	});

	it("recovers security lists from a failed initial load after retry", async () => {
		await act(async () =>
			root.render(
				createElement(SecurityCenter, {
					...securityProps,
					dataUnavailable: {
						sessions: true,
						accounts: true,
						passkeys: true,
						apiKeys: true,
						wallets: true,
					},
				}),
			),
		);
		await act(async () =>
			root.render(
				createElement(SecurityCenter, {
					...securityProps,
					initialSessions: [
						{
							id: "session-1",
							token: "test-token",
							createdAt: date,
							expiresAt: "2027-01-01T00:00:00.000Z",
							ipAddress: "192.0.2.1",
							userAgent: null,
							isCurrent: false,
						},
					],
					initialAccounts: [
						{
							id: "account-1",
							accountId: "external-id",
							providerId: "github",
							createdAt: date,
						},
					],
					initialPasskeys: [
						{ id: "passkey-1", name: "Recovered passkey", createdAt: date },
					],
					initialApiKeys: [
						{
							id: "key-1",
							name: "Recovered key",
							start: "test_",
							enabled: true,
							rateLimitEnabled: false,
							rateLimitTimeWindow: null,
							rateLimitMax: null,
							requestCount: 0,
							lastRequest: null,
							expiresAt: null,
							createdAt: date,
							updatedAt: date,
						},
					],
					initialWallets: [
						{
							id: "wallet-1",
							address: "0x1234567890123456789012345678901234567890",
							chainId: 1,
							isPrimary: true,
							createdAt: date,
						},
					],
				}),
			),
		);
		for (const text of [
			"192.0.2.1",
			"Github",
			"Recovered passkey",
			"Recovered key",
			"0x1234",
		]) {
			expect(container.textContent).toContain(text);
		}
	});
});

/** @see https://github.com/cinagroup/cinaauth/blob/main/apps/account-portal/lib/client-api.ts */
describe("explicit security reauthentication", () => {
	it.each([
		"security",
		"developer",
		"organization",
	] as const)("stays on %s and reports a failed sign-out", async (page) => {
		mocks.signOut.mockResolvedValue({
			data: null,
			error: { message: "Sign-out unavailable" },
		});
		const assign = vi
			.spyOn(window.location, "assign")
			.mockImplementation(() => {});
		await act(async () => root.render(managementPage(page)));
		const button = Array.from(container.querySelectorAll("button")).find(
			(candidate) =>
				candidate.textContent?.includes(
					page === "security"
						? dashboardMessages.en.reauthenticate
						: dashboardMessages.en.signInAgain,
				),
		);
		expect(button).toBeTruthy();
		await act(async () => button!.click());
		expect(mocks.error).toHaveBeenCalled();
		expect(mocks.push).not.toHaveBeenCalled();
		expect(assign).not.toHaveBeenCalled();
	});
	it.each([
		"security",
		"developer",
		"organization",
	] as const)("starts explicit step-up from %s after successful sign-out", async (page) => {
		mocks.signOut.mockResolvedValue({ data: { success: true }, error: null });
		window.history.replaceState(
			null,
			"",
			`/dashboard/${page}?section=credentials`,
		);
		const assign = vi
			.spyOn(window.location, "assign")
			.mockImplementation(() => {});
		await act(async () => root.render(managementPage(page)));
		const button = Array.from(container.querySelectorAll("button")).find(
			(candidate) =>
				candidate.textContent?.includes(
					page === "security"
						? dashboardMessages.en.reauthenticate
						: dashboardMessages.en.signInAgain,
				),
		);
		await act(async () => button!.click());
		expect(assign).toHaveBeenCalledWith(
			`/sign-in?mode=step-up&callbackURL=${encodeURIComponent(`/dashboard/${page}?section=credentials`)}`,
		);
		expect(mocks.signOut).toHaveBeenCalledTimes(1);
	});
});
