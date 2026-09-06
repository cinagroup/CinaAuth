import { describe, expect, it, vi } from "vitest";
import { getSecurityProviderLinkURL } from "./security-provider-actions";

const makeClient = () => ({
	linkSocial: vi.fn(async () => ({
		data: { url: "https://social.example.com/authorize" },
		error: null,
	})),
	oauth2: {
		link: vi.fn(async () => ({
			data: { url: "https://generic.example.com/authorize" },
			error: null,
		})),
	},
});

describe("security provider link actions", () => {
	it.each([
		"google",
		"github",
	] as const)("uses linkSocial for the %s social provider", async (providerId) => {
		const client = makeClient();

		await expect(
			getSecurityProviderLinkURL(client, {
				id: providerId,
				type: "social",
			}),
		).resolves.toBe("https://social.example.com/authorize");

		expect(client.linkSocial).toHaveBeenCalledWith({
			provider: providerId,
			callbackURL: "/dashboard/security",
			errorCallbackURL: "/dashboard/security?link=failed",
			disableRedirect: true,
		});
		expect(client.oauth2.link).not.toHaveBeenCalled();
	});

	it("uses the unified linkSocial API for a Generic OAuth provider", async () => {
		const client = makeClient();

		await expect(
			getSecurityProviderLinkURL(client, {
				id: "github-enterprise",
				type: "generic-oauth",
			}),
		).resolves.toBe("https://social.example.com/authorize");

		expect(client.linkSocial).toHaveBeenCalledWith({
			provider: "github-enterprise",
			callbackURL: "/dashboard/security",
			errorCallbackURL: "/dashboard/security?link=failed",
			disableRedirect: true,
		});
		expect(client.oauth2.link).not.toHaveBeenCalled();
	});

	it("fails closed when the provider does not return an authorization URL", async () => {
		const client: ReturnType<typeof makeClient> = {
			...makeClient(),
			linkSocial: vi.fn(async () => ({
				data: { url: "" },
				error: null,
			})),
		};

		await expect(
			getSecurityProviderLinkURL(client, {
				id: "enterprise-idp",
				type: "generic-oauth",
			}),
		).rejects.toThrow("Provider did not return a link URL");
	});
});
