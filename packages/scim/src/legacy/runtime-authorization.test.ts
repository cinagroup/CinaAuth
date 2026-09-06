import { sso } from "@cinaauth/sso";
import { APIError } from "cinaauth/api";
import { organization } from "cinaauth/plugins";
import { getTestInstance } from "cinaauth/test";
import { describe, expect, it } from "vitest";
import { scim } from ".";

describe("SCIM runtime authorization", () => {
	it("runs only after token verification and denies the provider", async () => {
		let authorizedProviderId: string | undefined;
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				sso(),
				scim({
					authorizeProvider: ({ provider }) => {
						authorizedProviderId = provider.providerId;
						expect("scimToken" in provider).toBe(false);
						return false;
					},
				}),
				organization(),
			],
		});
		const { headers } = await signInWithTestUser();
		const { scimToken } = await auth.api.generateSCIMToken({
			body: { providerId: "blocked-provider" },
			headers,
		});

		const response = await auth.api.listSCIMUsers({
			headers: { authorization: `Bearer ${scimToken}` },
			asResponse: true,
		});
		expect(response.status).toBe(403);
		expect(authorizedProviderId).toBe("blocked-provider");
	});

	it("wraps organization member provisioning and returns a SCIM conflict when capacity is denied", async () => {
		let provisionCalled = false;
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				sso(),
				scim({
					withOrganizationMemberProvisioning: async (payload, _provision) => {
						expect(payload.organizationId).toBeTruthy();
						expect("scimToken" in payload.provider).toBe(false);
						provisionCalled = true;
						throw new APIError("CONFLICT", {
							code: "ENTITLEMENT_LIMIT_REACHED",
							message: "Organization member limit reached",
						});
					},
				}),
				organization(),
			],
		});
		const { headers } = await signInWithTestUser();
		const organizationValue = await auth.api.createOrganization({
			body: { name: "Capacity Test", slug: "capacity-test" },
			headers,
		});
		const { scimToken } = await auth.api.generateSCIMToken({
			body: {
				providerId: "capacity-provider",
				organizationId: organizationValue?.id,
			},
			headers,
		});

		const response = await auth.api.createSCIMUser({
			body: { userName: "new-member@example.com" },
			headers: { authorization: `Bearer ${scimToken}` },
			asResponse: true,
		});
		expect(response.status).toBe(409);
		await expect(response.json()).resolves.toMatchObject({
			schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
			status: "409",
			code: "ENTITLEMENT_LIMIT_REACHED",
			detail: "Organization member limit reached",
		});
		expect(provisionCalled).toBe(true);
	});
});
