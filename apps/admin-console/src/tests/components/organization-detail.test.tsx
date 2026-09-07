import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	act,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import OrganizationDetailPage from "@/app/(admin)/organizations/[id]/page";

const mocks = vi.hoisted(() => ({
	request: vi.fn(),
	error: vi.fn(),
	read: vi.fn(),
	orgId: "org-1",
}));
vi.mock("next/navigation", () => ({
	useParams: () => ({ id: mocks.orgId }),
	useRouter: () => ({ push: vi.fn() }),
}));
vi.mock("@/components/role-guard", () => ({
	RoleGuard: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@/lib/i18n/i18n-context", () => ({
	useI18n: () => ({ t: (key: string) => key }),
}));
vi.mock("sonner", () => ({ toast: { error: mocks.error, success: vi.fn() } }));
vi.mock("@/lib/client-api", () => ({
	fetchAdminResponse: mocks.request,
	fetchAdminJson: mocks.read,
}));

beforeEach(() => {
	vi.clearAllMocks();
	mocks.orgId = "org-1";
	mocks.read.mockImplementation(async (path: string) => {
		const url = new URL(path, "https://admin.test");
		return {
			data: url.pathname.endsWith("/teams")
				? { teams: [{ id: "team-1", name: "Platform" }] }
				: url.pathname.endsWith("/members")
					? { members: [], total: 25 }
					: { name: "Example", slug: "example", invitations: [] },
		};
	});
});
const renderPage = () => {
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	return render(
		<QueryClientProvider client={client}>
			<OrganizationDetailPage />
		</QueryClientProvider>,
	);
};

/** @see https://tanstack.com/query/latest/docs/framework/react/guides/mutations */
it.each([
	{
		input: "organizations.teamName",
		action: "organizations.createTeam",
		error: "toast.createFailed",
	},
	{
		input: "organizations.teamMemberUserId",
		action: "organizations.addMember",
		error: "toast.actionFailed",
	},
])("retains $input on transport failure and prevents duplicate submissions", async ({
	input,
	action,
	error,
}) => {
	let rejectRequest: (reason: Error) => void = () => {};
	mocks.request.mockImplementationOnce(
		() =>
			new Promise<Response>((_resolve, reject) => {
				rejectRequest = reject;
			}),
	);
	renderPage();
	await screen.findByText("Platform");
	fireEvent.change(screen.getByPlaceholderText(input), {
		target: { value: "draft-value" },
	});
	fireEvent.click(screen.getByRole("button", { name: action }));
	await waitFor(() =>
		expect(screen.getByRole("button", { name: action })).toBeDisabled(),
	);
	await act(async () => rejectRequest(new Error("Network unavailable")));
	await waitFor(() => expect(mocks.error).toHaveBeenCalledWith(error));
	expect(screen.getByPlaceholderText(input)).toHaveValue("draft-value");
	expect(screen.getByRole("button", { name: action })).toBeEnabled();
	mocks.request.mockResolvedValueOnce(new Response("{}", { status: 200 }));
	fireEvent.click(screen.getByRole("button", { name: action }));
	await waitFor(() =>
		expect(screen.getByPlaceholderText(input)).toHaveValue(""),
	);
	expect(mocks.request).toHaveBeenCalledTimes(2);
});

it("keeps an organization edit open after a network failure so it can be retried", async () => {
	let rejectRequest: (reason: Error) => void = () => {};
	mocks.request.mockImplementationOnce(
		() =>
			new Promise<Response>((_resolve, reject) => {
				rejectRequest = reject;
			}),
	);
	renderPage();
	await screen.findByText("Example");
	fireEvent.click(
		screen.getByRole("button", { name: "organizations.editOrg" }),
	);
	fireEvent.change(screen.getByLabelText("organizations.orgName"), {
		target: { value: "New name" },
	});
	fireEvent.click(screen.getByRole("button", { name: "organizations.save" }));
	await waitFor(() =>
		expect(
			screen.getByRole("button", { name: "organizations.save" }),
		).toBeDisabled(),
	);
	await act(async () => rejectRequest(new Error("Network unavailable")));
	await waitFor(() =>
		expect(mocks.error).toHaveBeenCalledWith("toast.saveFailed"),
	);
	expect(screen.getByLabelText("organizations.orgName")).toHaveValue(
		"New name",
	);
	expect(screen.getByRole("dialog")).toBeVisible();
});

it("fetches the next member page instead of silently truncating the organization", async () => {
	renderPage();
	await screen.findByText("Example");
	fireEvent.click(await screen.findByRole("button", { name: "common.next" }));
	await waitFor(() =>
		expect(mocks.read).toHaveBeenCalledWith(
			"/api/admin/organizations/org-1/members?limit=20&offset=20",
		),
	);
});

/** @see https://tanstack.com/table/latest/docs/faq#pitfall-1-creating-new-columns-or-data-on-every-render */
it("remains responsive while the next member page is loading", async () => {
	let resolvePage: (value: { data: { members: []; total: number } }) => void =
		() => {};
	const originalRead = mocks.read.getMockImplementation()!;
	mocks.read.mockImplementation((path: string) =>
		path.includes("offset=20")
			? new Promise((resolve) => {
					resolvePage = resolve;
				})
			: originalRead(path),
	);
	renderPage();
	await screen.findByText("Example");
	fireEvent.click(await screen.findByRole("button", { name: "common.next" }));
	fireEvent.click(
		screen.getByRole("button", { name: "organizations.editOrg" }),
	);
	expect(screen.getByRole("dialog")).toBeVisible();
	await act(async () => resolvePage({ data: { members: [], total: 25 } }));
	expect(screen.getByRole("dialog")).toBeVisible();
});

it("discards organization drafts after navigating to a different organization", async () => {
	const view = renderPage();
	await screen.findByText("Platform");
	fireEvent.change(screen.getByPlaceholderText("organizations.teamName"), {
		target: { value: "Private draft" },
	});
	mocks.orgId = "org-2";
	view.rerender(
		<QueryClientProvider client={new QueryClient()}>
			<OrganizationDetailPage />
		</QueryClientProvider>,
	);
	await waitFor(() =>
		expect(screen.getByPlaceholderText("organizations.teamName")).toHaveValue(
			"",
		),
	);
});
