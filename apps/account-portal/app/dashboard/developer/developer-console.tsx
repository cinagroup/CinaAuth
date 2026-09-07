"use client";

import {
	AlertTriangle,
	Boxes,
	CalendarDays,
	Check,
	Copy,
	KeyRound,
	Loader2,
	Pencil,
	Plus,
	RefreshCw,
	ShieldCheck,
	Smartphone,
	Trash2,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { DashboardPageHeader } from "@/components/dashboard/dashboard-page-header";
import { useDashboardI18n } from "@/components/dashboard/use-dashboard-i18n";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
	DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import type { OAuthClientRecord } from "@/lib/auth";
import { authClient } from "@/lib/auth-client";
import { startAccountStepUp } from "@/lib/client-api";
import type { DashboardMessages } from "@/lib/dashboard-i18n";
import { formatDashboardMessage } from "@/lib/dashboard-i18n";
import type {
	DeveloperOAuthClient,
	DeveloperOAuthClientType,
	DeveloperOAuthConsent,
	DeveloperOAuthScope,
} from "@/lib/developer-console";
import {
	canRotateDeveloperSecret,
	DEVELOPER_OAUTH_SCOPES,
	formatDeveloperDate,
	parseDeveloperRedirectUris,
	toDeveloperOAuthClient,
	validateDeveloperClientName,
} from "@/lib/developer-console";
import { isSessionRecent } from "@/lib/security-center";
import { useServerSnapshotState } from "@/lib/use-server-snapshot-state";

type DeveloperConsoleProps = {
	currentSessionCreatedAt: string;
	emailVerified: boolean;
	initialClients: DeveloperOAuthClient[];
	initialConsents: DeveloperOAuthConsent[];
	dataUnavailable: {
		clients: boolean;
		consents: boolean;
	};
};

type ClientDraft = {
	name: string;
	type: DeveloperOAuthClientType;
	redirectUris: string;
	scopes: DeveloperOAuthScope[];
};

type SecretNotice = {
	clientId: string;
	secret: string;
	operation: "created" | "rotated";
};

const EMPTY_DRAFT: ClientDraft = {
	name: "",
	type: "web",
	redirectUris: "",
	scopes: ["openid", "profile", "email"],
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null;

const localizeDeveloperError = (error: string, messages: DashboardMessages) => {
	if (error.startsWith("Invalid redirect URI: ")) {
		return formatDashboardMessage(messages.redirectUriInvalid, {
			uri: error.slice("Invalid redirect URI: ".length),
		});
	}
	const localizedErrors: Record<string, string> = {
		"Add at least one redirect URI.": messages.redirectUriRequired,
		"A client can use at most 10 redirect URIs.": messages.redirectUriLimit,
		"Each redirect URI must be 2048 characters or less.":
			messages.redirectUriTooLong,
		"Redirect URIs cannot contain credentials or URL fragments.":
			messages.redirectUriCredentials,
		"Web callbacks require HTTPS on a non-loopback host.":
			messages.webCallbackHttps,
		"Native callbacks require non-loopback HTTPS, exact loopback HTTP, or an authority-free reverse-domain scheme.":
			messages.nativeCallbackInvalid,
		"Application name is required.": messages.applicationNameRequired,
		"Application name must be 100 characters or less.":
			messages.applicationNameTooLong,
	};
	return localizedErrors[error] ?? error;
};

const getApiError = (value: unknown, fallback: string) => {
	if (!isRecord(value)) return fallback;
	for (const field of ["message", "error_description", "error"] as const) {
		if (typeof value[field] === "string" && value[field]) return value[field];
	}
	return fallback;
};

const mutateAuth = async <T,>(
	path: string,
	body: unknown,
	httpFallback: string,
): Promise<T> => {
	const response = await fetch(path, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
		credentials: "include",
		cache: "no-store",
	});
	const text = await response.text();
	let payload: unknown = null;
	if (text) {
		try {
			payload = JSON.parse(text) as unknown;
		} catch {
			payload = text;
		}
	}
	if (!response.ok) {
		throw new Error(
			getApiError(
				payload,
				formatDashboardMessage(httpFallback, {
					status: String(response.status),
				}),
			),
		);
	}
	return payload as T;
};

const copyValue = async (
	value: string,
	label: string,
	messages: DashboardMessages,
) => {
	try {
		await navigator.clipboard.writeText(value);
		toast.success(formatDashboardMessage(messages.valueCopied, { label }));
	} catch {
		toast.error(formatDashboardMessage(messages.unableCopyValue, { label }));
	}
};

function ClientEditorFields({
	draft,
	onChange,
	editing,
}: {
	draft: ClientDraft;
	onChange: (draft: ClientDraft) => void;
	editing: boolean;
}) {
	const { messages } = useDashboardI18n();
	const toggleScope = (scope: DeveloperOAuthScope, checked: boolean) => {
		onChange({
			...draft,
			scopes: checked
				? [...new Set([...draft.scopes, scope])]
				: draft.scopes.filter((item) => item !== scope),
		});
	};

	return (
		<div className="grid gap-5 py-2">
			<div className="grid gap-2">
				<Label htmlFor={editing ? "edit-client-name" : "create-client-name"}>
					{messages.applicationName}
				</Label>
				<Input
					id={editing ? "edit-client-name" : "create-client-name"}
					maxLength={100}
					placeholder={messages.applicationNamePlaceholder}
					value={draft.name}
					onChange={(event) => onChange({ ...draft, name: event.target.value })}
				/>
			</div>
			<div className="grid gap-2">
				<Label>{messages.applicationType}</Label>
				<Select
					disabled={editing}
					value={draft.type}
					onValueChange={(value: DeveloperOAuthClientType) =>
						onChange({ ...draft, type: value })
					}
				>
					<SelectTrigger>
						<SelectValue />
					</SelectTrigger>
					<SelectContent>
						<SelectItem value="web">{messages.webServerApplication}</SelectItem>
						<SelectItem value="native">
							{messages.nativeDeviceApplication}
						</SelectItem>
					</SelectContent>
				</Select>
				<p className="text-xs text-muted-foreground">
					{draft.type === "web"
						? messages.confidentialClientDescription
						: messages.publicPkceClientDescription}
				</p>
			</div>
			<div className="grid gap-2">
				<Label
					htmlFor={editing ? "edit-redirect-uris" : "create-redirect-uris"}
				>
					{messages.redirectUris}
				</Label>
				<Textarea
					id={editing ? "edit-redirect-uris" : "create-redirect-uris"}
					className="min-h-28 font-mono text-xs"
					placeholder={
						draft.type === "web"
							? "https://app.example.com/oauth/callback"
							: "cinaapp://oauth/callback"
					}
					value={draft.redirectUris}
					onChange={(event) =>
						onChange({ ...draft, redirectUris: event.target.value })
					}
				/>
				<p className="text-xs text-muted-foreground">
					{messages.redirectUrisHint}
				</p>
			</div>
			<div className="grid gap-3">
				<Label>{messages.allowedScopes}</Label>
				<div className="grid gap-3 sm:grid-cols-2">
					{DEVELOPER_OAUTH_SCOPES.map((scope) => (
						<label key={scope} className="flex items-start gap-3 text-sm">
							<Checkbox
								checked={draft.scopes.includes(scope)}
								onCheckedChange={(checked) =>
									toggleScope(scope, checked === true)
								}
							/>
							<span>
								<span className="font-mono">{scope}</span>
								{scope === "offline_access" ? (
									<span className="block text-xs text-muted-foreground">
										{messages.refreshTokensEnabled}
									</span>
								) : null}
							</span>
						</label>
					))}
				</div>
			</div>
		</div>
	);
}

export function DeveloperConsole({
	currentSessionCreatedAt,
	emailVerified,
	initialClients,
	initialConsents,
	dataUnavailable,
}: DeveloperConsoleProps) {
	const { locale, messages } = useDashboardI18n();
	const [clients, setClients] = useServerSnapshotState(initialClients);
	const [consents, setConsents] = useServerSnapshotState(initialConsents);
	const [createOpen, setCreateOpen] = useState(false);
	const [draft, setDraft] = useState<ClientDraft>(EMPTY_DRAFT);
	const [editingClient, setEditingClient] =
		useState<DeveloperOAuthClient | null>(null);
	const [busyAction, setBusyAction] = useState<string | null>(null);
	const [secretNotice, setSecretNotice] = useState<SecretNotice | null>(null);
	const [secretAcknowledged, setSecretAcknowledged] = useState(false);
	const recentAuthentication = isSessionRecent(currentSessionCreatedAt);
	const writesAllowed =
		emailVerified && recentAuthentication && !dataUnavailable.clients;

	const runAction = async (
		name: string,
		action: () => Promise<void>,
		fallback: string,
	) => {
		setBusyAction(name);
		try {
			await action();
		} catch (error) {
			toast.error(error instanceof Error ? error.message : fallback);
		} finally {
			setBusyAction(null);
		}
	};

	const reauthenticate = () =>
		runAction(
			"reauthenticate",
			() => startAccountStepUp(authClient),
			messages.unableFreshSignIn,
		);

	const validateDraft = () => {
		const nameResult = validateDeveloperClientName(draft.name);
		if (nameResult.error) {
			throw new Error(localizeDeveloperError(nameResult.error, messages));
		}
		const redirectResult = parseDeveloperRedirectUris(
			draft.redirectUris,
			draft.type,
		);
		if (redirectResult.error) {
			throw new Error(localizeDeveloperError(redirectResult.error, messages));
		}
		if (!draft.scopes.includes("openid")) {
			throw new Error(messages.openidScopeRequired);
		}
		return { name: nameResult.name, redirectUris: redirectResult.uris };
	};

	const showSecret = (
		clientId: string,
		secret: string,
		operation: SecretNotice["operation"],
	) => {
		setSecretAcknowledged(false);
		setSecretNotice({ clientId, secret, operation });
	};

	const createClient = () =>
		runAction(
			"client:create",
			async () => {
				const validated = validateDraft();
				const response = await mutateAuth<OAuthClientRecord>(
					"/api/auth/oauth2/create-client",
					{
						client_name: validated.name,
						redirect_uris: validated.redirectUris,
						scope: draft.scopes.join(" "),
						token_endpoint_auth_method:
							draft.type === "native" ? "none" : "client_secret_basic",
						grant_types: draft.scopes.includes("offline_access")
							? ["authorization_code", "refresh_token"]
							: ["authorization_code"],
						response_types: ["code"],
						application_type: draft.type,
					},
					messages.httpError,
				);
				const client = toDeveloperOAuthClient(response);
				setClients((current) => [client, ...current]);
				setCreateOpen(false);
				setDraft(EMPTY_DRAFT);
				toast.success(messages.oauthClientCreated);
				if (response.client_secret) {
					showSecret(response.client_id, response.client_secret, "created");
				}
			},
			messages.unableCreateOauthClient,
		);

	const openEditor = (client: DeveloperOAuthClient) => {
		setEditingClient(client);
		setDraft({
			name: client.name,
			type: client.type === "native" ? "native" : "web",
			redirectUris: client.redirectUris.join("\n"),
			scopes: DEVELOPER_OAUTH_SCOPES.filter((scope) =>
				client.scopes.includes(scope),
			),
		});
	};

	const updateClient = () => {
		if (!editingClient) return;
		void runAction(
			`client:update:${editingClient.clientId}`,
			async () => {
				const validated = validateDraft();
				const response = await mutateAuth<OAuthClientRecord>(
					"/api/auth/oauth2/update-client",
					{
						client_id: editingClient.clientId,
						update: {
							client_name: validated.name,
							redirect_uris: validated.redirectUris,
							scope: [
								...editingClient.scopes.filter(
									(scope) =>
										!DEVELOPER_OAUTH_SCOPES.some(
											(managed) => managed === scope,
										),
								),
								...draft.scopes,
							].join(" "),
							// Only change refresh grants when their checkbox changes;
							// preserve grant types and response types outside this editor.
							...(draft.scopes.includes("offline_access") !==
							editingClient.scopes.includes("offline_access")
								? {
										grant_types: draft.scopes.includes("offline_access")
											? [
													...new Set([
														...editingClient.grantTypes,
														"refresh_token",
													]),
												]
											: editingClient.grantTypes.filter(
													(grant) => grant !== "refresh_token",
												),
									}
								: {}),
						},
					},
					messages.httpError,
				);
				const updated = toDeveloperOAuthClient(response);
				setClients((current) =>
					current.map((item) =>
						item.clientId === updated.clientId ? updated : item,
					),
				);
				setEditingClient(null);
				toast.success(messages.oauthClientUpdated);
			},
			messages.unableUpdateOauthClient,
		);
	};

	const rotateSecret = (client: DeveloperOAuthClient) =>
		runAction(
			`client:rotate:${client.clientId}`,
			async () => {
				const response = await mutateAuth<OAuthClientRecord>(
					"/api/auth/oauth2/client/rotate-secret",
					{ client_id: client.clientId },
					messages.httpError,
				);
				if (!response.client_secret) {
					throw new Error(messages.rotatedSecretMissing);
				}
				showSecret(client.clientId, response.client_secret, "rotated");
				toast.success(messages.clientSecretRotated);
			},
			messages.unableRotateClientSecret,
		);

	const deleteClient = (client: DeveloperOAuthClient) =>
		runAction(
			`client:delete:${client.clientId}`,
			async () => {
				await mutateAuth<null>(
					"/api/auth/oauth2/delete-client",
					{
						client_id: client.clientId,
					},
					messages.httpError,
				);
				setClients((current) =>
					current.filter((item) => item.clientId !== client.clientId),
				);
				setConsents((current) =>
					current.filter((item) => item.clientId !== client.clientId),
				);
				toast.success(messages.oauthClientDeleted);
			},
			messages.unableDeleteOauthClient,
		);

	const revokeConsent = (consent: DeveloperOAuthConsent) =>
		runAction(
			`consent:delete:${consent.id}`,
			async () => {
				await mutateAuth<null>(
					"/api/auth/oauth2/delete-consent",
					{
						id: consent.id,
					},
					messages.httpError,
				);
				setConsents((current) =>
					current.filter((item) => item.id !== consent.id),
				);
				toast.success(messages.consentRevoked);
			},
			messages.unableRevokeConsent,
		);

	return (
		<div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
			<DashboardPageHeader
				titleKey="developerTitle"
				descriptionKey="developerDescription"
			>
				<Dialog open={createOpen} onOpenChange={setCreateOpen}>
					<DialogTrigger asChild>
						<Button disabled={!writesAllowed}>
							<Plus className="mr-2 h-4 w-4" /> {messages.createClient}
						</Button>
					</DialogTrigger>
					<DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
						<DialogHeader>
							<DialogTitle>{messages.createOauthClient}</DialogTitle>
							<DialogDescription>
								{messages.createOauthClientDescription}
							</DialogDescription>
						</DialogHeader>
						<ClientEditorFields
							draft={draft}
							onChange={setDraft}
							editing={false}
						/>
						<DialogFooter>
							<Button
								disabled={busyAction === "client:create"}
								onClick={() => void createClient()}
							>
								{busyAction === "client:create" ? (
									<Loader2 className="mr-2 h-4 w-4 animate-spin" />
								) : null}
								{messages.createClient}
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>
			</DashboardPageHeader>

			{!emailVerified || !recentAuthentication || dataUnavailable.clients ? (
				<Alert variant="destructive">
					<AlertTriangle className="h-4 w-4" />
					<AlertTitle>{messages.oauthChangesLocked}</AlertTitle>
					<AlertDescription className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
						<span>
							{!emailVerified
								? messages.verifyEmailForDeveloper
								: !recentAuthentication
									? messages.freshSessionForOauth
									: messages.oauthClientListUnavailable}
						</span>
						{emailVerified && !recentAuthentication ? (
							<Button
								className="shrink-0"
								disabled={busyAction === "reauthenticate"}
								onClick={() => void reauthenticate()}
								size="sm"
								variant="outline"
							>
								<RefreshCw className="mr-2 h-4 w-4" /> {messages.signInAgain}
							</Button>
						) : null}
					</AlertDescription>
				</Alert>
			) : (
				<Alert>
					<ShieldCheck className="h-4 w-4" />
					<AlertTitle>{messages.protectedDeveloperAccess}</AlertTitle>
					<AlertDescription>
						{messages.protectedDeveloperAccessDescription}
					</AlertDescription>
				</Alert>
			)}

			<Card>
				<CardHeader className="flex flex-row items-start justify-between gap-4">
					<div>
						<CardTitle className="flex items-center gap-2">
							<Boxes className="h-5 w-5" /> {messages.oauthApplications}
						</CardTitle>
						<CardDescription>
							{messages.oauthApplicationsDescription}
						</CardDescription>
					</div>
					<Badge variant="secondary">{clients.length}</Badge>
				</CardHeader>
				<CardContent className="grid gap-4">
					{clients.length === 0 ? (
						<div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
							{dataUnavailable.clients
								? messages.oauthApplicationDataUnavailable
								: messages.noOauthApplications}
						</div>
					) : (
						clients.map((client) => (
							<div
								key={client.clientId}
								className="grid gap-4 rounded-lg border p-4"
							>
								<div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
									<div className="min-w-0">
										<div className="flex flex-wrap items-center gap-2">
											<h3 className="font-medium">{client.name}</h3>
											<Badge variant={client.public ? "secondary" : "default"}>
												{client.public
													? messages.publicPkce
													: messages.confidential}
											</Badge>
											<Badge variant="outline">{client.type}</Badge>
											{client.disabled ? (
												<Badge variant="destructive">{messages.disabled}</Badge>
											) : null}
										</div>
										<div className="mt-2 flex min-w-0 items-center gap-2">
											<code className="truncate rounded bg-muted px-2 py-1 text-xs">
												{client.clientId}
											</code>
											<Button
												aria-label={messages.copyClientId}
												onClick={() =>
													void copyValue(
														client.clientId,
														messages.clientId,
														messages,
													)
												}
												size="icon"
												variant="ghost"
											>
												<Copy className="h-4 w-4" />
											</Button>
										</div>
									</div>
									<div className="flex flex-wrap gap-2">
										<Button
											disabled={!writesAllowed}
											onClick={() => openEditor(client)}
											size="sm"
											variant="outline"
										>
											<Pencil className="mr-2 h-4 w-4" /> {messages.edit}
										</Button>
										{canRotateDeveloperSecret(client) ? (
											<AlertDialog>
												<AlertDialogTrigger asChild>
													<Button
														disabled={!writesAllowed}
														size="sm"
														variant="outline"
													>
														<KeyRound className="mr-2 h-4 w-4" />{" "}
														{messages.rotateSecret}
													</Button>
												</AlertDialogTrigger>
												<AlertDialogContent>
													<AlertDialogHeader>
														<AlertDialogTitle>
															{messages.rotateClientSecretTitle}
														</AlertDialogTitle>
														<AlertDialogDescription>
															{messages.rotateClientSecretDescription}
														</AlertDialogDescription>
													</AlertDialogHeader>
													<AlertDialogFooter>
														<AlertDialogCancel>
															{messages.cancel}
														</AlertDialogCancel>
														<AlertDialogAction
															onClick={() => void rotateSecret(client)}
														>
															{messages.rotateSecret}
														</AlertDialogAction>
													</AlertDialogFooter>
												</AlertDialogContent>
											</AlertDialog>
										) : null}
										<AlertDialog>
											<AlertDialogTrigger asChild>
												<Button
													disabled={!writesAllowed}
													size="sm"
													variant="destructive"
												>
													<Trash2 className="mr-2 h-4 w-4" /> {messages.delete}
												</Button>
											</AlertDialogTrigger>
											<AlertDialogContent>
												<AlertDialogHeader>
													<AlertDialogTitle>
														{formatDashboardMessage(
															messages.deleteClientTitle,
															{ name: client.name },
														)}
													</AlertDialogTitle>
													<AlertDialogDescription>
														{messages.deleteClientDescription}
													</AlertDialogDescription>
												</AlertDialogHeader>
												<AlertDialogFooter>
													<AlertDialogCancel>
														{messages.cancel}
													</AlertDialogCancel>
													<AlertDialogAction
														className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
														onClick={() => void deleteClient(client)}
													>
														{messages.deleteClient}
													</AlertDialogAction>
												</AlertDialogFooter>
											</AlertDialogContent>
										</AlertDialog>
									</div>
								</div>
								<div className="grid gap-3 text-sm lg:grid-cols-2">
									<div>
										<p className="font-medium">{messages.redirectUris}</p>
										<div className="mt-1 grid gap-1">
											{client.redirectUris.map((uri) => (
												<code
													key={uri}
													className="break-all text-xs text-muted-foreground"
												>
													{uri}
												</code>
											))}
										</div>
									</div>
									<div>
										<p className="font-medium">{messages.scopes}</p>
										<div className="mt-1 flex flex-wrap gap-1">
											{client.scopes.map((scope) => (
												<Badge key={scope} variant="outline">
													{scope}
												</Badge>
											))}
										</div>
									</div>
								</div>
								{client.createdAt ? (
									<p className="flex items-center gap-2 text-xs text-muted-foreground">
										<CalendarDays className="h-3.5 w-3.5" />
										{formatDashboardMessage(messages.createdOn, {
											date: formatDeveloperDate(client.createdAt, locale),
										})}
									</p>
								) : null}
							</div>
						))
					)}
				</CardContent>
			</Card>

			<div className="grid gap-6 lg:grid-cols-2">
				<Card>
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<Smartphone className="h-5 w-5" /> {messages.deviceFlow}
						</CardTitle>
						<CardDescription>{messages.deviceFlowDescription}</CardDescription>
					</CardHeader>
					<CardContent className="grid gap-4 text-sm">
						<p>{messages.deviceFlowClientRequirement}</p>
						<div className="grid gap-2">
							<div>
								<span className="text-muted-foreground">
									{messages.deviceCode}
								</span>
								<code className="mt-1 block break-all rounded bg-muted p-2 text-xs">
									https://auth.cinaseek.ai/api/auth/device/code
								</code>
							</div>
							<div>
								<span className="text-muted-foreground">
									{messages.tokenExchange}
								</span>
								<code className="mt-1 block break-all rounded bg-muted p-2 text-xs">
									https://auth.cinaseek.ai/api/auth/device/token
								</code>
							</div>
							<div>
								<span className="text-muted-foreground">
									{messages.userVerification}
								</span>
								<code className="mt-1 block break-all rounded bg-muted p-2 text-xs">
									https://accounts.cinaseek.ai/device
								</code>
							</div>
						</div>
						<Alert>
							<ShieldCheck className="h-4 w-4" />
							<AlertDescription>
								{messages.deviceFlowSecretWarning}
							</AlertDescription>
						</Alert>
					</CardContent>
				</Card>

				<Card>
					<CardHeader className="flex flex-row items-start justify-between gap-4">
						<div>
							<CardTitle className="flex items-center gap-2">
								<Check className="h-5 w-5" /> {messages.yourConsentGrants}
							</CardTitle>
							<CardDescription>
								{messages.yourConsentGrantsDescription}
							</CardDescription>
						</div>
						<Badge variant="secondary">{consents.length}</Badge>
					</CardHeader>
					<CardContent className="grid gap-3">
						{consents.length === 0 ? (
							<p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
								{dataUnavailable.consents
									? messages.consentDataUnavailable
									: messages.noActiveConsentGrants}
							</p>
						) : (
							consents.map((consent) => {
								const client = clients.find(
									(item) => item.clientId === consent.clientId,
								);
								return (
									<div
										key={consent.id}
										className="grid gap-3 rounded-lg border p-4"
									>
										<div className="flex items-start justify-between gap-3">
											<div className="min-w-0">
												<p className="font-medium">
													{client?.name ?? messages.oauthApplication}
												</p>
												<code className="block truncate text-xs text-muted-foreground">
													{consent.clientId}
												</code>
											</div>
											<AlertDialog>
												<AlertDialogTrigger asChild>
													<Button
														disabled={
															!recentAuthentication || dataUnavailable.consents
														}
														size="sm"
														variant="outline"
													>
														{messages.revoke}
													</Button>
												</AlertDialogTrigger>
												<AlertDialogContent>
													<AlertDialogHeader>
														<AlertDialogTitle>
															{messages.revokeConsentTitle}
														</AlertDialogTitle>
														<AlertDialogDescription>
															{messages.revokeConsentDescription}
														</AlertDialogDescription>
													</AlertDialogHeader>
													<AlertDialogFooter>
														<AlertDialogCancel>
															{messages.cancel}
														</AlertDialogCancel>
														<AlertDialogAction
															onClick={() => void revokeConsent(consent)}
														>
															{messages.revokeConsent}
														</AlertDialogAction>
													</AlertDialogFooter>
												</AlertDialogContent>
											</AlertDialog>
										</div>
										<div className="flex flex-wrap gap-1">
											{consent.scopes.map((scope) => (
												<Badge key={scope} variant="outline">
													{scope}
												</Badge>
											))}
										</div>
										<p className="text-xs text-muted-foreground">
											{formatDashboardMessage(messages.grantedOn, {
												date: formatDeveloperDate(consent.createdAt, locale),
											})}
										</p>
									</div>
								);
							})
						)}
					</CardContent>
				</Card>
			</div>

			<Dialog
				open={editingClient !== null}
				onOpenChange={(open) => !open && setEditingClient(null)}
			>
				<DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
					<DialogHeader>
						<DialogTitle>{messages.editOauthClient}</DialogTitle>
						<DialogDescription>
							{messages.editOauthClientDescription}
						</DialogDescription>
					</DialogHeader>
					<ClientEditorFields draft={draft} onChange={setDraft} editing />
					<DialogFooter>
						<Button
							disabled={
								!editingClient || busyAction?.startsWith("client:update:")
							}
							onClick={updateClient}
						>
							{busyAction?.startsWith("client:update:") ? (
								<Loader2 className="mr-2 h-4 w-4 animate-spin" />
							) : null}
							{messages.saveChanges}
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>

			<Dialog
				open={secretNotice !== null}
				onOpenChange={(open) => {
					if (!open && secretAcknowledged) {
						setSecretNotice(null);
						setSecretAcknowledged(false);
					}
				}}
			>
				<DialogContent
					className="sm:max-w-xl"
					onEscapeKeyDown={(event) =>
						!secretAcknowledged && event.preventDefault()
					}
					onPointerDownOutside={(event) =>
						!secretAcknowledged && event.preventDefault()
					}
				>
					<DialogHeader>
						<DialogTitle>{messages.copyClientSecretNow}</DialogTitle>
						<DialogDescription>
							{messages.copyClientSecretDescription}
						</DialogDescription>
					</DialogHeader>
					{secretNotice ? (
						<div className="grid gap-4">
							<Alert variant="destructive">
								<AlertTriangle className="h-4 w-4" />
								<AlertDescription>
									{secretNotice.operation === "rotated"
										? `${messages.previousSecretInvalid} `
										: ""}
									{messages.clientSecretSafety}
								</AlertDescription>
							</Alert>
							<div className="grid gap-2">
								<Label>{messages.clientId}</Label>
								<div className="flex gap-2">
									<Input readOnly value={secretNotice.clientId} />
									<Button
										aria-label={messages.copyClientId}
										onClick={() =>
											void copyValue(
												secretNotice.clientId,
												messages.clientId,
												messages,
											)
										}
										size="icon"
										variant="outline"
									>
										<Copy className="h-4 w-4" />
									</Button>
								</div>
							</div>
							<div className="grid gap-2">
								<Label>{messages.clientSecret}</Label>
								<div className="flex gap-2">
									<Input
										className="font-mono"
										readOnly
										value={secretNotice.secret}
									/>
									<Button
										aria-label={messages.copyClientSecret}
										onClick={() =>
											void copyValue(
												secretNotice.secret,
												messages.clientSecret,
												messages,
											)
										}
										size="icon"
										variant="outline"
									>
										<Copy className="h-4 w-4" />
									</Button>
								</div>
							</div>
							<label className="flex items-start gap-3 text-sm">
								<Checkbox
									checked={secretAcknowledged}
									onCheckedChange={(checked) =>
										setSecretAcknowledged(checked === true)
									}
								/>
								<span>{messages.storedClientSecret}</span>
							</label>
						</div>
					) : null}
					<DialogFooter>
						<Button
							disabled={!secretAcknowledged}
							onClick={() => {
								setSecretNotice(null);
								setSecretAcknowledged(false);
							}}
						>
							{messages.done}
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</div>
	);
}
