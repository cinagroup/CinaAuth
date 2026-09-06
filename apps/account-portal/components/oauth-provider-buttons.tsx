"use client";

import { oneTapClient } from "cinaauth/client/plugins";
import { createAuthClient } from "cinaauth/react";
import { Github, KeyRound } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { useI18n } from "@/components/i18n-provider";
import { Button } from "@/components/ui/button";
import { FieldSeparator } from "@/components/ui/field";
import { useAuthCapabilities } from "@/hooks/use-auth-capabilities";
import { resolveAuthClientBaseURL } from "@/lib/auth-api";
import { formatOAuthProviderName } from "@/lib/auth-capabilities";
import { authClient } from "@/lib/auth-client";

export function OAuthProviderButtons({
	callbackURL,
}: {
	/**
	 * Post-login destination. Leave undefined during a signed OIDC
	 * authorization so the server-provided continuation URL (back to the
	 * relying party) wins over a local default such as /dashboard.
	 */
	callbackURL?: string;
}) {
	const { messages } = useI18n();
	const googleButtonMeasureRef = useRef<HTMLDivElement>(null);
	const googleButtonRef = useRef<HTMLDivElement>(null);
	const [googleButtonWidth, setGoogleButtonWidth] = useState<number>();
	const { data } = useAuthCapabilities();
	const providers = data?.oauthProviders ?? [];
	const oneTapReady =
		data?.oneTap === true && typeof data.oneTapClientId === "string";
	const googleOneTapClient = useMemo(
		() =>
			oneTapReady && data?.oneTapClientId
				? createAuthClient({
						baseURL: resolveAuthClientBaseURL(
							typeof window === "undefined"
								? undefined
								: window.location.origin,
						),
						plugins: [oneTapClient({ clientId: data.oneTapClientId })],
					})
				: null,
		[oneTapReady, data?.oneTapClientId],
	);
	const visibleProviders = providers.filter(
		(provider) =>
			!(oneTapReady && provider.type === "social" && provider.id === "google"),
	);

	useEffect(() => {
		const container = googleButtonMeasureRef.current;
		if (!oneTapReady || !container) return;
		const updateWidth = () => {
			const nextWidth = Math.min(Math.round(container.clientWidth), 400);
			if (nextWidth > 0) {
				setGoogleButtonWidth((current) =>
					current === nextWidth ? current : nextWidth,
				);
			}
		};
		updateWidth();
		const observer = new ResizeObserver(updateWidth);
		observer.observe(container);
		return () => observer.disconnect();
	}, [oneTapReady]);

	useEffect(() => {
		const container = googleButtonRef.current;
		if (!googleOneTapClient || !container || !googleButtonWidth) return;
		container.replaceChildren();
		void googleOneTapClient.oneTap({
			callbackURL,
			context: "signin",
			button: {
				container,
				config: {
					type: "standard",
					theme: "outline",
					size: "large",
					shape: "rectangular",
					text: "continue_with",
					width: googleButtonWidth,
				},
			},
			fetchOptions: {
				onError(error) {
					toast.error(error.error.message || messages.googleAuthFailed);
				},
			},
		});
		return () => container.replaceChildren();
	}, [callbackURL, googleButtonWidth, googleOneTapClient, messages]);

	if (visibleProviders.length === 0 && !oneTapReady) return null;

	return (
		<>
			<FieldSeparator>{messages.or}</FieldSeparator>
			{oneTapReady ? (
				<div
					ref={googleButtonMeasureRef}
					className="flex min-h-12 w-full items-center justify-center overflow-hidden"
					aria-label={`${messages.continueWith} Google`}
				>
					<div
						key={googleButtonWidth ?? "pending"}
						ref={googleButtonRef}
						className="flex w-full items-center justify-center"
					/>
				</div>
			) : null}
			{visibleProviders.map((provider) => (
				<Button
					key={provider.id}
					type="button"
					variant="outline"
					size="lg"
					className="relative flex h-auto min-h-12 w-full justify-center whitespace-normal px-3 py-3 text-center"
					onClick={() => {
						if (provider.type === "social") {
							void authClient.signIn.social({
								provider: provider.id,
								callbackURL,
							});
							return;
						}
						void authClient.signIn.social({
							provider: provider.id,
							callbackURL,
						});
					}}
				>
					{provider.id === "github" ? (
						<Github data-icon="inline-start" aria-hidden />
					) : (
						<KeyRound data-icon="inline-start" aria-hidden />
					)}
					<span>
						{messages.continueWith} {formatOAuthProviderName(provider.id)}
					</span>
				</Button>
			))}
		</>
	);
}
