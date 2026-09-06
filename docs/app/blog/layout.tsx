import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata } from "next";
import { createMetadata } from "@/lib/metadata";

const description = "Latest updates, articles, and insights about CinaAuth";

export const metadata: Metadata = createMetadata({
	title: "Blog",
	description,
	openGraph: {
		url: "/blog",
		title: "Blog - CinaAuth",
		description,
		images: ["/api/og-release?heading=Better%20Auth%20Blog"],
	},
	twitter: {
		images: ["/api/og-release?heading=Better%20Auth%20Blog"],
		title: "Blog - CinaAuth",
		description,
	},
	alternates: {
		types: {
			"application/rss+xml": [
				{
					title: "CinaAuth Blog",
					url: "https://cinagroup.com/blog/rss.xml",
				},
			],
		},
	},
});

export default function BlogLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return (
		<RootProvider theme={{ enabled: false }}>
			<div className="relative flex min-h-screen flex-col">
				<main className="flex-1">{children}</main>
			</div>
		</RootProvider>
	);
}
