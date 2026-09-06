import type * as React from "react";

import { cn } from "@/lib/utils";

// Spec: card-marketing — rounded-md (8px), p-6, shadow-l2 (stacked + inset hairline).
const Card = ({
	className,
	...props
}: React.HTMLAttributes<HTMLDivElement>) => (
	<div
		className={cn(
			"rounded-md bg-card text-card-foreground shadow-l2",
			className,
		)}
		{...props}
	/>
);
Card.displayName = "Card";

const CardHeader = ({
	className,
	...props
}: React.HTMLAttributes<HTMLDivElement>) => (
	<div className={cn("flex flex-col space-y-1.5 p-6", className)} {...props} />
);
CardHeader.displayName = "CardHeader";

const CardTitle = ({
	className,
	...props
}: React.HTMLAttributes<HTMLHeadingElement>) => (
	// Spec: display-sm (20/600/-0.6px) for card-level headings.
	<h3
		className={cn(
			"text-[20px] font-semibold leading-[28px] tracking-[-0.6px]",
			className,
		)}
		{...props}
	/>
);
CardTitle.displayName = "CardTitle";

const CardDescription = ({
	className,
	...props
}: React.HTMLAttributes<HTMLParagraphElement>) => (
	// Spec: body text uses --body (#4d4d4d) for secondary copy.
	<p className={cn("text-sm text-body", className)} {...props} />
);
CardDescription.displayName = "CardDescription";

const CardContent = ({
	className,
	...props
}: React.HTMLAttributes<HTMLDivElement>) => (
	<div className={cn("p-6 pt-0", className)} {...props} />
);
CardContent.displayName = "CardContent";

const CardFooter = ({
	className,
	...props
}: React.HTMLAttributes<HTMLDivElement>) => (
	<div className={cn("flex items-center p-6 pt-0", className)} {...props} />
);
CardFooter.displayName = "CardFooter";

export {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle,
};
