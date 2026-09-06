import type { ImageProps } from "next/image";
import Image from "next/image";

type LogoProps = Omit<ImageProps, "src" | "alt" | "width" | "height"> & {
	size?: number;
};

export const Logo = ({ size = 28, ...props }: LogoProps) => (
	<Image
		src="/logo.png"
		alt="CinaSeek"
		width={size}
		height={size}
		priority
		{...props}
	/>
);
