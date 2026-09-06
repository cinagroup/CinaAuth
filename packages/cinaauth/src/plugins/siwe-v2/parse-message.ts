/** Fields extracted from a strictly validated EIP-4361 message. */
export interface ParsedSiweMessage {
	scheme?: string | undefined;
	domain?: string | undefined;
	address?: string | undefined;
	uri?: string | undefined;
	version?: string | undefined;
	chainId?: number | undefined;
	nonce?: string | undefined;
	issuedAt?: string | undefined;
	expirationTime?: string | undefined;
	notBefore?: string | undefined;
	requestId?: string | undefined;
	statement?: string | undefined;
	resources?: string[] | undefined;
}

export interface StrictParsedSiweMessage extends ParsedSiweMessage {
	domain: string;
	address: string;
	uri: string;
	version: "1";
	chainId: number;
	nonce: string;
	issuedAt: string;
}

const ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

/**
 * Normalizes a SIWE `domain` (RFC 3986 authority) for comparison: strips any
 * scheme and path, lowercases, leaving `host[:port]`.
 */
export function normalizeSiweDomain(domain: string): string {
	const withoutScheme = domain
		.trim()
		.toLowerCase()
		.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
	const pathStart = withoutScheme.indexOf("/");
	return pathStart === -1 ? withoutScheme : withoutScheme.slice(0, pathStart);
}

const STRICT_HEADER_REGEX =
	/^(?:([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)?([^\s/?#]+) wants you to sign in with your Ethereum account:$/;
const CHAIN_ID_REGEX = /^[1-9][0-9]*$/;
const NONCE_REGEX = /^[A-Za-z0-9]{8,}$/;
const RFC3339_REGEX =
	/^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

/** Parse an RFC 3339 timestamp without accepting JavaScript's loose date forms. */
export function parseSiweDateTime(value: string): number | null {
	const match = value.match(RFC3339_REGEX);
	if (!match) return null;
	const year = Number(match[1]);
	const month = Number(match[2]);
	const day = Number(match[3]);
	const hour = Number(match[4]);
	const minute = Number(match[5]);
	const second = Number(match[6]);
	const millisecond = Number((match[7] ?? "").padEnd(3, "0").slice(0, 3));
	if (
		month < 1 ||
		month > 12 ||
		day < 1 ||
		day > 31 ||
		hour > 23 ||
		minute > 59 ||
		second > 59
	) {
		return null;
	}

	const utc = new Date(0);
	utc.setUTCFullYear(year, month - 1, day);
	utc.setUTCHours(hour, minute, second, millisecond);
	if (
		utc.getUTCFullYear() !== year ||
		utc.getUTCMonth() !== month - 1 ||
		utc.getUTCDate() !== day ||
		utc.getUTCHours() !== hour ||
		utc.getUTCMinutes() !== minute ||
		utc.getUTCSeconds() !== second
	) {
		return null;
	}

	const offset = match[8];
	if (!offset) return null;
	if (offset === "Z" || offset === "z") return utc.getTime();
	const offsetHours = Number(offset.slice(1, 3));
	const offsetMinutes = Number(offset.slice(4, 6));
	if (offsetHours > 23 || offsetMinutes > 59) return null;
	const direction = offset[0] === "+" ? 1 : -1;
	return (
		utc.getTime() - direction * (offsetHours * 60 + offsetMinutes) * 60 * 1000
	);
}

function isValidUri(value: string): boolean {
	if (!value || /\s/.test(value)) return false;
	try {
		const uri = new URL(value);
		return !!uri.protocol;
	} catch {
		return false;
	}
}

function isValidAuthority(value: string): boolean {
	if (!value || value.includes("@")) return false;
	try {
		const parsed = new URL(`https://${value}`);
		return (
			!!parsed.hostname &&
			parsed.username === "" &&
			parsed.password === "" &&
			parsed.pathname === "/" &&
			parsed.search === "" &&
			parsed.hash === ""
		);
	} catch {
		return false;
	}
}

/**
 * Strictly parse the EIP-4361 ABNF shape and all fields used for authentication.
 * Unknown, duplicated, reordered, or malformed fields make the message invalid.
 */
export function parseSiweMessageStrict(
	message: string,
): StrictParsedSiweMessage | null {
	if (message.includes("\r") || message.endsWith("\n")) return null;
	const lines = message.split("\n");
	const header = lines[0]?.match(STRICT_HEADER_REGEX);
	if (!header || !isValidAuthority(header[2] ?? "")) return null;
	const address = lines[1];
	if (!address || !ADDRESS_REGEX.test(address)) return null;
	if (lines[2] !== "") return null;

	let cursor = 3;
	let statement: string | undefined;
	if (lines[cursor] !== "") {
		statement = lines[cursor];
		if (!statement) return null;
		cursor += 1;
	}
	if (lines[cursor] !== "") return null;
	cursor += 1;

	const take = (prefix: string): string | null => {
		const line = lines[cursor];
		if (!line?.startsWith(prefix)) return null;
		cursor += 1;
		return line.slice(prefix.length);
	};

	const uri = take("URI: ");
	const version = take("Version: ");
	const rawChainId = take("Chain ID: ");
	const nonce = take("Nonce: ");
	const issuedAt = take("Issued At: ");
	if (
		!uri ||
		!isValidUri(uri) ||
		version !== "1" ||
		!rawChainId ||
		!CHAIN_ID_REGEX.test(rawChainId) ||
		!nonce ||
		!NONCE_REGEX.test(nonce) ||
		!issuedAt ||
		parseSiweDateTime(issuedAt) === null
	) {
		return null;
	}
	const chainId = Number(rawChainId);
	if (!Number.isSafeInteger(chainId) || chainId <= 0) return null;

	let expirationTime: string | undefined;
	let notBefore: string | undefined;
	let requestId: string | undefined;
	if (lines[cursor]?.startsWith("Expiration Time: ")) {
		expirationTime = take("Expiration Time: ") ?? undefined;
		if (!expirationTime || parseSiweDateTime(expirationTime) === null)
			return null;
	}
	if (lines[cursor]?.startsWith("Not Before: ")) {
		notBefore = take("Not Before: ") ?? undefined;
		if (!notBefore || parseSiweDateTime(notBefore) === null) return null;
	}
	if (lines[cursor]?.startsWith("Request ID: ")) {
		requestId = take("Request ID: ") ?? undefined;
		if (requestId === undefined) return null;
	}

	let resources: string[] | undefined;
	if (lines[cursor] === "Resources:") {
		cursor += 1;
		resources = [];
		while (cursor < lines.length) {
			const line = lines[cursor];
			if (!line?.startsWith("- ")) return null;
			const resource = line.slice(2);
			if (!isValidUri(resource)) return null;
			resources.push(resource);
			cursor += 1;
		}
		if (resources.length === 0) return null;
	}
	if (cursor !== lines.length) return null;

	return {
		scheme: header[1],
		domain: header[2]!,
		address,
		statement,
		uri,
		version: "1",
		chainId,
		nonce,
		issuedAt,
		expirationTime,
		notBefore,
		requestId,
		resources,
	};
}
