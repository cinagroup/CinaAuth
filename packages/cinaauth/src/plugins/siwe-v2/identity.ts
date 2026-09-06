import { toChecksumAddress } from "../../utils/hashing";

/** Return a canonical CAIP-10 identifier for an EVM account. */
export function toCaip10AccountId(address: string, chainId: number): string {
	if (!Number.isSafeInteger(chainId) || chainId <= 0) {
		throw new TypeError("chainId must be a positive safe integer");
	}
	return `eip155:${chainId}:${toChecksumAddress(address)}`;
}
