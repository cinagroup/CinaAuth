"use client";

import { useState } from "react";

/** Keeps local mutations until a refreshed server snapshot replaces the data. */
export function useServerSnapshotState<T>(snapshot: T) {
	const [source, setSource] = useState(() => snapshot);
	const [value, setValue] = useState(() => snapshot);
	if (source !== snapshot) {
		setSource(() => snapshot);
		setValue(() => snapshot);
	}
	return [value, setValue] as const;
}
