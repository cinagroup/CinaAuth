import { defineConfig } from "tsdown";

export default defineConfig({
	dts: { build: true, incremental: true },
	format: ["esm"],
	entry: ["./src/index.ts", "./src/legacy/index.ts", "./src/legacy/client.ts"],
	treeshake: true,
});
