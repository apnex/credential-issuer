// public-surface - `@apnex/credential-issuer` exposes exactly what `export-map.json` and `CONTRACT.md` declare (`EM14`, `E12`, `D31`, `D10-E2`).
import assert from "node:assert/strict";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const map = JSON.parse(fs.readFileSync(path.join(root, "export-map.json"), "utf8"));
const publicName = (p) => (p === "." ? pkg.name : `${pkg.name}/${p.slice(2)}`);
const EXPECTED_ROWS = [
	"standing-code",
	"admission-key-issue",
	"fresh-key-per-dial",
	"single-use-admission",
	"admission-key-verifier",
	"preshared-key-secret",
	"key-reuse-report",
];

test("the export map names the package and exactly its exported paths", () => {
	assert.equal(map.package, pkg.name);
	assert.deepEqual(Object.keys(map.paths).sort(), Object.keys(pkg.exports).sort());
	assert.deepEqual(Object.keys(map).sort(), ["deferred", "package", "paths"]);
});

for (const [p, entry] of Object.entries(map.paths)) {
	test(`${publicName(p)} exposes what the map names`, async () => {
		assert.ok(entry.exports, `${p} names no exports`);
		const mod = await import(publicName(p));
		assert.deepEqual(Object.keys(mod).sort(), Object.keys(entry.exports).sort());
		for (const [name, use] of Object.entries(entry.exports)) {
			assert.equal(use.part, "credential-issuer", `${name} realises the credential-issuer part`);
			assert.ok(Array.isArray(use.serves) && use.serves.length > 0, `${name} serves at least one row`);
		}
	});
}

const contractRows = () => {
	const lines = fs.readFileSync(path.join(root, "CONTRACT.md"), "utf8").split("\n");
	const start = lines.findIndex((l) => /^\|\s*Capability\s*\|\s*Relation\s*\|/.test(l));
	const rows = [];
	for (let i = start + 2; start >= 0 && lines[i]?.startsWith("|"); i++) {
		rows.push(lines[i].split("|")[1].trim().replaceAll("`", ""));
	}
	return rows;
};

test("D10-E2: all seven contract rows are served, none is deferred, and every row has its contract test file", () => {
	const rows = contractRows();
	assert.deepEqual(rows, EXPECTED_ROWS);
	const served = new Set(
		Object.values(map.paths)
			.flatMap((e) => Object.values(e.exports))
			.flatMap((x) => x.serves),
	);
	for (const row of rows) {
		assert.ok(served.has(row), `${row} is served`);
		assert.ok(fs.existsSync(path.join(root, "test", "contract", `${row}.test.js`)), `test/contract/${row}.test.js exists`);
	}
	for (const row of served) {
		assert.ok(rows.includes(row), `${row} is a row of CONTRACT.md`);
	}
	assert.deepEqual(map.deferred, {});
});

const sources = (dir) =>
	fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
		d.isDirectory() ? sources(path.join(dir, d.name)) : [path.join(dir, d.name)],
	);
const imports = (text) =>
	[
		...text.matchAll(
			/\bimport\s+(type\s+)?[^;]*?\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']|\bexport\s+(type\s+)?[^;]*?\bfrom\s*["']([^"']+)["']|\brequire\s*\(\s*["']([^"']+)["']/g,
		),
	].map((m) => ({
		typeOnly: Boolean(m[1] || m[4]),
		specifier: m[2] ?? m[3] ?? m[5] ?? m[6],
	}));
const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/.*$/gm, "$1");
const builtins = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

test("no source file imports a module particular to one runtime outside a file whose name ends -adapter.ts, or uses a global particular to Node", () => {
	const files = sources(path.join(root, "src")).filter((f) => f.endsWith(".ts"));
	assert.ok(files.some((f) => f.endsWith("-adapter.ts")));
	for (const file of files) {
		if (file.endsWith("-adapter.ts")) continue;
		const name = path.relative(root, file);
		const text = fs.readFileSync(file, "utf8");
		const runtime = imports(text)
			.map((i) => i.specifier)
			.filter((s) => s.startsWith("node:") || builtins.has(s));
		assert.deepEqual(runtime, [], `${name} imports ${runtime.join(", ")}`);
		assert.doesNotMatch(
			code(text),
			/\b(process|Buffer|__dirname|__filename|setImmediate|setTimeout|setInterval)\b|\brequire\s*\(/,
			`${name} uses a global particular to Node or a timer outside the clock adapter`,
		);
	}
});

test("only the clock adapter reads a clock or randomness directly; all other source files use the clock, wallClock and randomBytes ports", () => {
	const files = sources(path.join(root, "src")).filter((f) => f.endsWith(".ts"));
	for (const file of files) {
		const base = path.basename(file);
		if (base === "clock-adapter.ts") continue;
		const text = code(fs.readFileSync(file, "utf8"));
		assert.doesNotMatch(
			text,
			/Date\.now\s*\(|new Date\s*\(|performance\.now|Temporal\.Now|Math\.random|getRandomValues|randomBytes\s*\(\s*\)/,
			`${path.relative(root, file)} reads a clock or randomness outside clock-adapter.ts`,
		);
	}
});

test("AGP is taken only as types: every source import of @agp is type-only, and the built package imports no @agp module at run time", () => {
	for (const file of sources(path.join(root, "src")).filter((f) => f.endsWith(".ts"))) {
		for (const { typeOnly, specifier } of imports(fs.readFileSync(file, "utf8"))) {
			if (specifier.startsWith("@agp/")) {
				assert.ok(typeOnly, `${path.relative(root, file)} imports ${specifier} at run time`);
			}
		}
	}
	for (const file of sources(path.join(root, "dist")).filter((f) => f.endsWith(".js"))) {
		assert.doesNotMatch(fs.readFileSync(file, "utf8"), /["']@agp\//, `${path.relative(root, file)} imports AGP at run time`);
	}
});

const validDepSpec = (name, spec) => spec === `file:../${name}` || new RegExp(`^https://github\\.com/apnex/${name}/releases/download/v0\\.\\d+\\.\\d+/apnex-${name}-0\\.\\d+\\.\\d+\\.tgz$`).test(spec);

test("the package depends on caller-identity and shape-check through file: links or pinned GitHub release URLs, and declares @agp/core as a peer", () => {
	assert.deepEqual(Object.keys(pkg.dependencies ?? {}).sort(), ["@apnex/caller-identity", "@apnex/shape-check"]);
	assert.ok(validDepSpec("caller-identity", pkg.dependencies["@apnex/caller-identity"]));
	assert.ok(validDepSpec("shape-check", pkg.dependencies["@apnex/shape-check"]));
	assert.deepEqual(pkg.peerDependencies, {
		"@agp/core": "file:../agp/packages/core",
	});
});
