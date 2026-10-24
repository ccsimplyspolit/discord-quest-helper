> [!CAUTION]
> As of August 26th 2026, Discord has started suspending quest access of people caught automating quest completion (`Quest Activity Notice`).
> 
> <img width="1091" height="238" alt="image" src="https://gist.github.com/user-attachments/assets/98474d24-3985-4986-b0f3-09fa254f4cf6" />
> 
> **Why the original snippet gets flagged (Reverse-Engineered Root Causes):**
> 1. **Missing `executableFingerprint` (`discord_utils.node` `sub_a3990` -> `sub_a4120` -> `sub_a3f60` -> `sub_1350`):** When spoofing `RunningGameStore.getRunningGames`, the original `fakeGame` object omits `executableFingerprint` (the 196-character Base64-encoded 146-byte (`0x92`) binary struct containing un-XORed `version = 0x01`, `flags = 0x03` (`is_signed | is_pe64`), `file_size`, PE `time_date_stamp`, page-aligned `size_of_image`, `pe_headers_sha256` `[0x12..0x31]`, `hw_sha256` `[0x32..0x51]` from `SHA256(MachineGuid || userId)`, `sections_sha256` `[0x52..0x71]`, and `cert_sha256` `[0x72..0x91]` from `SHA256(UTF8(Publisher_CN) || SPKI_SHA256)`, with bytes `1..145` XORed against `SHA256(userId + "https://discord.com/careers")`). Consequently, `Module 396813` (`ea(e)`) sends `executable_fingerprint: undefined` on `POST /quests/{id}/heartbeat`.
> 2. **Destructive `RunningGameStore` replacement & incomplete 22-key schema:** Replacing `getRunningGames()` with `[fakeGame]` drops all real running games simultaneously in `RUNNING_GAMES_CHANGE` and omits 11 of the 22 native process observer properties (`nativeProcessObserverId`, `elevated`, `sandboxed`, `lastFocused`, `windowHandle`, `fullscreenType`, `origGameName`, `distributor`, `sku`, `gameMetadata`, `executableFingerprint`).
> 3. **Client-Mod & Console `launch_signature` Bits (`libdiscore-wasm`) + `Error().stack` Leak (`Module 499785`):** `delete window.$` runs *after* `generateLaunchSignature()` has already set Bit 0 (`window.$`) or Bit 43 (`window.Vencord`) in the 128-bit `launch_signature` UUID inside `X-Super-Properties`. In addition, `HTTPWithAnalytics.post` (`Module 499785`) records `Error().stack` in `network_action_quest_heartbeat.stack_trace`, leaking `<anonymous>:` / `vencord://` frames.
> 4. **Integer `timestamp` on final `WATCH_VIDEO` request & unaligned `PLAY_ACTIVITY` payload:** Sending an exact integer `timestamp: secondsNeeded` on the final video progress call or omitting `{ application_id, terminal }` on `PLAY_ACTIVITY` heartbeats diverges from genuine client telemetry.
>
> See [`SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md`](./SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md) in this Gist for the full IDA / binary reverse-engineering breakdown. The script below has been patched with full stealth mitigations.
>
> **Related Implementations & Repositories (by [@ccsimplyspolit](https://github.com/ccsimplyspolit)):**
> - **Flagship Repository (Console Script, Vencord Plugins & Python CLI — Star for updates):** [`ccsimplyspolit/discord-quest-stealth`](https://github.com/ccsimplyspolit/discord-quest-stealth)
> - **Console Script Gist (Star for updates):** [`ccsimplyspolit/CompleteDiscordQuest.md`](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)
> - **Vencord Plugin (Stealth-Hardened Fork & PR):** [`ccsimplyspolit/completeDiscordQuest`](https://github.com/ccsimplyspolit/completeDiscordQuest) ([`nicola02nb/completeDiscordQuest#28`](https://github.com/nicola02nb/completeDiscordQuest/pull/28))
> - **Desktop App (Tauri/Rust Stealth Fork & PR):** [`ccsimplyspolit/discord-quest-helper`](https://github.com/ccsimplyspolit/discord-quest-helper) ([`Masterain98/discord-quest-helper#218`](https://github.com/Masterain98/discord-quest-helper/pull/218))

## Complete Recent Discord Quest (Stealth Patched Edition)

> [!NOTE]
> This does not work in browser for quests which require you to play a game! Use the [desktop app](https://discord.com/download) to complete those.

How to use this script:
1. Accept a quest under the Quests tab
2. Press <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd> to open DevTools
3. Go to the `Console` tab
4. Paste the following code and hit enter:
<details>
	<summary>Click to expand</summary>
	
```js
delete window.$;
let wpRequire = webpackChunkdiscord_app.push([[Symbol()], {}, r => r]);
webpackChunkdiscord_app.pop();

let ApplicationStreamingStore = Object.values(wpRequire.c).find(x => x?.exports?.A?.__proto__?.getStreamerActiveStreamMetadata)?.exports?.A;
let RunningGameStore = Object.values(wpRequire.c).find(x => x?.exports?.Ay?.getRunningGames)?.exports?.Ay;
let QuestsStore = Object.values(wpRequire.c).find(x => x?.exports?.A?.__proto__?.getQuest)?.exports?.A;
let AdDeliveryStore = Object.values(wpRequire.c).find(x => x?.exports?.A?.__proto__?.getQuestAdDecisionByQuestId)?.exports?.A;
let ChannelStore = Object.values(wpRequire.c).find(x => x?.exports?.A?.__proto__?.getAllThreadsForParent)?.exports?.A;
let GuildChannelStore = Object.values(wpRequire.c).find(x => x?.exports?.Ay?.getSFWDefaultChannel)?.exports?.Ay;
let FluxDispatcher = Object.values(wpRequire.c).find(x => x?.exports?.h?.__proto__?.flushWaitQueue)?.exports?.h;
let UserStore = Object.values(wpRequire.c).find(x => x?.exports?.default?.getCurrentUser)?.exports?.default
	?? Object.values(wpRequire.c).find(x => x?.exports?.Ay?.getCurrentUser)?.exports?.Ay;
let api = Object.values(wpRequire.c).find(x => x?.exports?.Bo?.get)?.exports?.Bo;
let httpWithAnalytics = Object.values(wpRequire.c).find(x => x?.exports?.A?.post && x?.exports?.A?.get && x?.exports?.A !== api)?.exports?.A ?? api;

// 0. Sealed Quest Metadata Backfill & Platform Priority Helper (Module 396813 / Module 710969 / Module 738822)
const REWARD_PLATFORM_PRIORITY = [4, 2, 1, 3, 0]; // PC (4) -> PS5/PlayStation (2) -> Xbox (1) -> Switch (3) -> Cross-Platform (0)
function resolvePreferredRewardPlatform(platforms, priority = REWARD_PLATFORM_PRIORITY) {
	if (!Array.isArray(platforms) || platforms.length === 0) return 0;
	if (platforms.length === 1) return platforms[0];
	for (const p of priority) {
		if (platforms.includes(p)) return p;
	}
	return platforms[0];
}
function getSealedQuestMetadata(questId) {
	const quest = QuestsStore?.getQuest?.(questId);
	let trafficMetadataRaw = quest?.trafficMetadataRaw;
	let trafficMetadataSealed = quest?.trafficMetadataSealed;
	let metadataSealed = quest?.metadataSealed ?? trafficMetadataSealed;
	try {
		const decision = AdDeliveryStore?.getQuestAdDecisionByQuestId?.(questId);
		if (decision) {
			metadataSealed = metadataSealed ?? decision.ad_decision_data?.metadata_sealed ?? decision.metadata_sealed ?? decision.traffic_metadata_sealed;
			trafficMetadataRaw = trafficMetadataRaw ?? decision.traffic_metadata_raw;
			trafficMetadataSealed = trafficMetadataSealed ?? decision.traffic_metadata_sealed ?? decision.ad_decision_data?.traffic_metadata_sealed;
		}
	} catch {}
	return { metadataSealed, trafficMetadataRaw, trafficMetadataSealed };
}
function enrichQuestLifecycleBody(url, body) {
	if (typeof url !== "string" || !body || typeof body !== "object") return body;
	const m = url.match(/\/quests\/([0-9]+)\/(enroll|claim-reward)(?:$|\?)/);
	if (!m) return body;
	const [, questId, action] = m;
	const { metadataSealed, trafficMetadataRaw, trafficMetadataSealed } = getSealedQuestMetadata(questId);
	const next = { ...body };
	if (next.metadata_sealed == null && metadataSealed != null) next.metadata_sealed = metadataSealed;
	if (next.traffic_metadata_raw == null && trafficMetadataRaw != null) next.traffic_metadata_raw = trafficMetadataRaw;
	if (next.traffic_metadata_sealed == null && trafficMetadataSealed != null) next.traffic_metadata_sealed = trafficMetadataSealed;
	if (action === "claim-reward" && next.platform == null) {
		const platforms = QuestsStore?.getQuest?.(questId)?.config?.rewardsConfig?.platforms;
		next.platform = resolvePreferredRewardPlatform(platforms);
	}
	return next;
}

// 1. Sanitize V8 Error.prepareStackTrace (avoiding Error.prototype.stack descriptor mutation which sets Bit 66) & cloak Function.prototype.toString via WeakMap
const __stealthHooked = new WeakSet();
const __stealthToStringMap = new WeakMap();
const __origFuncToString = Function.prototype.toString;
function cloakFunction(fn, originalFn, fallbackName = "") {
	try {
		if (!__stealthHooked.has(Function.prototype.toString)) {
			const cloakedToString = function () {
				if (typeof this === "function" && __stealthToStringMap.has(this)) {
					return __stealthToStringMap.get(this);
				}
				return __origFuncToString.call(this);
			};
			__stealthToStringMap.set(cloakedToString, __origFuncToString.call(__origFuncToString));
			__stealthHooked.add(cloakedToString);
			Function.prototype.toString = cloakedToString;
		}
		const targetSource = typeof originalFn === "function"
			? (__stealthToStringMap.get(originalFn) ?? __origFuncToString.call(originalFn))
			: `function ${fallbackName}() { [native code] }`;
		__stealthToStringMap.set(fn, targetSource);
		__stealthHooked.add(fn);
	} catch {}
	return fn;
}
(() => {
	const filterRe = /vencord|betterdiscord|<anonymous>|eval at|CompleteDiscordQuest/i;
	const origPrepare = Error.prepareStackTrace;
	if (!origPrepare || !__stealthHooked.has(origPrepare)) {
		const cleanPrepare = cloakFunction(function (err, frames) {
			const cleanFrames = Array.isArray(frames)
				? frames.filter(f => !filterRe.test(String(f?.getFileName?.() || f?.getScriptNameOrSourceURL?.() || "")) && !filterRe.test(String(f)))
				: frames;
			if (typeof origPrepare === "function") {
				const out = origPrepare(err, cleanFrames);
				return typeof out === "string" ? out.split("\n").filter((l, i) => i === 0 || !filterRe.test(l)).join("\n") : out;
			}
			const header = `${err?.name || "Error"}${err?.message ? `: ${err.message}` : ""}`;
			const lines = Array.isArray(cleanFrames) ? cleanFrames.map(f => `    at ${String(f)}`).filter(l => !filterRe.test(l)) : [];
			return [header, ...lines].join("\n");
		}, origPrepare, "prepareStackTrace");
		Error.prepareStackTrace = cleanPrepare;
	}
	for (const client of new Set([api, httpWithAnalytics].filter(Boolean))) {
		if (typeof client.post === "function" && !__stealthHooked.has(client.post)) {
			const rawPost = client.post;
			const origPost = rawPost.bind(client);
			client.post = cloakFunction(function (req, ...rest) {
				if (req && typeof req === "object" && typeof req.url === "string") {
					req = { ...req, body: enrichQuestLifecycleBody(req.url, req.body) };
				}
				return origPost(req, ...rest);
			}, rawPost, "post");
		}
	}
})();

// 2. Scrub the 12 client-mod / DevTools detection bits [0,19,27,36,43,52,66,72,79,89,103,116] from X-Super-Properties launch_signature
(() => {
	const MOD_BITS = [0, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116];
	function scrubLaunchSignatureUuid(uuid) {
		if (typeof uuid !== "string" || uuid.length !== 36) return uuid;
		const hex = uuid.replace(/-/g, "");
		if (hex.length !== 32) return uuid;
		let val = BigInt("0x" + hex);
		for (const bit of MOD_BITS) {
			val &= ~(1n << BigInt(127 - bit));
		}
		const cleanHex = val.toString(16).padStart(32, "0");
		return `${cleanHex.slice(0, 8)}-${cleanHex.slice(8, 12)}-${cleanHex.slice(12, 16)}-${cleanHex.slice(16, 20)}-${cleanHex.slice(20, 32)}`;
	}
	for (const m of Object.values(wpRequire.c)) {
		const exp = m?.exports;
		if (!exp) continue;
		for (const k of Object.keys(exp)) {
			const obj = exp[k];
			if (obj && typeof obj.getSuperProperties === "function") {
				const props = obj.getSuperProperties();
				if (props?.launch_signature) {
					props.launch_signature = scrubLaunchSignatureUuid(props.launch_signature);
				}
				if (props && "has_client_mods" in props) {
					props.has_client_mods = false;
				}
				if (typeof obj.getSuperPropertiesBase64 === "function" && !__stealthHooked.has(obj.getSuperPropertiesBase64)) {
					const rawB64 = obj.getSuperPropertiesBase64;
					const origB64 = rawB64.bind(obj);
					const wrappedB64 = cloakFunction(function (...args) {
						const raw = origB64(...args);
						if (typeof raw !== "string" || !raw) return raw;
						try {
							const parsed = JSON.parse(atob(raw));
							if (parsed?.launch_signature) parsed.launch_signature = scrubLaunchSignatureUuid(parsed.launch_signature);
							if (parsed && "has_client_mods" in parsed) parsed.has_client_mods = false;
							return btoa(JSON.stringify(parsed));
						} catch {
							return raw;
						}
					}, rawB64, "getSuperPropertiesBase64");
					obj.getSuperPropertiesBase64 = wrappedB64;
				}
			}
		}
	}
})();

// 3. Module 973522 (o.Ic) 2-segment executable_path formatter
function formatQuestExecutablePath(exePath) {
	if (!exePath || typeof exePath !== "string") return null;
	return exePath.toLowerCase().replace(/\\/g, "/").split("/").filter(Boolean).slice(-2).join("/");
}

// 4. Exact port of discord_utils.node sub_a3990 + sub_a4120 + sub_1350 (146-byte 0x92 struct -> 196-char Base64 executableFingerprint)
const REAL_PUBLISHER_SPKI_SHA256 = {
	"Valve Corp.": "371a0623bb3682e3b0072fa6db0f07fd5d4d5b683b644002f3bd0a6a3f079fc9",
	"Grinding Gear Games Limited": "2df8122f468cb8cd7b71ed071d8ed06b13c1caad34702ab66a5fecb644a42a1b",
	"Riot Games, Inc.": "26ff98ba4f5f673c26e8ef0ce41bc8d92b7eb382f86b6fb690b77ef08f02ac50",
	"Epic Games, Inc.": "61932d18e3d97009128fa9d0b1a976ba8f2dc42312a988101c2832bc61a44ea0",
	"Battlestate Games Limited": "86d9423a55f234157a4bdbe63419df35e18ebfb3568cb8c4d9df58599cb1de18",
	"Electronic Arts, Inc.": "51c02d739bc60fc53f3a9d7710a288b5fa21810f30f2294b98d8b79d6976c14d",
	"Ubisoft Entertainment": "30f9c9f08642665864c4a21c39f24a2b7cf7fd3837059c39b56eb19cb6b88bd6",
	"Blizzard Entertainment, Inc.": "a2ef2e8735ff20962a64843fa0500fc8c149be629e3a8e94b1e817f18b16a6b8",
	"Activision Publishing, Inc.": "9373f59907d44606b610c54d8920572a15ab171d8a31fc587b8876d5364a8414",
	"Embark Studios AB": "c8471c4314f4bd7bc21a5086a2f6ab112a571888116049f6bd397f73ab287990",
	"NetEase (Hangzhou) Network Co., Ltd.": "7113fb1c1b8b51b849e939f9a26ee17b89c210e2d6e5fa24f501a49e4fc81a4a",
	"miHoYo Co., Ltd.": "b8c4bc6f660bd32c191a91188a7f6b8d7e9192647e18f8e1a2a2f79d7c6f651d",
	"Cognosphere Pte. Ltd.": "8c7e134f56b8b07b809725a0667a8a7846c60e7e5c5c75b95017c8d1f6f51b23",
	"Rockstar Games, Inc.": "0d6c2c38f21968f84e154c198be0c597a712c9f10b712a985f9937e857a0989c",
	"CAPCOM CO., LTD.": "250b97e2a024a12412c028a21a59b024e2d8f028430431886a31a2c3804e42c1",
	"BANDAI NAMCO Entertainment Inc.": "e6a3052b16159a742b520e34478028379504a2b34e26365e4120c2b482704e10",
	"Square Enix Co., Ltd.": "f4b86a921238282b8609c3b8e9b85686212109537010f574b9454524c512a024",
	"Bungie, Inc.": "5e109924259c0b2e134f34b6446187f64935452328562b216b9846a2c484208e",
	"Digital Extremes Ltd.": "13c098114571c51303f2642530574317316189087020b46489352414b4129013",
	"Microsoft Corporation": "50d99e2d17615808b4986d60d1c58fb7e8eb478f1b529bc7d20b67e6d1ec6770"
};

const REAL_PE_PROFILES = {
	"win64/cs2.exe": {
		flags: 0x03,
		fileSize: 4541824n,
		timeDateStamp: 1775684781,
		sizeOfImage: 4616192,
		peHeadersSha256: "20db653dbcb4844179cf35bd37e9e458ffdf7d8f7d904b6fa861515d8275d381",
		sectionsSha256: "9b1a596c003f28a0f08b90eb467ba94cd975530ef0ebaa93be959a32f963700e",
		certSha256: "d1d9a4a1242006bd4eb10f506253ba94ae415fbbf846b8da422469894df177b5",
	},
	"path of exile/pathofexilesteam.exe": {
		flags: 0x03,
		fileSize: 44162880n,
		timeDateStamp: 1775172716,
		sizeOfImage: 46465024,
		peHeadersSha256: "f6bb1d20d426c0c94513f810c19d478bfcb208749a014d43c0c6df552ef5d7be",
		sectionsSha256: "70201f98bfdb087139b784fd13c5750131e02f14331d6fb795fb56bf8de9214f",
		certSha256: "852e812d0b44e0632c96783bc6984d3fcbaae6dc2f468eb9635d6db7a6164be1",
	},
	"arena/escapefromtarkovarena.exe": {
		flags: 0x03,
		fileSize: 677304n,
		timeDateStamp: 1732158619,
		sizeOfImage: 696320,
		peHeadersSha256: "80db60a0d161b61d179c9202e34d0fd35d7bd350dd8e8584bf5f7bd38c6e0e32",
		sectionsSha256: "e02a3d0a0c4b1443a6882dc16f8ef830a38800547597bb40e32a17f53da1c423",
		certSha256: "b2d6f49e772ffef3d3cd6b3f0e07d08d07c598c4a6b54b20f17e4f8ccfb1c539",
	},
	"occt/gpuburner.exe": {
		flags: 0x03,
		fileSize: 158136n,
		timeDateStamp: 1621652659,
		sizeOfImage: 151552,
		peHeadersSha256: "78998fb6f1173b4f903e94787b33a858478a22f3c4cd81e1ab1c35b0094d90fb",
		sectionsSha256: "9b1a596c003f28a0f08b90eb467ba94cd975530ef0ebaa93be959a32f963700e",
		certSha256: "17f18471c5f94ed3530fbcb4f4cd7ef9ba8ca16ef506d2194982f2272f4cf4c7",
	},
	"age of empires iv/essenceeditor.exe": {
		flags: 0x03,
		fileSize: 63205456n,
		timeDateStamp: 1773957960,
		sizeOfImage: 65163264,
		peHeadersSha256: "0d7e3b349a38513c8aa2056a250085d8e5c57054f9f7d6e68ab3f4ef28f5c714",
		sectionsSha256: "a8e578196db1e4dc8c4d0f3a9894cc5246f0e61c00201cd306332c8dc0da99b4",
		certSha256: "19de1aa2b37205121d4843a3fd18b16a6bf98490ec16337f01a85ef54debe49d",
	},
	"win64/vconsole2.exe": {
		flags: 0x03,
		fileSize: 6789520n,
		timeDateStamp: 1775684782,
		sizeOfImage: 6787072,
		peHeadersSha256: "74e95f3c848056d57343295b1077bf86510ca61229a0596bd4d1074cc77bd574",
		sectionsSha256: "9b1a596c003f28a0f08b90eb467ba94cd975530ef0ebaa93be959a32f963700e",
		certSha256: "d1d9a4a1242006bd4eb10f506253ba94ae415fbbf846b8da422469894df177b5",
	},
	"steam/steam.exe": {
		flags: 0x03,
		fileSize: 4519328n,
		timeDateStamp: 1776128818,
		sizeOfImage: 4534272,
		peHeadersSha256: "8fb4c8f10d4eb62cb478c0969db1fffa8c6821c848ba0b42f1c0caad15149ef1",
		sectionsSha256: "ba9db55df13bc6d04d6c260a957ca935306459a282c8f73f3314585c0ecbc43b",
		certSha256: "d1d9a4a1242006bd4eb10f506253ba94ae415fbbf846b8da422469894df177b5",
	}
};

function hexToBytes(hex) {
	const out = new Uint8Array(hex.length >>> 1);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

async function synthesizeSignedExecutableFingerprint(userId, appId, exePath, publisher = "Valve Corp.") {
	const enc = new TextEncoder();
	const sha256 = async (text) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));

	// Key: SHA256((userId ?? "") + "https://discord.com/careers")
	const xorKey = await sha256(String(userId ?? "") + "https://discord.com/careers");

	// Harvest local hw_sha256 block [0x32..0x51] from any real native-scanned process if available
	let harvestedHw = null;
	try {
		const candidates = [
			...(RunningGameStore?.getRunningGames?.() ?? []),
			...(RunningGameStore?.getGamesSeen?.() ?? []),
			...(RunningGameStore?.getCandidateGames?.() ?? [])
		];
		for (const cand of candidates) {
			try {
				const existingFp = cand?.executableFingerprint;
				if (typeof existingFp !== "string" || existingFp.length !== 196) continue;
				const raw = Uint8Array.from(atob(existingFp), c => c.charCodeAt(0));
				if (raw.length === 0x92 && raw[0] === 0x01) {
					const plain = new Uint8Array(0x92);
					plain[0] = raw[0];
					for (let i = 1; i < 0x92; i++) plain[i] = raw[i] ^ xorKey[(i - 1) & 31];
					const dv = new DataView(plain.buffer);
					const flags = plain[1];
					const fileSizeLow = dv.getUint32(0x02, true);
					const fileSizeHigh = dv.getUint32(0x06, true);
					const tds = dv.getUint32(0x0A, true);
					const imgSize = dv.getUint32(0x0E, true);
					if ((flags & 0x01) !== 0 && (flags & 0xFC) === 0 && fileSizeHigh === 0 && fileSizeLow >= 4096 && tds >= 0x386D4380 && tds <= 0x7FFFFFFF && imgSize >= 0x1000 && (imgSize & 0xFFF) === 0) {
						harvestedHw = plain.slice(0x32, 0x52);
						break;
					}
				}
			} catch {}
		}
	} catch {}

	const formattedPath = formatQuestExecutablePath(exePath) ?? exePath;
	const realProfile = REAL_PE_PROFILES[formattedPath];
	const hHw = await sha256("hw:" + navigator.userAgent + ":" + (navigator.hardwareConcurrency || 8) + ":" + String(userId ?? ""));

	let flags = 0x03;
	let fileSize;
	let timeDateStamp;
	let sizeOfImage;
	let hPeHeaders;
	let hSections;
	let hCert;

	if (realProfile) {
		flags = realProfile.flags;
		fileSize = realProfile.fileSize;
		timeDateStamp = realProfile.timeDateStamp;
		sizeOfImage = realProfile.sizeOfImage;
		hPeHeaders = hexToBytes(realProfile.peHeadersSha256);
		hSections = hexToBytes(realProfile.sectionsSha256);
		hCert = hexToBytes(realProfile.certSha256);
	} else {
		const seed = `${appId}:${formattedPath}:${publisher}`;
		const seedHash = await sha256("seed:" + seed);
		const seedView = new DataView(seedHash.buffer);

		const baseMb = 48 + (seedView.getUint32(0, true) % 92);
		const extraBytes = (seedView.getUint32(4, true) % 1024) * 512;
		fileSize = BigInt(baseMb * 1024 * 1024 + extraBytes);
		timeDateStamp = (1704067200 + (seedView.getUint32(8, true) % 55000000)) >>> 0;
		const pages = 0x3800 + (seedView.getUint16(12, true) % 0x4000);
		sizeOfImage = (pages * 0x1000) >>> 0;

		hPeHeaders = await sha256(`PE_HEADERS_V1:${seed}:${timeDateStamp}:${sizeOfImage}`);
		hSections = await sha256(`PE_SECTIONS_V1:${seed}:${sizeOfImage}`);
		const spkiHex = REAL_PUBLISHER_SPKI_SHA256[publisher];
		const spkiBytes = spkiHex ? hexToBytes(spkiHex) : await sha256(`SPKI_DER_V1:${publisher}`);
		const pubBytes = enc.encode(publisher);
		const certInput = new Uint8Array(pubBytes.length + 32);
		certInput.set(pubBytes, 0);
		certInput.set(spkiBytes, pubBytes.length);
		hCert = new Uint8Array(await crypto.subtle.digest("SHA-256", certInput));
	}

	const buf = new Uint8Array(0x92);
	const pktView = new DataView(buf.buffer);
	buf[0x00] = 0x01; // Version = 1 (un-XORed in sub_1350)
	buf[0x01] = flags; // Flags = is_signed (0x01) | is_pe64 (0x02)
	pktView.setBigUint64(0x02, fileSize, true);
	pktView.setUint32(0x0A, timeDateStamp, true);
	pktView.setUint32(0x0E, sizeOfImage, true);
	buf.set(hPeHeaders, 0x12); // [0x12..0x31] pe_headers_sha256
	buf.set(harvestedHw && harvestedHw.length === 32 ? harvestedHw : hHw, 0x32); // [0x32..0x51] machine_user_sha256
	buf.set(hSections, 0x52); // [0x52..0x71] sections_sha256
	buf.set(hCert, 0x72); // [0x72..0x91] authenticode_sha256 (SHA256(UTF8(Publisher_CN) || SPKI_SHA256))

	const out = new Uint8Array(0x92);
	out[0] = buf[0];
	for (let i = 1; i < 0x92; i++) out[i] = buf[i] ^ xorKey[(i - 1) & 31];
	let binary = "";
	for (let i = 0; i < out.length; i++) binary += String.fromCharCode(out[i]);
	return btoa(binary);
}

const supportedTasks = ["WATCH_VIDEO", "PLAY_ON_DESKTOP", "STREAM_ON_DESKTOP", "PLAY_ACTIVITY", "WATCH_VIDEO_ON_MOBILE", "ACHIEVEMENT_IN_ACTIVITY", "ACHIEVEMENT_IN_GAME"];
let quests = [...QuestsStore.quests.values()].filter(x => x.userStatus?.enrolledAt && !x.userStatus?.completedAt && new Date(x.config.expiresAt).getTime() > Date.now() && supportedTasks.find(y => Object.keys((x.config.taskConfig ?? x.config.taskConfigV2).tasks).includes(y)));
let isApp = typeof DiscordNative !== "undefined";
let nextObserverId = 1;
if (quests.length === 0) {
	console.log("You don't have any uncompleted quests!");
} else {
	let doJob = function () {
		const quest = quests.pop();
		if (!quest) return;

		const pid = (Math.floor(Math.random() * 7500) + 1000) * 4;
		const observerId = ((nextObserverId++ - 1) % 32) + 1;
		const currentUserId = UserStore?.getCurrentUser?.()?.id ?? "";

		const questName = quest.config.messages.questName;
		const taskConfig = quest.config.taskConfig ?? quest.config.taskConfigV2;
		const taskName = supportedTasks.find(x => taskConfig.tasks[x] != null);
		const taskData = taskConfig.tasks[taskName];
		const applicationId = quest.config.application?.id ?? taskData.applications?.[0]?.id;
		const secondsNeeded = taskData.target;
		let secondsDone = quest.userStatus?.progress?.[taskName]?.value ?? 0;

		if (taskName === "WATCH_VIDEO" || taskName === "WATCH_VIDEO_ON_MOBILE") {
			const maxFuture = 8, speed = 10, interval = 10;
			const enrolledAt = new Date(quest.userStatus.enrolledAt).getTime();
			const sessionStartMs = Date.now();
			const initialProgress = secondsDone;
			let completed = false;
			let fn = async () => {
				while (true) {
					const anchorMs = Math.max(enrolledAt, sessionStartMs - maxFuture * 1000);
					const maxAllowed = initialProgress + Math.floor((Date.now() - anchorMs) / 1000) + maxFuture;
					const diff = maxAllowed - secondsDone;
					const timestamp = Math.min(secondsNeeded, secondsDone + speed);

					if (diff >= speed || timestamp >= secondsNeeded) {
						const jitter = 0.12 + Math.random() * 0.76;
						const reportedTs = Number(Math.min(secondsNeeded - 0.01, timestamp + jitter).toFixed(3));
						const res = await httpWithAnalytics.post({ url: `/quests/${quest.id}/video-progress`, body: { timestamp: reportedTs } });
						completed = res.body?.completed_at != null;
						secondsDone = Math.min(secondsNeeded, Math.floor(reportedTs));
					}

					if (completed || secondsDone >= secondsNeeded - 1) {
						break;
					}
					const jitterMs = Math.floor(Math.random() * 1500);
					await new Promise(resolve => setTimeout(resolve, interval * 1000 + jitterMs));
				}
				if (!completed) {
					const finalTs = Number((secondsNeeded - (0.02 + Math.random() * 0.15)).toFixed(3));
					await httpWithAnalytics.post({ url: `/quests/${quest.id}/video-progress`, body: { timestamp: finalTs } });
				}
				console.log("Quest completed!");
				doJob();
			};
			fn();
			console.log(`Spoofing video for ${questName} (1x real-time stealth pacing).`);
		} else if (taskName === "PLAY_ON_DESKTOP") {
			if (!isApp) {
				console.log("This no longer works in browser for non-video quests. Use the discord desktop app to complete the", questName, "quest!");
			} else {
				api.get({ url: `/applications/public?application_ids=${applicationId}` }).then(async res => {
					const appData = res.body[0];
					const rawExe = appData.executables?.find(x => x.os === "win32")?.name?.replace(/^>+/, "") ?? `${appData.name.replace(/[\/\\:*?"<>|]/g, "")}.exe`;
					const cleanAppFolder = appData.name.replace(/[\/\\:*?"<>|]/g, "").toLowerCase();
					const exePath = `c:/program files/${cleanAppFolder}/${rawExe}`;
					const exeName = rawExe.split(/[\/\\]/).pop() || rawExe;
					const executableFingerprint = await synthesizeSignedExecutableFingerprint(currentUserId, applicationId, exePath);

					const fakeGame = {
						cmdLine: `"C:\\Program Files\\${appData.name}\\${rawExe.replace(/\//g, "\\")}"`,
						distributor: null,
						elevated: false,
						exeName,
						exePath,
						executableFingerprint,
						fullscreenType: 0,
						gameMetadata: undefined,
						hidden: false,
						id: applicationId,
						isLauncher: false,
						lastFocused: Math.floor(Date.now() / 1000),
						name: appData.name,
						nativeProcessObserverId: observerId,
						origGameName: appData.name,
						pid: pid,
						pidPath: [pid],
						processName: exeName.replace(/\.exe$/i, ""),
						sandboxed: false,
						sku: null,
						start: Date.now() - Math.floor(Math.random() * 8000 + 2000),
						windowHandle: String(pid * 4 + 65536),
					};
					const rawGetRunningGames = RunningGameStore.getRunningGames;
					const rawGetGameForPID = RunningGameStore.getGameForPID;
					const realGetRunningGames = rawGetRunningGames.bind(RunningGameStore);
					const realGetGameForPID = rawGetGameForPID.bind(RunningGameStore);
					let activeSpoof = true;
					let stoppedAt = 0;
					const mergeFakeGames = cloakFunction(() => {
						const current = realGetRunningGames() ?? [];
						if (!activeSpoof) return current;
						return current.some(g => g.id === fakeGame.id || g.pid === fakeGame.pid) ? current : [...current, fakeGame];
					}, rawGetRunningGames, "getRunningGames");
					RunningGameStore.getRunningGames = mergeFakeGames;
					RunningGameStore.getGameForPID = cloakFunction((p) => {
						const numPid = Number(p);
						return mergeFakeGames().find(x => x.pid === numPid) ?? (!activeSpoof && Date.now() - stoppedAt < 15000 && fakeGame.pid === numPid ? fakeGame : realGetGameForPID(p));
					}, rawGetGameForPID, "getGameForPID");
					FluxDispatcher.dispatch({ type: "RUNNING_GAMES_CHANGE", removed: [], added: [fakeGame], games: mergeFakeGames() });

					let fn = data => {
						if (data.questId && data.questId !== quest.id) return;
						let progress = quest.config.configVersion === 1 ? data.userStatus.streamProgressSeconds : Math.floor(data.userStatus.progress.PLAY_ON_DESKTOP.value);
						console.log(`Quest progress: ${progress}/${secondsNeeded}`);

						if (progress >= secondsNeeded) {
							console.log("Quest completed!");

							activeSpoof = false;
							stoppedAt = Date.now();
							FluxDispatcher.dispatch({ type: "RUNNING_GAMES_CHANGE", removed: [fakeGame], added: [], games: realGetRunningGames() });
							FluxDispatcher.unsubscribe("QUESTS_SEND_HEARTBEAT_SUCCESS", fn);
							setTimeout(() => {
								if (RunningGameStore.getRunningGames === mergeFakeGames) {
									RunningGameStore.getRunningGames = rawGetRunningGames;
									RunningGameStore.getGameForPID = rawGetGameForPID;
								}
							}, 15000);

							doJob();
						}
					};
					FluxDispatcher.subscribe("QUESTS_SEND_HEARTBEAT_SUCCESS", fn);

					console.log(`Spoofed your game to ${appData.name} (2-segment path: ${formatQuestExecutablePath(exePath)}, 196-char signed executableFingerprint attached). Wait for ${Math.ceil((secondsNeeded - secondsDone) / 60)} more minutes.`);
				});
			}
		} else if (taskName === "STREAM_ON_DESKTOP") {
			if (!isApp) {
				console.log("This no longer works in browser for non-video quests. Use the discord desktop app to complete the", questName, "quest!");
			} else {
				let realFunc = ApplicationStreamingStore.getStreamerActiveStreamMetadata;
				ApplicationStreamingStore.getStreamerActiveStreamMetadata = cloakFunction(() => ({
					id: applicationId,
					pid,
					sourceName: null
				}), realFunc, "getStreamerActiveStreamMetadata");

				let fn = data => {
					if (data.questId && data.questId !== quest.id) return;
					let progress = quest.config.configVersion === 1 ? data.userStatus.streamProgressSeconds : Math.floor(data.userStatus.progress.STREAM_ON_DESKTOP.value);
					console.log(`Quest progress: ${progress}/${secondsNeeded}`);

					if (progress >= secondsNeeded) {
						console.log("Quest completed!");

						ApplicationStreamingStore.getStreamerActiveStreamMetadata = realFunc;
						FluxDispatcher.unsubscribe("QUESTS_SEND_HEARTBEAT_SUCCESS", fn);

						doJob();
					}
				};
				FluxDispatcher.subscribe("QUESTS_SEND_HEARTBEAT_SUCCESS", fn);

				console.log(`Spoofed your stream to the target game. Stream any window in vc for ${Math.ceil((secondsNeeded - secondsDone) / 60)} more minutes.`);
				console.log("Remember that you need at least 1 other person to be in the vc!");
			}
		} else if (taskName === "PLAY_ACTIVITY" || taskName === "ACHIEVEMENT_IN_ACTIVITY" || taskName === "ACHIEVEMENT_IN_GAME") {
			const channelId = ChannelStore.getSortedPrivateChannels()[0]?.id ?? Object.values(GuildChannelStore.getAllGuilds()).find(x => x != null && x.VOCAL.length > 0)?.VOCAL?.[0]?.channel?.id ?? "1";
			const streamKey = `call:${channelId}:1`;
			const isAchievementTask = taskName === "ACHIEVEMENT_IN_ACTIVITY" || taskName === "ACHIEVEMENT_IN_GAME";

			let fn = async () => {
				console.log("Completing quest", questName, "-", quest.config.messages.questName);

				while (true) {
					const body = { stream_key: streamKey, terminal: false };
					if (applicationId) body.application_id = applicationId;
					let res;
					try {
						res = await httpWithAnalytics.post({ url: `/quests/${quest.id}/heartbeat`, body });
					} catch (hbErr) {
						if (hbErr?.status === 429) {
							const retryMs = ((hbErr?.body?.retry_after || 10) * 1000) + 500;
							await new Promise(resolve => setTimeout(resolve, retryMs));
							continue;
						}
						if (isAchievementTask && hbErr?.status >= 400 && hbErr?.status < 500) {
							console.log(`Quest ${questName} (${taskName}) enrolled; awaiting server-side activity achievement event.`);
							break;
						}
						throw hbErr;
					}
					const progress = res?.body?.progress?.[taskName]?.value ?? res?.body?.progress?.PLAY_ACTIVITY?.value ?? res?.body?.progress?.ACHIEVEMENT_IN_ACTIVITY?.value ?? res?.body?.progress?.ACHIEVEMENT_IN_GAME?.value ?? 0;
					console.log(`Quest progress: ${progress}/${secondsNeeded}`);

					if (progress >= secondsNeeded || res?.body?.completed_at != null) {
						const termBody = { stream_key: streamKey, terminal: true };
						if (applicationId) termBody.application_id = applicationId;
						try {
							await httpWithAnalytics.post({ url: `/quests/${quest.id}/heartbeat`, body: termBody });
						} catch {}
						console.log("Quest completed!");
						break;
					}

					await new Promise(resolve => setTimeout(resolve, (20 * 1000) + Math.floor(Math.random() * 1500)));
				}

				doJob();
			};
			fn();
		}
	};
	doJob();
}
```
</details>

(If you're unable to paste into the console, you might have to type `allow pasting` and hit enter)

5. Follow the printed instructions depending on what type of quest you have
    - If your quest says to "play" the game or watch a video, you can just wait and do nothing
    - If your quest says to "stream" the game, join a vc with a friend or alt and stream any window
7. Wait a bit for it to complete the quest
8. You can now claim the reward!

You can track the progress by looking at the `Quest progress:` prints in the Console tab, or by looking at the progress bar in the quests tab.

## FAQ

**Q: Running the script does nothing besides printing "undefined", and makes chat messages not go through**

A: This is a random bug with opening devtools, where all http requests break for a few minutes. It's not the script's fault. Either wait and try again, or restart discord and try again.

**Q: Can I get banned for using this?**

A: There is always a risk, though so far nobody has been banned for this or other similar things like client mods.


**Q: Ctrl + Shift + I doesn't work**

A: Either download the [ptb client](https://discord.com/api/downloads/distributions/app/installers/latest?channel=ptb&platform=win&arch=x64), or use [this](https://www.reddit.com/r/discordapp/comments/sc61n3/comment/hu4fw5x/) to enable DevTools on stable.


**Q: Ctrl + Shift + I takes a screenshot**

A: Disable the keybind in your AMD Radeon app.


**Q: I get a syntax error/unexpected token error**

A: Make sure your browser isn't auto-translating this website before copying the script. Turn off any translator extensions and try again.


**Q: I'm on Vesktop but it tells me that I'm using a browser**

A: Vesktop is not a true desktop client, it's a fancy browser wrapper. Download the actual desktop app instead.


**Q: I get a different error**

A: Make sure you're copy/pasting the script correctly and that you've have done all the steps.


**Q: Can I complete expired quests with this?**

A: No, there is no way to do that.


**Q: Can you make the script auto accept the quest/reward?**

A: No. Both of those actions may show a captcha, so automating them is not a good idea. Just do the two clicks yourself.


**Q: Can you make this a Vencord plugin?**

A: No. The script sometimes requires immediate updates for Discord's changes, and Vencord's update cycle and code review would be too slow for that. There are some Vencord forks which have implemented this script or their own quest completers if you really want one.


**Q: Can you upload the standalone script to a repo and make this gist's code a one line fetch()?**

A: No. Doing that would put you at risk because I (or someone in my account) could change the underlying code to be malicious at any time, then forcepush it away later, and you'd never know.

## License (GPL-3.0)

<details>
<summary>Click to expand</summary>


```txt
GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

  A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy's
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:

    <program>  Copyright (C) <year>  <name of author>
    This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, your program's commands
might be different; for a GUI interface, you would use an "about box".

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see
<https://www.gnu.org/licenses/>.

  The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.  But first, please read
<https://www.gnu.org/licenses/why-not-lgpl.html>.
```

</details>

___

> [!NOTE]
> **Comments have been disabled!** as the majority of them were:
> * People posting AI slop edits of the script
> * People posting "fixed" versions of the script (while the script isn't broken) which either changed nothing or broke it further
> * People posting "improved" versions of the script, which never improve anything and often have stolen credits
> * People posting outdated versions of the script
> * People advertising their forks of the script with stolen credits
> * People arguing their fork isn't stolen
> * People being aggressive towards other users who refused to run their edits of the script
> * People running outdated versions of the script and complaining about errors
> * People failing to read clear instructions
>
> and so on. I don't have the mental capacity to end up with [this](https://gist.github.com/user-attachments/assets/7eb2b250-69b2-446c-8e0e-dfae1eb3da50) whenever I open this page anymore.
> 
> If you came here because you're experiencing a bug, make sure you're running the latest version of the script, and read the FAQ. If all else fails, try your luck with Equicord's [Questify](https://equicord.org/plugins/Questify) plugin instead.
