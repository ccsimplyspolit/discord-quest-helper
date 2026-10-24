/**
 * CompleteDiscordQuest.js — Stealth-Hardened Discord Quest Completer (Console Edition)
 * Repository: https://github.com/ccsimplyspolit/discord-quest-stealth
 * Gist: https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd
 */
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
