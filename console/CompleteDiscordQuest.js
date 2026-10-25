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
const KNOWN_PUBLISHERS = [
	[/counter-strike|cs2|dota|team fortress|deadlock|half-life|left 4 dead|portal|steam|valve/i, "Valve Corp."],
	[/valorant|league of legends|teamfight tactics|legends of runeterra|2xko|riot/i, "Riot Games, Inc."],
	[/fortnite|rocket league|fall guys|alan wake|unreal|epic games/i, "Epic Games Inc."],
	[/overwatch|world of warcraft|diablo|hearthstone|starcraft|call of duty|warzone|blizzard|activision/i, "Blizzard Entertainment, Inc."],
	[/apex legends|battlefield|ea sports|fc 2[456]|the sims|need for speed|electronic arts/i, "Electronic Arts, Inc."],
	[/rainbow six|assassin's creed|far cry|the division|for honor|skull and bones|xdefiant|ubisoft/i, "Ubisoft Entertainment Sweden AB"],
	[/genshin|honkai|zenless zone zero|hoyoverse|mihoyo|cognosphere/i, "COGNOSPHERE PTE. LTD."],
	[/pubg|krafton/i, "KRAFTON, Inc."],
	[/marvel rivals|once human|naraka|netease/i, "NetEase Interactive Entertainment Pte. Ltd."],
	[/THE FINALS|arc raiders|embark/i, "Embark Studios AB"],
	[/helldivers|arrowhead|playstation|sony/i, "PlayStation PC LLC"],
	[/halo|forza|minecraft|sea of thieves|age of empires|reliccardinal|flight simulator|xbox|microsoft|bethesda|doom|starfield|elder scrolls|fallout/i, "Microsoft Corporation"],
	[/cyberpunk|witcher|cd projekt/i, "CD PROJEKT S.A."],
	[/baldur's gate|larian/i, "Larian Studios Games Ltd"],
	[/warframe|soulframe|digital extremes/i, "Digital Extremes Ltd."],
	[/path of exile|grinding gear/i, "Grinding Gear Games Limited"],
	[/tarkov|battlestate/i, "BATTLESTATE GAMES LIMITED"],
	[/unturned|battleye|beservice/i, "BattlEye Innovations e.K."],
	[/unitycrashhandler|lethal company|killscript|legion td/i, "Unity Technologies SF"],
	[/destiny|marathon|bungie/i, "Bungie, Inc."],
	[/street fighter|monster hunter|resident evil|dragon's dogma|capcom/i, "CAPCOM CO., LTD."],
	[/elden ring|armored core|tekken|bandai namco/i, "Bandai Namco Entertainment Inc."],
	[/final fantasy|square enix/i, "SQUARE ENIX CO., LTD."],
	[/war thunder|enlisted|crossout|gaijin/i, "Gaijin Network Ltd"],
	[/world of tanks|world of warships|wargaming/i, "Wargaming.net Limited"],
	[/dead by daylight|behaviour/i, "Behaviour Interactive Inc."],
	[/palworld|pocketpair/i, "Pocketpair, Inc."],
	[/delta force|arena breakout|wuthering waves|tencent|proxima beta|kuro/i, "Proxima Beta Pte. Limited"],
	[/roblox/i, "Roblox Corporation"],
	[/discord/i, "Discord Inc."]
];

function resolvePublisherCommonName(explicitPublisher, appName, exePath) {
	if (explicitPublisher && typeof explicitPublisher === "string" && explicitPublisher.trim().length > 0) {
		return explicitPublisher.trim();
	}
	const combined = `${appName || ""} ${exePath || ""}`.trim();
	for (const [pattern, publisherCn] of KNOWN_PUBLISHERS) {
		if (pattern.test(combined)) return publisherCn;
	}
	const cleanTitle = (appName || "")
		.replace(/[^a-zA-Z0-9 ]+/g, " ")
		.trim()
		.split(/\s+/)
		.filter(Boolean)
		.slice(0, 2)
		.map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
		.join(" ");
	return cleanTitle ? `${cleanTitle} Interactive, Inc.` : "Valve Corp.";
}

const REAL_PUBLISHER_SPKI_SHA256 = {
	"Valve Corp.": "371a0623e9c19d00bbb1e738b4733455dc76db156b54396d0ea258d3fcd0cbb2",
	"Microsoft Corporation": "8d79b51d140a92816a138dcba36f41720b3ce5063718cfbc4ad77efde8315a4d",
	"Epic Games Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
	"Epic Games, Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
	"Grinding Gear Games Limited": "4a7d34305a2f2d4d80468c26c2a577c12b7c0f75fa259831e437d2dca4db1e26",
	"BATTLESTATE GAMES LIMITED": "9f2bb2c2b8be0d67edbd1d8ef7c1975b01b167240532992803a1db5d11630271",
	"BattlEye Innovations e.K.": "1bfadddd1286fda141b960b44981fab55f9fe19c47330ea65821b8a6ae6e04d1",
	"Unity Technologies SF": "9a77d26b6e94916aab4e95449b74ef791b018c9f23c24fd6d1359a92d439427d",
	"Discord Inc.": "019f6eae63414925d0d85965c4f4af0eabec52dfb171c39d253ba5f19498c095"
};

const REAL_PE_PROFILES = {
	"win64/cs2.exe": {
		publisherCn: "Valve Corp.",
		fileSize: 2968216n,
		timeDateStamp: 1780353039,
		sizeOfImage: 4399104,
		hdrSha256: "70ee27820eb88028bd01c71ab6ad481845b0f986e279e180a73348c1eb4ccdbd",
		secSha256: "e4753bcf81bbf6e588a138f9de2754d750bd5f8f6306ef971456ed67288ea0de",
	},
	"path of exile/pathofexilesteam.exe": {
		publisherCn: "Grinding Gear Games Limited",
		fileSize: 79345496n,
		timeDateStamp: 1788480744,
		sizeOfImage: 81326080,
		hdrSha256: "701cd4cc5340283e472bb3bb8c533c93437e63d2e416720d82fcb7606d915df1",
		secSha256: "8587c9700969c5d30caf6fd7dda44975f252a6a8a055d07b1a6e563bacab9a2d",
	},
	"arena/escapefromtarkovarena.exe": {
		publisherCn: "BATTLESTATE GAMES LIMITED",
		fileSize: 3243360n,
		timeDateStamp: 1778746394,
		sizeOfImage: 684032,
		hdrSha256: "e809d7e33272567b5d2525f324cf5bd33555471e080b46df8c58d26590e21883",
		secSha256: "c602de1c1277db5de20b3753cd0074071fedc69bdca6f5f0a4b8b1661d3d7d9b",
	},
	"age of empires iv/reliccardinal.exe": {
		publisherCn: "Microsoft Corporation",
		fileSize: 144752932n,
		timeDateStamp: 1784152935,
		sizeOfImage: 147050496,
		hdrSha256: "066f57c46278b6f9b2829fcdf0969341185b84753d0319e39aaf64234a2d72e6",
		secSha256: "bb1b940d7f8bf0356a6a593582d4861e9f85723542cf96231abcd56db746c0a9",
	},
	"age of empires iv/gpuburner.exe": {
		publisherCn: "Microsoft Corporation",
		fileSize: 51616064n,
		timeDateStamp: 1784151922,
		sizeOfImage: 62803968,
		hdrSha256: "c602ddeb51b4a9da0a13019ab812b6e6db1454ebf0777ec227e3a3e8c5e12852",
		secSha256: "91b3b7032e0a9d3a1cb476092213ca1cbf323617e344b3e0d9dff4ec686a7f69",
	},
	"age of empires iv/essenceeditor.exe": {
		publisherCn: "Microsoft Corporation",
		fileSize: 10231608n,
		timeDateStamp: 3813183688,
		sizeOfImage: 10231808,
		hdrSha256: "a25ba2a7621664f67ea7f861471098150dea3e874ff2f5fa875d2d3708cdf925",
		secSha256: "52b2292823de3571a3d64eba977f923a30e7bd16b9b003c6beec694a2c4778e2",
	},
	"win64/vconsole2.exe": {
		publisherCn: "Valve Corp.",
		fileSize: 5137560n,
		timeDateStamp: 1791254866,
		sizeOfImage: 6017024,
		hdrSha256: "f498b04ef723de1b746d5a8ffabdc2ef017a4d13acb669ab4b764836c1818bad",
		secSha256: "c9a39e259c2bdf10c2cf2e27a57aeea9ad318d1c6492e6949d85c532c6c9e485",
	},
	"steam/steam.exe": {
		publisherCn: "Valve Corp.",
		fileSize: 5823128n,
		timeDateStamp: 1792617103,
		sizeOfImage: 7430144,
		hdrSha256: "e8bcb8fce00b9a29b1d5fca5e01607cdd06ba30329bc605994dced5d0741c196",
		secSha256: "476550e4d464edbaf9bdd27f609247f699e72e8db60b37fbf5b72f192b06062b",
	}
};

function hexToBytes(hex) {
	const out = new Uint8Array(hex.length >>> 1);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

async function synthesizeSignedExecutableFingerprint(userId, appId, exePath, explicitPublisher = null, appName = "") {
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
					if ((flags & 0x01) !== 0 && (flags & 0xFC) === 0 && fileSizeHigh === 0 && fileSizeLow >= 1024 && tds >= 0x386D4380 && imgSize >= 0x1000 && (imgSize & 0xFFF) === 0) {
						harvestedHw = plain.slice(0x32, 0x52);
						break;
					}
				}
			} catch {}
		}
	} catch {}

	const formattedPath = formatQuestExecutablePath(exePath) ?? exePath;
	const realProfile = REAL_PE_PROFILES[formattedPath];
	const publisher = realProfile ? realProfile.publisherCn : resolvePublisherCommonName(explicitPublisher, appName, exePath);
	const hHw = await sha256("hw:" + navigator.userAgent + ":" + (navigator.hardwareConcurrency || 8) + ":" + String(userId ?? ""));
	const spkiHex = REAL_PUBLISHER_SPKI_SHA256[publisher];
	const spkiBytes = spkiHex ? hexToBytes(spkiHex) : await sha256(`AUTHENTICODE_SPKI_RSA4096:${publisher}`);
	const certRawCn = publisher === "Epic Games, Inc." ? "Epic Games Inc." : publisher;
	const pubBytes = enc.encode(certRawCn);
	const certInput = new Uint8Array(pubBytes.length + 32);
	certInput.set(pubBytes, 0);
	certInput.set(spkiBytes, pubBytes.length);
	const hCert = new Uint8Array(await crypto.subtle.digest("SHA-256", certInput));

	const flags = 0x03;
	let fileSize;
	let timeDateStamp;
	let sizeOfImage;
	let hPeHeaders;
	let hSections;

	if (realProfile) {
		fileSize = realProfile.fileSize;
		timeDateStamp = realProfile.timeDateStamp >>> 0;
		sizeOfImage = realProfile.sizeOfImage >>> 0;
		hPeHeaders = hexToBytes(realProfile.hdrSha256);
		hSections = hexToBytes(realProfile.secSha256);
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
					const executableFingerprint = await synthesizeSignedExecutableFingerprint(currentUserId, applicationId, exePath, appData.publishers?.[0]?.name, appData.name);

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
				const origEnrolledAt = new Map();
				let autoLaunchedFrameId = null;
				try {
					if (isAchievementTask && QuestsStore?.quests) {
						// Deprioritize already-completed sibling quests sharing the same applicationId so Discord's GET_QUEST RPC returns the active uncompleted quest
						for (const q of QuestsStore.quests.values()) {
							if (!q || q.id === quest.id) continue;
							if (q.userStatus?.completedAt != null && typeof q.userStatus?.enrolledAt === "string") {
								origEnrolledAt.set(q.userStatus, q.userStatus.enrolledAt);
								q.userStatus.enrolledAt = "2099-01-01T00:00:00.000Z";
							}
						}
					}

					const buildAriseRequestId = bodyStr => {
						const mask64 = (1n << 64n) - 1n;
						const bitPositions = [];
						for (let b = 127; b >= 0; b--) {
							if (b !== 79 && b !== 78 && b !== 77 && b !== 76 && b !== 63 && b !== 62) {
								bitPositions.push(BigInt(b));
							}
						}
						const randBits = bits => {
							let v = 0n;
							const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(bits / 8)));
							for (const byte of bytes) v = (v << 8n) | BigInt(byte);
							return v & ((1n << BigInt(bits)) - 1n);
						};
						const nonce58 = randBits(58);
						let tag64;
						if (bodyStr === undefined) {
							tag64 = randBits(64);
						} else {
							let fnv = 0xcbf29ce484222325n;
							for (const byte of new TextEncoder().encode(bodyStr)) {
								fnv = ((fnv ^ BigInt(byte)) * 1099511628211n) & mask64;
							}
							let sm = (0x6c1fd93a84b7250en ^ ((nonce58 + 0x9e3779b97f4a7c15n) & mask64)) & mask64;
							sm = ((sm ^ (sm >> 30n)) * 0xbf58476d1ce4e5b9n) & mask64;
							sm = ((sm ^ (sm >> 27n)) * 0x94d049bb133111ebn) & mask64;
							sm = (sm ^ (sm >> 31n)) & mask64;
							tag64 = (fnv ^ sm) & mask64;
						}
						const combined122 = (nonce58 << 64n) | tag64;
						let uuidInt = (4n << 76n) | (2n << 62n);
						for (let i = 0; i < 122; i++) {
							uuidInt |= ((combined122 >> BigInt(121 - i)) & 1n) << bitPositions[i];
						}
						const hex = uuidInt.toString(16).padStart(32, "0");
						return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
					};

					const acknowledgeActivityDisclosures = async appId => {
						try {
							const discRes = await httpWithAnalytics.get({ url: `/applications/${appId}/disclosures` }).catch(() => null);
							const disclosures = discRes?.body?.disclosures;
							if (Array.isArray(disclosures) && disclosures.length > 0 && !discRes?.body?.all_acked) {
								await httpWithAnalytics.post({
									url: `/applications/${appId}/disclosures`,
									body: { disclosures }
								}).catch(() => null);
							}
						} catch {}
					};

					const ARISE_TITLES = ["chronicle-ace", "crashies-ace", "f0rsaken-ace", "tenz-ace", "jawgemo-ace", "aspas-ace", "jinggg-ace", "bstrdd-ace", "kangkang-ace", "mystery-ace"];
					const ARISE_BADGES = ["Bronze", "Silver", "Gold"];
					const ARISE_SCORES = { "ace-1": 24368, "ace-2": 24379, "ace-3": 24545, "ace-4": 24540, "ace-5": 24457, "ace-6": 23344, "ace-7": 23630, "ace-8": 23838, "ace-9": 23058, "ace-10": 22423 };

					const broadcastActivityCompletion = () => {
						let count = 0;
						for (const iframe of document.querySelectorAll("iframe")) {
							const src = String(iframe?.src || "");
							if (src.includes("discordsays.com") && (!applicationId || src.includes(String(applicationId)))) {
								try {
									for (const titleId of ARISE_TITLES) iframe.contentWindow?.postMessage({ type: "award-title", payload: titleId }, "*");
									for (const rank of ARISE_BADGES) iframe.contentWindow?.postMessage({ type: "award-badge", payload: rank }, "*");
									for (const [leaderboardId, score] of Object.entries(ARISE_SCORES)) iframe.contentWindow?.postMessage({ type: "submit-score", payload: { leaderboardId, score } }, "*");
									iframe.contentWindow?.postMessage({ type: "quest-completed" }, "*");
									count++;
								} catch {}
							}
						}
						try {
							const nativeHelper = window.VencordNative?.pluginHelpers?.CompleteDiscordQuest ?? window.VencordNative?.pluginHelpers?.DiscordStealthGuard;
							nativeHelper?.syncActivityMaxRecords?.(String(applicationId || "1536318183873454090"))?.catch?.(() => null);
						} catch {}
						return count;
					};

					if (isAchievementTask && applicationId) {
						try {
							FluxDispatcher.dispatch({ type: "QUEST_APPLICATION_START_TIMER", questId: quest.id });
							await acknowledgeActivityDisclosures(applicationId);
							await httpWithAnalytics.post({ url: `/applications/${applicationId}/proxy-ticket`, body: {} }).catch(() => null);
						} catch {}

						broadcastActivityCompletion();

						// Try headless OAuth2 code exchange + Activity backend API (via native Electron helper or renderer fetch)
						try {
							const oauthRes = await httpWithAnalytics.post({
								url: "/oauth2/authorize",
								query: { client_id: String(applicationId), response_type: "code", scope: "identify", prompt: "none", state: "" },
								body: { permissions: "0", authorize: true, integration_type: 1, location_context: { guild_id: "10000", channel_id: "10000", channel_type: 10000 } }
							}).catch(() => null);
							const loc = oauthRes?.body?.location || "";
							const codeMatch = loc.match(/[?&]code=([^&#]+)/);
							if (codeMatch?.[1]) {
								const oauthCode = decodeURIComponent(codeMatch[1]);
								const nativeHelper = window.VencordNative?.pluginHelpers?.CompleteDiscordQuest ?? window.VencordNative?.pluginHelpers?.DiscordStealthGuard;
								if (typeof nativeHelper?.completeActivityQuest === "function") {
									const nativeResult = await nativeHelper.completeActivityQuest(String(applicationId), String(quest.id), oauthCode, secondsNeeded).catch(() => null);
									if (nativeResult?.ok) {
										console.log("Quest completed via Activity backend API!");
										doJob();
										return;
									}
								}

								const baseOrigin = `https://${applicationId}.discordsays.com`;
								const buildHeaders = (token = "", extra = {}) => ({
									"Content-Type": "application/json",
									"Accept": "*/*",
									"X-Auth-Token": token,
									"X-Universe-ID": "78a74ba6-b027-4b0e-a686-9a6f4124c068",
									"X-Discord-Activity-Id": String(applicationId),
									"X-Discord-Hostname": `${applicationId}.discordsays.com`,
									"X-Arise-Client": "spades-prod-main-4835c58",
									...extra
								});
								const authRes = await fetch(`${baseOrigin}/.proxy/acf/authorize`, {
									method: "POST",
									headers: buildHeaders(""),
									body: JSON.stringify({ code: oauthCode, activityId: String(applicationId) })
								}).catch(() => null);
								if (authRes?.ok) {
									const authData = await authRes.json().catch(() => null);
									const acfToken = authData?.token || authData?.authToken || "";
									if (acfToken) {
										let ariseToken = acfToken;
										const regRes = await fetch(`${baseOrigin}/.proxy/acf/arise/register`, {
											method: "POST",
											headers: buildHeaders(acfToken)
										}).catch(() => null);
										if (regRes?.ok) {
											const regData = await regRes.json().catch(() => null);
											if (regData?.authToken) ariseToken = regData.authToken;
										}
										await Promise.allSettled([
											...ARISE_TITLES.map(id => {
												const body = JSON.stringify({ id });
												return fetch(`${baseOrigin}/.proxy/api/profileTitle/add`, { method: "POST", headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }), body });
											}),
											...ARISE_BADGES.map(rank => {
												const body = JSON.stringify({ rank });
												return fetch(`${baseOrigin}/.proxy/api/profileBadge/add`, { method: "POST", headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }), body });
											}),
											...Object.entries(ARISE_SCORES).map(([board, score]) => {
												const body = JSON.stringify({ score });
												return fetch(`${baseOrigin}/.proxy/api/leaderboards/${board}/submit`, { method: "POST", headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }), body });
											}),
											fetch(`${baseOrigin}/.proxy/api/profile/mission-completed`, { method: "POST", headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(undefined) }) })
										]);
										const progRes = await fetch(`${baseOrigin}/.proxy/acf/quest/progress`, {
											method: "POST",
											headers: buildHeaders(acfToken),
											body: JSON.stringify({ progress: Math.max(1, Number(secondsNeeded) || 1), quest_id: String(quest.id) })
										}).catch(() => null);
										if (progRes?.ok) {
											console.log("Quest completed via Activity backend API!");
											doJob();
											return;
										}
									}
								}
							}
						} catch {}

						// Ensure Activity Frame is mounted (auto-launch in minimized PIP mode if not open) and drive via postMessage bridge
						if (broadcastActivityCompletion() === 0) {
							try {
								await acknowledgeActivityDisclosures(applicationId);
								const FrameMgr = Object.values(wpRequire.c).find(x => x?.exports?.A?.launchFrame && x?.exports?.A?.updateFrameLayoutMode)?.exports?.A
									?? Object.values(wpRequire.c).find(x => x?.exports?.launchFrame && x?.exports?.updateFrameLayoutMode)?.exports;
								if (typeof FrameMgr?.launchFrame === "function") {
									const launchedId = await FrameMgr.launchFrame({ applicationId: String(applicationId), surface: { type: 0 }, showErrorModal: false });
									autoLaunchedFrameId = typeof launchedId === "string" ? launchedId : `main:${applicationId}`;
									FrameMgr.updateFrameLayoutMode?.({ frameId: autoLaunchedFrameId, layoutMode: 1 });
								}
							} catch {}
						}

						for (let cycle = 0; cycle < 12; cycle++) {
							await new Promise(resolve => setTimeout(resolve, 6500));
							broadcastActivityCompletion();
							const curQ = QuestsStore?.getQuest?.(quest.id);
							const curProg = curQ?.userStatus?.progress?.[taskName]?.value ?? 0;
							if (curQ?.userStatus?.completedAt != null || curProg >= secondsNeeded) {
								console.log("Quest completed!");
								doJob();
								return;
							}
						}
					}

					while (true) {
						if (isAchievementTask) broadcastActivityCompletion();
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
				} finally {
					if (autoLaunchedFrameId && applicationId) {
						try {
							FluxDispatcher.dispatch({ type: "FRAME_STOP", applicationId: String(applicationId), frameId: autoLaunchedFrameId });
						} catch {}
					}
					for (const [statusObj, val] of origEnrolledAt.entries()) {
						try { statusObj.enrolledAt = val; } catch {}
					}
				}

				doJob();
			};
			fn();
		}
	};
	doJob();
}
