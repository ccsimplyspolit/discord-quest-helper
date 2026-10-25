/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { Logger } from "@utils/Logger";
import definePlugin, { OptionType, PluginNative, StartAt } from "@utils/types";
import { filters, find, waitFor } from "@webpack";
import { RestAPI, UserStore } from "@webpack/common";

const Native = VencordNative.pluginHelpers.DiscordStealthGuard as PluginNative<typeof import("./native")>;
const logger = new Logger("DiscordStealthGuard", "#2ecc71");

function safeLazy<T extends object>(filter: (m: any) => boolean): T {
    let cached: any = null;
    waitFor(filter, (m: any) => {
        cached = m;
    });
    const resolve = () => cached ?? (cached = find(filter, { isIndirect: true }));
    return new Proxy({} as T, {
        get(_target, prop) {
            const mod = resolve();
            if (!mod) return undefined;
            const val = Reflect.get(mod, prop, mod);
            return typeof val === "function" ? val.bind(mod) : val;
        },
        set(_target, prop, value) {
            const mod = resolve();
            if (!mod) return true;
            return Reflect.set(mod, prop, value, mod);
        },
        has(_target, prop) {
            const mod = resolve();
            return mod ? Reflect.has(mod, prop) : false;
        }
    });
}

const RunningGameStore: any = safeLazy(filters.byProps("getRunningGames", "getGameForPID"));
const QuestStore: any = safeLazy(filters.byProps("getQuest", "quests"));
const AdDeliveryStore: any = safeLazy(filters.byStoreName("AdDeliveryStore"));
const DetectableGamesStore: any = safeLazy(filters.byProps("getDetectableGame", "games"));
const SuperPropertiesStore: any = safeLazy(filters.byProps("getSuperProperties", "getSuperPropertiesBase64"));

let lastDecisionFetchAt = 0;
const fetchedEarnedQuestIds = new Set<string>();

const STACK_MOD_FILTER_RE = /vencord|betterdiscord|userplugins|discordstealthguard|completediscordquest|<anonymous>|eval at|dist[\\/](?:renderer|preload|patcher)\.js/i;

/**
 * All 12 client-mod detection bits in libdiscore-wasm (34aec3bbe8b005d0.wasm, Func #1088):
 * Bit 0 (jQuery), Bit 19 (BetterDiscord/BdApi), Bit 27 (Powercord), Bit 36 (Cumcord),
 * Bit 43 (Vencord/VencordNative), Bit 52 (Replugged), Bit 66 (GooseMod), Bit 72 (Aliucord),
 * Bit 79 (Enmity), Bit 89 (Vendetta), Bit 103 (Shelter), Bit 116 (Moonlight)
 */
const CLIENT_MOD_DETECTION_BITS = [0, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116] as const;

const HIDDEN_WINDOW_MOD_GLOBALS = new Set<PropertyKey>([
    "$",
    "jQuery",
    "BetterDiscord",
    "BdApi",
    "Powercord",
    "cumcord",
    "Vencord",
    "VencordNative",
    "replugged",
    "goosemod",
    "aliucord",
    "enmity",
    "vendetta",
    "shelter",
    "moonlight"
]);

let cachedMachineGuid = "";
let machineGuidLoaded = false;
const fingerprintCache = new Map<string, string>();
const loggedFingerprints = new Set<string>();
const videoProgressTrackers = new Map<string, { startWallMs: number; startTs: number; lastTs: number }>();
let nextSyntheticObserverId = 1;
let cachedWindowProxy: Window | null = null;
const cleanupCallbacks: Array<() => void> = [];
const stealthHookedFns = new WeakSet<Function>();
const stealthRestHookedFns = new WeakSet<Function>();
const cloakedToStringMap = new WeakMap<Function, string>();
let fnToStringHooked = false;

export function isStealthHooked(fn: unknown): boolean {
    return typeof fn === "function" && stealthHookedFns.has(fn);
}

export function cloakFunction<T extends Function>(wrapped: T, original?: Function | null, fallbackName = ""): T {
    try {
        stealthHookedFns.add(wrapped);
        if (!fnToStringHooked) {
            fnToStringHooked = true;
            const origToString = Function.prototype.toString;
            const nativeToStringStr = origToString.call(origToString);
            const wrappedToString = function (this: Function) {
                if (typeof this === "function" && cloakedToStringMap.has(this)) {
                    return cloakedToStringMap.get(this)!;
                }
                const raw = origToString.call(this);
                if (typeof raw === "string" && raw.length < 600 && /Vencord\.Plugins\.plugins\[/.test(raw)) {
                    return `function ${this?.name || ""}() { [native code] }`;
                }
                return raw;
            };
            Object.defineProperty(wrappedToString, "name", { value: "toString", configurable: true });
            Object.defineProperty(wrappedToString, "length", { value: 0, configurable: true });
            cloakedToStringMap.set(wrappedToString, nativeToStringStr);
            stealthHookedFns.add(wrappedToString);
            Object.defineProperty(Function.prototype, "toString", {
                value: wrappedToString,
                writable: true,
                configurable: true,
                enumerable: false
            });
        }
        const targetName = original ? original.name : fallbackName;
        const targetLen = original ? original.length : wrapped.length;
        Object.defineProperty(wrapped, "name", { value: targetName, configurable: true });
        Object.defineProperty(wrapped, "length", { value: targetLen, configurable: true });
        let origStr = original
            ? (cloakedToStringMap.get(original) ?? Function.prototype.toString.call(original))
            : `function ${fallbackName}() { [native code] }`;
        if (/Vencord|Vesktop|Equicord|BetterDiscord/i.test(origStr)) {
            origStr = `function ${targetName || fallbackName}() { [native code] }`;
        }
        cloakedToStringMap.set(wrapped, origStr);
    } catch { }
    return wrapped;
}

const KNOWN_PUBLISHERS: ReadonlyArray<[RegExp, string]> = [
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
    [/counter-strike|\bcs2\b|dota|team fortress|deadlock|half-life|left 4 dead|portal|vconsole2|\bsteam\.exe\b|steamwebhelper|\bvalve\b/i, "Valve Corp."],
    [/discord/i, "Discord Inc."],
    [/chrome|google/i, "Google LLC"],
    [/firefox|mozilla/i, "Mozilla Corporation"],
    [/brave/i, "Brave Software, Inc."],
    [/opera/i, "Opera Norway AS"],
    [/spotify/i, "Spotify AB"],
    [/obs64|obs32|obs studio|\bobs\b/i, "OBS Project"],
    [/telegram/i, "Telegram FZ-LLC"]
];

export function resolvePublisherCommonName(
    explicitPublisher?: string | null,
    appName?: string | null,
    exePath?: string | null
): string {
    if (explicitPublisher && typeof explicitPublisher === "string" && explicitPublisher.trim().length > 0) {
        return explicitPublisher.trim();
    }
    const cleanExeTail = exePath ? formatQuestExecutablePath(exePath) : "";
    const combined = `${appName || ""} ${cleanExeTail}`.trim();
    for (const [pattern, publisherCn] of KNOWN_PUBLISHERS) {
        if (pattern.test(combined)) {
            return publisherCn;
        }
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

// ============================================================================
// Pure-JS Synchronous SHA-256 (for instant synchronous sub_1350 packing)
// ============================================================================
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(n: number, x: number): number {
    return (x >>> n) | (x << (32 - n));
}

function sha256Bytes(input: Uint8Array | string): Uint8Array {
    const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
    const bitLen = data.length * 8;
    const padLen = ((data.length + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(data);
    buf[data.length] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let offset = 0; offset < padLen; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
            const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g; g = f; f = e; e = (d + temp1) >>> 0;
            d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }
        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false); outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false); outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false); outView.setUint32(20, h5, false);
    outView.setUint32(24, h6, false); outView.setUint32(28, h7, false);
    return out;
}

function uint8ToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToUint8(b64: string): Uint8Array | null {
    try {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    } catch {
        return null;
    }
}

function getEffectiveMachineGuid(): string {
    if (cachedMachineGuid) return cachedMachineGuid;
    const seed = `RENDERER_GUID_V1:${navigator.userAgent}:${navigator.hardwareConcurrency || 8}:${navigator.language || "en"}`;
    const h = sha256Bytes(seed);
    h[6] = (h[6] & 0x0f) | 0x40;
    h[8] = (h[8] & 0x3f) | 0x80;
    const hex = Array.from(h.subarray(0, 16), b => b.toString(16).padStart(2, "0")).join("");
    cachedMachineGuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    return cachedMachineGuid;
}

/**
 * Exact port of Discord Module 973522 `o.Ic(exePath)`:
 * Normalizes backslashes to '/', lowercases, strips trailing '/', and takes the last 2 segments.
 * Example: "C:\\Program Files\\Steam\\steamapps\\common\\CS2\\win64\\cs2.exe" -> "win64/cs2.exe"
 */
export function formatQuestExecutablePath(exePath: string): string {
    const norm = (exePath || "").replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
    const parts = norm.split("/").filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join("/") : norm;
}

function hexToUint8(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length >>> 1);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

const REAL_PUBLISHER_SPKI_SHA256: Record<string, string> = {
    "Valve Corp.": "371a0623e9c19d00bbb1e738b4733455dc76db156b54396d0ea258d3fcd0cbb2",
    "Microsoft Corporation": "8d79b51d140a92816a138dcba36f41720b3ce5063718cfbc4ad77efde8315a4d",
    "Epic Games Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
    "Epic Games, Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
    "Grinding Gear Games Limited": "4a7d34305a2f2d4d80468c26c2a577c12b7c0f75fa259831e437d2dca4db1e26",
    "BATTLESTATE GAMES LIMITED": "9f2bb2c2b8be0d67edbd1d8ef7c1975b01b167240532992803a1db5d11630271",
    "BattlEye Innovations e.K.": "1bfadddd1286fda141b960b44981fab55f9fe19c47330ea65821b8a6ae6e04d1",
    "Unity Technologies SF": "9a77d26b6e94916aab4e95449b74ef791b018c9f23c24fd6d1359a92d439427d",
    "Discord Inc.": "019f6eae63414925d0d85965c4f4af0eabec52dfb171c39d253ba5f19498c095",
};

interface RealPeProfile {
    publisherCn: string;
    fileSize: bigint;
    timeDateStamp: number;
    sizeOfImage: number;
    hdrSha256: string;
    secSha256: string;
}

const REAL_PE_PROFILES: Record<string, RealPeProfile> = {
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
        fileSize: 4901016n,
        timeDateStamp: 1760055276,
        sizeOfImage: 5709824,
        hdrSha256: "cda2926ecca1eb1b53a0b1421c1969b461d08748d900c2e7c1fda332086c3556",
        secSha256: "5ae151258e7abe392da4ecef7855e6a51c1d9422a88b6ccd352f50835458e743",
    },
    "steam/steam.exe": {
        publisherCn: "Valve Corp.",
        fileSize: 5823128n,
        timeDateStamp: 1792617103,
        sizeOfImage: 7430144,
        hdrSha256: "e8bcb8fce00b9a29b1d5fca5e01607cdd06ba30329bc605994dced5d0741c196",
        secSha256: "476550e4d464edbaf9bdd27f609247f699e72e8db60b37fbf5b72f192b06062b",
    },
};

/**
 * Checks whether an existing executableFingerprint is missing, malformed, or comes from an unsigned/tiny stub
 * (like stagecraft.exe / discord-quest-runner.exe where is_signed == 0, timeDateStamp == 0, or fileSize < 512 KB).
 */
export function isFingerprintSuspiciousOrMissing(fp: string | null | undefined, userId: string): boolean {
    if (!fp || typeof fp !== "string" || fp.length !== 196) return true;
    const raw = base64ToUint8(fp);
    if (!raw || raw.length !== 0x92 || raw[0] !== 1) return true;

    const xorKey = sha256Bytes(userId + "https://discord.com/careers");
    const decrypted = new Uint8Array(0x92);
    decrypted[0] = raw[0];
    for (let i = 1; i < 0x92; i++) {
        decrypted[i] = raw[i] ^ xorKey[(i - 1) & 0x1f];
    }

    const flags = decrypted[1];
    const isSignedAndPe64 = (flags & 0x03) === 0x03 && (flags & 0xfc) === 0;
    const view = new DataView(decrypted.buffer);
    const fileSizeLow = view.getUint32(2, true);
    const fileSizeHigh = view.getUint32(6, true);
    const fileSize = fileSizeHigh * 0x100000000 + fileSizeLow;
    const timeDateStamp = view.getUint32(0x0a, true);
    const sizeOfImage = view.getUint32(0x0e, true);

    if (!isSignedAndPe64 || fileSize < 512 * 1024 || timeDateStamp === 0 || sizeOfImage === 0 || (sizeOfImage & 0xfff) !== 0) {
        return true;
    }

    // Verify cert_sha256 [0x72..0x91] is not all-zero
    let certNonZero = false;
    for (let i = 0x72; i < 0x92; i++) {
        if (decrypted[i] !== 0) {
            certNonZero = true;
            break;
        }
    }
    if (!certNonZero) return true;

    if (machineGuidLoaded) {
        const expectedHw = sha256Bytes(getEffectiveMachineGuid() + userId);
        for (let i = 0; i < 32; i++) {
            if (decrypted[0x32 + i] !== expectedHw[i]) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Exact synchronous port of discord_utils.node sub_a3990 + sub_a4120 + sub_1350 + sub_116790
 * Produces a 196-character Base64 string representing a 146-byte (0x92) signed PE64 game binary.
 */
export function synthesizeSignedExecutableFingerprint(
    exePath: string,
    userId: string,
    publisherName?: string | null,
    appName?: string | null,
    existingFp?: string | null
): string {
    const normExePath = (exePath || "game.exe").replace(/\\/g, "/");
    const questPath = formatQuestExecutablePath(normExePath);
    const profile = REAL_PE_PROFILES[questPath];
    const resolvedPublisher = profile
        ? profile.publisherCn
        : resolvePublisherCommonName(publisherName, appName, normExePath);
    const machineGuid = getEffectiveMachineGuid();
    const cacheKey = `${normExePath.toLowerCase()}|${userId}|${resolvedPublisher}|${machineGuid}`;
    if (machineGuidLoaded) {
        const cached = fingerprintCache.get(cacheKey);
        if (cached) return cached;
    }

    let fileSize = 0n;
    let timeDateStamp = 0;
    let sizeOfImage = 0;
    let hdrSha256: Uint8Array = new Uint8Array(32);
    let secSha256: Uint8Array = new Uint8Array(32);
    let preservedRealPe = false;

    if (profile) {
        fileSize = profile.fileSize;
        timeDateStamp = profile.timeDateStamp;
        sizeOfImage = profile.sizeOfImage;
        hdrSha256 = hexToUint8(profile.hdrSha256);
        secSha256 = hexToUint8(profile.secSha256);
        preservedRealPe = true;
    } else if (existingFp && typeof existingFp === "string" && existingFp.length === 196) {
        const raw = base64ToUint8(existingFp);
        if (raw && raw.length === 0x92 && raw[0] === 1) {
            const xorKey = sha256Bytes(userId + "https://discord.com/careers");
            const dec = new Uint8Array(0x92);
            dec[0] = raw[0];
            for (let i = 1; i < 0x92; i++) {
                dec[i] = raw[i] ^ xorKey[(i - 1) & 0x1f];
            }
            const view = new DataView(dec.buffer);
            const fSize = view.getBigUint64(0x02, true);
            const tds = view.getUint32(0x0a, true);
            const soi = view.getUint32(0x0e, true);
            if ((dec[1] & 0x02) !== 0 && fSize >= 512n * 1024n && tds !== 0 && soi !== 0 && (soi & 0xfff) === 0) {
                fileSize = fSize;
                timeDateStamp = tds;
                sizeOfImage = soi;
                hdrSha256 = dec.slice(0x12, 0x32);
                secSha256 = dec.slice(0x52, 0x72);
                preservedRealPe = true;
            }
        }
    }

    if (!preservedRealPe) {
        const normSeed = `${normExePath.toLowerCase()}|${resolvedPublisher}`;
        const seedHash = sha256Bytes(normSeed);
        const seedView = new DataView(seedHash.buffer);

        // Realistic AAA game .exe size: 48 MB .. 140 MB
        const baseMb = 48 + (seedView.getUint32(0, true) % 92);
        const extraBytes = (seedView.getUint32(4, true) % 1024) * 512;
        fileSize = BigInt(baseMb * 1024 * 1024 + extraBytes);

        // Realistic compile timestamp (2024..2025) and page-aligned SizeOfImage
        timeDateStamp = (1704067200 + (seedView.getUint32(8, true) % 55000000)) >>> 0;
        const pages = 0x3800 + (seedView.getUint16(12, true) % 0x4000);
        sizeOfImage = (pages * 0x1000) >>> 0;

        hdrSha256 = sha256Bytes(`PE_HEADERS_V1:${normSeed}:${timeDateStamp}:${sizeOfImage}`);
        secSha256 = sha256Bytes(`PE_SECTIONS_V1:${normSeed}:${sizeOfImage}`);
    }

    const hwSha256 = sha256Bytes(machineGuid + userId);

    const knownSpkiHex = REAL_PUBLISHER_SPKI_SHA256[resolvedPublisher];
    const spkiSha256 = knownSpkiHex
        ? hexToUint8(knownSpkiHex)
        : sha256Bytes(`AUTHENTICODE_SPKI_RSA4096:${resolvedPublisher}`);
    const certRawCn = resolvedPublisher === "Epic Games, Inc." ? "Epic Games Inc." : resolvedPublisher;
    const pubBytes = new TextEncoder().encode(certRawCn);
    const certInput = new Uint8Array(pubBytes.length + 32);
    certInput.set(pubBytes, 0);
    certInput.set(spkiSha256, pubBytes.length);
    const certSha256 = sha256Bytes(certInput);

    // Pack 0x92 (146) bytes
    const packet = new Uint8Array(0x92);
    const pktView = new DataView(packet.buffer);
    packet[0x00] = 1; // Version 1
    packet[0x01] = 0x03; // Flags: is_signed (1) | is_pe64 (2)
    pktView.setBigUint64(0x02, fileSize, true);
    pktView.setUint32(0x0a, timeDateStamp, true);
    pktView.setUint32(0x0e, sizeOfImage, true);
    packet.set(hdrSha256, 0x12);
    packet.set(hwSha256, 0x32);
    packet.set(secSha256, 0x52);
    packet.set(certSha256, 0x72);

    // XOR bytes [1..145] with SHA256(userId + "https://discord.com/careers")
    const xorKey = sha256Bytes(userId + "https://discord.com/careers");
    for (let i = 1; i < 0x92; i++) {
        packet[i] ^= xorKey[(i - 1) & 0x1f];
    }

    const b64 = uint8ToBase64(packet);
    if (machineGuidLoaded) {
        fingerprintCache.set(cacheKey, b64);
    }
    return b64;
}

const settings = definePluginSettings({
    cleanLaunchSignature: {
        type: OptionType.BOOLEAN,
        description: "Zero all 12 client-mod detection bits (including Bit 0 jQuery & Bit 43 Vencord) in libdiscore-wasm launch_signature",
        default: true,
    },
    spoofSignedExeFingerprint: {
        type: OptionType.BOOLEAN,
        description: "Automatically synthesize valid 196-char Authenticode-signed executableFingerprint (sub_a3990/sub_1350) for games & quests",
        default: true,
    },
    guardQuestEndpoints: {
        type: OptionType.BOOLEAN,
        description: "Protect /quests/* heartbeat, video-progress, and enroll payloads (inject 2-segment executable_path, exeFingerprint, metadata_sealed, and stack_trace sanitization)",
        default: true,
    },
    debugLogging: {
        type: OptionType.BOOLEAN,
        description: "Log intercepted anti-fraud checks and quest heartbeats to console",
        default: true,
    }
});

export function ensureGameObjectHasValidFingerprint(game: any): any {
    if (!game || typeof game !== "object" || !settings.store.spoofSignedExeFingerprint) return game;
    try {
        const userId = UserStore?.getCurrentUser?.()?.id;
        if (!userId) return game;

        const rawExePath = (
            game.exePath ||
            game.executable_path ||
            `c:/program files (x86)/steam/steamapps/common/${(game.name || "game").toLowerCase().replace(/[^a-z0-9_-]/g, "_")}/win64/${(game.exeName || "game.exe").toLowerCase()}`
        ).replace(/\\/g, "/");
        const publisher = resolvePublisherCommonName(game.publisher, game.name, rawExePath);
        const currentFp = game.exeFingerprint || game.executableFingerprint;

        // Normalize synthetic PID alignment (Windows PIDs are always multiples of 4)
        // and fix the telltale `nativeProcessObserverId === pid` heuristic
        if (typeof game.pid === "number" && game.pid > 0) {
            if ((game.pid & 3) !== 0 && game.pid < 1000000000) {
                const alignedPid = (game.pid & ~3) || 4000;
                if (Array.isArray(game.pidPath) && game.pidPath[0] === game.pid) {
                    game.pidPath = [alignedPid];
                }
                game.pid = alignedPid;
            }
            if (game.nativeProcessObserverId === game.pid || game.nativeProcessObserverId == null) {
                game.nativeProcessObserverId = ((nextSyntheticObserverId++ - 1) % 32) + 1;
            }
        }

        if (isFingerprintSuspiciousOrMissing(currentFp, userId)) {
            const validFp = synthesizeSignedExecutableFingerprint(rawExePath, userId, publisher, game.name, currentFp);
            game.exeFingerprint = validFp;
            game.executableFingerprint = validFp;
            if (!game.exePath) game.exePath = rawExePath;
            if (typeof game.cmdLine === "string" && game.cmdLine.includes("--remote-debugging-port")) {
                game.cmdLine = game.cmdLine.replace(/--remote-debugging-port(?:=\d+|\s+\d+)?/g, "").trim();
            }
            const logKey = `${game.name || rawExePath}|${validFp}`;
            if (settings.store.debugLogging && !loggedFingerprints.has(logKey)) {
                loggedFingerprints.add(logKey);
                logger.info(`Attached signed 196-char executableFingerprint for game: ${game.name || rawExePath} (Publisher: ${publisher})`);
            }
        }
    } catch (e) {
        logger.error("Error in ensureGameObjectHasValidFingerprint:", e);
    }
    return game;
}

export default definePlugin({
    name: "DiscordStealthGuard",
    description: "Full anti-detection shield against libdiscore-wasm client-mod bits, sub_a3990 executableFingerprint checks, and Quest Activity Notice telemetry triggers.",
    authors: [{ name: "Antigravity", id: 0n }],
    required: true,
    startAt: StartAt.WebpackReady,
    settings,

    patches: [
        // 1. Patch libdiscore-wasm generateLaunchSignature(e) to pass a clean Proxy(window) hiding mod globals
        {
            find: "libdiscore logs are part of the main app logs",
            replacement: {
                match: /\.generateLaunchSignature\((\i)\)/,
                replace: ".generateLaunchSignature($self.getCleanWindowProxy($1))"
            }
        },
        // 2. Sanitize both the exported `launchSignature` variable N and `extendSuperProperties({launch_signature:N})` in Module 174459
        {
            find: "extendSuperProperties({launch_signature:",
            replacement: [
                {
                    match: /(\i)=(\(0,\i\.xd\)\(\)\?\(0,\i\.xy\)\(\(0,\i\.V\)\(\)\):null)/,
                    replace: "$1=$self.cleanLaunchSignatureUuid($2)"
                },
                {
                    match: /launch_signature:(\i)/g,
                    replace: "launch_signature:$self.cleanLaunchSignatureUuid($1)"
                }
            ]
        },
        // 3. Patch getExecutableFingerprintForProcess(pid) in DiscordUtils wrapper
        {
            find: "setProcessObserverCollectExecutableFingerprint(",
            replacement: {
                match: /getExecutableFingerprintForProcess\((\i)\)\{/,
                replace: "getExecutableFingerprintForProcess($1){const _fp=$self.getFingerprintForPid($1);if(_fp)return Promise.resolve(_fp);"
            }
        }
    ],

    getFingerprintForPid(pid: number): string | null {
        if (!settings.store.spoofSignedExeFingerprint) return null;
        try {
            const game = RunningGameStore?.getGameForPID?.(pid);
            if (game) {
                this.ensureGameObjectHasValidFingerprint(game);
                return game.executableFingerprint || game.exeFingerprint || null;
            }
        } catch { }
        return null;
    },

    getCleanWindowProxy(origWindow: any) {
        if (!settings.store.cleanLaunchSignature || !origWindow || typeof origWindow !== "object") {
            return origWindow;
        }
        if (cachedWindowProxy) return cachedWindowProxy;
        try {
            // Use an empty extensible object inheriting from Window.prototype as the Proxy target
            // so hiding non-configurable window globals (e.g. `var Vencord`, `VencordNative`) in
            // `has`, `ownKeys`, and `getOwnPropertyDescriptor` never violates V8 Proxy invariants.
            const proxyTarget = Object.create(Reflect.getPrototypeOf(origWindow));
            Object.defineProperty(proxyTarget, Symbol.toStringTag, {
                value: "Window",
                configurable: true
            });
            cachedWindowProxy = new Proxy(proxyTarget, {
                get(_target, prop) {
                    if (HIDDEN_WINDOW_MOD_GLOBALS.has(prop)) {
                        return undefined;
                    }
                    if (prop === Symbol.toStringTag) {
                        return "Window";
                    }
                    const val = Reflect.get(origWindow, prop, origWindow);
                    if (typeof val !== "function") {
                        return val;
                    }
                    // Preserve class/interface constructors (which have `.prototype`) so `new win.MutationObserver(...)`,
                    // `val.prototype`, and `instanceof` checks inside wasm-bindgen work without losing `.prototype`.
                    if ("prototype" in val && val.prototype !== undefined) {
                        return val;
                    }
                    return val.bind(origWindow);
                },
                has(_target, prop) {
                    if (HIDDEN_WINDOW_MOD_GLOBALS.has(prop)) {
                        return false;
                    }
                    return Reflect.has(origWindow, prop);
                },
                ownKeys(_target) {
                    return Reflect.ownKeys(origWindow).filter(k => !HIDDEN_WINDOW_MOD_GLOBALS.has(k));
                },
                getOwnPropertyDescriptor(_target, prop) {
                    if (HIDDEN_WINDOW_MOD_GLOBALS.has(prop)) {
                        return undefined;
                    }
                    const desc = Reflect.getOwnPropertyDescriptor(origWindow, prop);
                    return desc ? { ...desc, configurable: true } : undefined;
                },
                getPrototypeOf(_target) {
                    return Reflect.getPrototypeOf(origWindow);
                }
            });
            return cachedWindowProxy;
        } catch {
            return Object.create(null);
        }
    },

    scrubLiveSuperProperties() {
        const self = this;
        waitFor(["getSuperProperties", "getSuperPropertiesBase64"], (store: any) => {
            try {
                if (!store) return;
                const scrubPropsObj = (props: any) => {
                    if (props && typeof props === "object") {
                        if (props.launch_signature) {
                            props.launch_signature = self.cleanLaunchSignatureUuid(props.launch_signature);
                        }
                        if ("has_client_mods" in props) {
                            props.has_client_mods = false;
                        }
                    }
                    return props;
                };

                scrubPropsObj(store.getSuperProperties?.());

                if (typeof store.getSuperProperties === "function" && !isStealthHooked(store.getSuperProperties)) {
                    const rawGetProps = store.getSuperProperties;
                    const origGetProps = rawGetProps.bind(store);
                    const wrappedGetProps = cloakFunction(function (...args: any[]) {
                        return scrubPropsObj(origGetProps(...args));
                    }, rawGetProps, "getSuperProperties");
                    store.getSuperProperties = wrappedGetProps;
                    cleanupCallbacks.push(() => {
                        store.getSuperProperties = rawGetProps;
                    });
                }

                if (typeof store.getSuperPropertiesBase64 === "function" && !isStealthHooked(store.getSuperPropertiesBase64)) {
                    const rawGetB64 = store.getSuperPropertiesBase64;
                    const origGetB64 = rawGetB64.bind(store);
                    let lastRawB64 = "";
                    let lastCleanB64 = "";
                    const wrappedGetB64 = cloakFunction(function (...args: any[]) {
                        const rawB64 = origGetB64(...args);
                        if (typeof rawB64 !== "string" || !rawB64) return rawB64;
                        if (rawB64 === lastRawB64 && lastCleanB64) return lastCleanB64;
                        try {
                            const parsed = JSON.parse(atob(rawB64));
                            scrubPropsObj(parsed);
                            lastRawB64 = rawB64;
                            lastCleanB64 = btoa(JSON.stringify(parsed));
                            return lastCleanB64;
                        } catch {
                            return rawB64;
                        }
                    }, rawGetB64, "getSuperPropertiesBase64");
                    store.getSuperPropertiesBase64 = wrappedGetB64;
                    cleanupCallbacks.push(() => {
                        store.getSuperPropertiesBase64 = rawGetB64;
                    });
                }
            } catch { }
        });
    },

    /**
     * Clears all 12 client-mod bits [0, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116]
     * in any 128-bit UUIDv4 launch_signature string.
     */
    cleanLaunchSignatureUuid(uuid: string | null | undefined): string | null | undefined {
        if (!uuid || typeof uuid !== "string" || !settings.store.cleanLaunchSignature) return uuid;
        const hex = uuid.replace(/-/g, "");
        if (hex.length !== 32) return uuid;

        const bytes = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }

        for (const bitIndex of CLIENT_MOD_DETECTION_BITS) {
            const byteIdx = bitIndex >> 3;
            const bitMask = 1 << (7 - (bitIndex & 7));
            bytes[byteIdx] &= ~bitMask;
        }

        const outHex = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
        return `${outHex.slice(0, 8)}-${outHex.slice(8, 12)}-${outHex.slice(12, 16)}-${outHex.slice(16, 20)}-${outHex.slice(20, 32)}`;
    },

    ensureGameObjectHasValidFingerprint(game: any): any {
        return ensureGameObjectHasValidFingerprint(game);
    },

    installStackTraceSanitizer() {
        try {
            const sanitizeStackString = (stack: unknown): any => {
                if (typeof stack !== "string") return stack;
                return stack
                    .split("\n")
                    .filter((line, idx) => idx === 0 || !STACK_MOD_FILTER_RE.test(line))
                    .join("\n");
            };

            const wrapPrepare = (underlying: any) => {
                if (isStealthHooked(underlying)) return underlying;
                const cleanPrepare = cloakFunction(function (err: Error, frames: any[]) {
                    const cleanFrames = Array.isArray(frames)
                        ? frames.filter(f => {
                            try {
                                const file = String(f?.getFileName?.() || f?.getScriptNameOrSourceURL?.() || "");
                                const str = String(f?.toString?.() || "");
                                return !STACK_MOD_FILTER_RE.test(file) && !STACK_MOD_FILTER_RE.test(str);
                            } catch {
                                return true;
                            }
                        })
                        : frames;
                    if (typeof underlying === "function" && !isStealthHooked(underlying)) {
                        const res = underlying(err, cleanFrames);
                        return sanitizeStackString(res);
                    }
                    const header = `${err?.name || "Error"}${err?.message ? `: ${err.message}` : ""}`;
                    const lines = Array.isArray(cleanFrames)
                        ? cleanFrames.map(f => `    at ${String(f)}`).filter(l => !STACK_MOD_FILTER_RE.test(l))
                        : [];
                    return sanitizeStackString([header, ...lines].join("\n"));
                }, typeof underlying === "function" ? underlying : null, "prepareStackTrace");
                return cleanPrepare;
            };

            const currentDesc = Object.getOwnPropertyDescriptor(Error, "prepareStackTrace");
            if (!currentDesc || !isStealthHooked(currentDesc.get)) {
                const initUnderlying = (Error as any).prepareStackTrace;
                let activePrepare: any = wrapPrepare(initUnderlying);
                const getter = cloakFunction(function () {
                    return activePrepare;
                }, null, "get prepareStackTrace");
                const setter = cloakFunction(function (newFn: any) {
                    activePrepare = wrapPrepare(newFn);
                }, null, "set prepareStackTrace");
                Object.defineProperty(Error, "prepareStackTrace", {
                    configurable: true,
                    enumerable: false,
                    get: getter,
                    set: setter
                });
                cleanupCallbacks.push(() => {
                    if (currentDesc) {
                        Object.defineProperty(Error, "prepareStackTrace", currentDesc);
                    } else {
                        delete (Error as any).prepareStackTrace;
                    }
                });
            }

            const protoStackDesc = Object.getOwnPropertyDescriptor(Error.prototype, "stack");
            if (protoStackDesc?.get && !isStealthHooked(protoStackDesc.get)) {
                const origStackGet = protoStackDesc.get;
                const origStackSet = protoStackDesc.set;
                const wrappedStackGet = cloakFunction(function (this: Error) {
                    return sanitizeStackString(origStackGet.call(this));
                }, origStackGet, "get stack");
                const wrappedStackSet = origStackSet
                    ? cloakFunction(function (this: Error, val: any) {
                        origStackSet.call(this, sanitizeStackString(val));
                    }, origStackSet, "set stack")
                    : undefined;
                Object.defineProperty(Error.prototype, "stack", {
                    configurable: true,
                    enumerable: protoStackDesc.enumerable ?? false,
                    get: wrappedStackGet,
                    set: wrappedStackSet
                });
                cleanupCallbacks.push(() => {
                    Object.defineProperty(Error.prototype, "stack", protoStackDesc);
                });
            }
        } catch (e) {
            logger.warn("Could not install Error.prepareStackTrace sanitizer:", e);
        }
    },

    /**
     * Installs getter/setter traps on RunningGameStore.getRunningGames, getRunningNonGames, and getGameForPID.
     * Even if an external script (like aamiaa/CompleteDiscordQuest.md) overwrites
     * `RunningGameStore.getRunningGames = () => [fakeGame]`, our setter automatically wraps their function
     * and injects a valid 196-char signed executableFingerprint into every returned game object.
     */
    installRunningGameStoreHooks() {
        const self = this;
        waitFor(["getRunningGames", "getGameForPID"], (store: any) => {
            try {
                if (!store) return;

                const hookListGetter = (propName: "getRunningGames" | "getRunningNonGames") => {
                    const currentFn = store[propName];
                    if (typeof currentFn !== "function" || isStealthHooked(currentFn)) return;

                    let underlyingFn = currentFn.bind(store);
                    const wrapFn = (fn: (...args: any[]) => any) => {
                        return cloakFunction(function (this: any, ...args: any[]) {
                            const list = fn.apply(this ?? store, args);
                            if (Array.isArray(list)) {
                                for (const g of list) self.ensureGameObjectHasValidFingerprint(g);
                            }
                            return list;
                        }, currentFn, propName);
                    };

                    let activeWrapped = wrapFn(underlyingFn);
                    Object.defineProperty(store, propName, {
                        configurable: true,
                        enumerable: true,
                        get: cloakFunction(function () {
                            return activeWrapped;
                        }, null, `get ${propName}`),
                        set: cloakFunction(function (newFn: any) {
                            if (typeof newFn === "function") {
                                underlyingFn = newFn;
                                activeWrapped = wrapFn(newFn);
                            }
                        }, null, `set ${propName}`)
                    });
                    cleanupCallbacks.push(() => {
                        Object.defineProperty(store, propName, {
                            configurable: true,
                            enumerable: true,
                            writable: true,
                            value: currentFn
                        });
                    });
                };

                hookListGetter("getRunningGames");

                if (typeof store.getGameForPID === "function" && !isStealthHooked(store.getGameForPID)) {
                    const origGetPidRef = store.getGameForPID;
                    let underlyingGetPid = origGetPidRef.bind(store);
                    const wrapPidFn = (fn: (pid: number) => any) => {
                        return cloakFunction(function (this: any, pid: number) {
                            const game = fn.call(this ?? store, pid);
                            return self.ensureGameObjectHasValidFingerprint(game);
                        }, origGetPidRef, "getGameForPID");
                    };
                    let activePidWrapped = wrapPidFn(underlyingGetPid);
                    Object.defineProperty(store, "getGameForPID", {
                        configurable: true,
                        enumerable: true,
                        get: cloakFunction(function () {
                            return activePidWrapped;
                        }, null, "get getGameForPID"),
                        set: cloakFunction(function (newFn: any) {
                            if (typeof newFn === "function") {
                                underlyingGetPid = newFn;
                                activePidWrapped = wrapPidFn(newFn);
                            }
                        }, null, "set getGameForPID")
                    });
                    cleanupCallbacks.push(() => {
                        Object.defineProperty(store, "getGameForPID", {
                            configurable: true,
                            enumerable: true,
                            writable: true,
                            value: origGetPidRef
                        });
                    });
                }
            } catch (e) {
                logger.warn("RunningGameStore hook warning:", e);
            }
        });
    },

    resolveQuestGameMetadata(questId: string, bodyAppId?: string) {
        const quest = QuestStore?.getQuest?.(questId) ?? QuestStore?.quests?.get?.(questId);
        const tasks = quest?.config?.taskConfigV2?.tasks ?? quest?.config?.taskConfig?.tasks ?? {};
        const isPlayOnDesktop = Boolean(tasks.PLAY_ON_DESKTOP);
        const isPlayActivityOnly = (Boolean(tasks.PLAY_ACTIVITY) || Boolean(tasks.ACHIEVEMENT_IN_ACTIVITY) || Boolean(tasks.ACHIEVEMENT_IN_GAME)) && !tasks.PLAY_ON_DESKTOP;
        const appId = bodyAppId || quest?.config?.application?.id;
        const appName = quest?.config?.application?.name || quest?.config?.messages?.gameTitle || "Game";

        const runningGames = RunningGameStore?.getRunningGames?.() ?? [];
        // Strictly match by appId; never fall back to runningGames[0] (which could leak a foreign game's path)
        const exactRunningGame = runningGames.find((g: any) =>
            appId && String(g?.id) === String(appId)
        );

        let rawExePath: string | undefined = exactRunningGame?.exePath;
        if (!rawExePath && appId) {
            const detectable = DetectableGamesStore?.getDetectableGame?.(appId);
            const winExe = detectable?.executables?.find?.((x: any) => x.os === "win32")?.name?.replace(/^>+/, "");
            if (winExe) {
                rawExePath = `c:/program files (x86)/steam/steamapps/common/${appName.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}/${winExe}`;
            }
        }
        if (!rawExePath) {
            rawExePath = `c:/program files (x86)/steam/steamapps/common/${appName.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}/win64/game_win64.exe`;
        }

        const publisher = resolvePublisherCommonName(exactRunningGame?.publisher, appName, rawExePath);

        return {
            isPlayOnDesktop,
            isPlayActivityOnly,
            hasRunningDesktopGame: Boolean(exactRunningGame),
            appId,
            appName,
            rawExePath,
            publisher
        };
    },

    async ensureQuestSealedMetadata(questId?: string): Promise<void> {
        try {
            const now = Date.now();
            const quest = questId ? (QuestStore?.getQuest?.(questId) ?? QuestStore?.quests?.get?.(questId)) : null;
            const adMap = AdDeliveryStore?.deliveryAdDecisionByPlacement;
            const hasDecisionSealed = Boolean(adMap?.get?.(1)?.metadataSealed || adMap?.get?.(3)?.metadataSealed);
            const hasQuestTrafficSealed = !questId || Boolean(quest?.trafficMetadataSealed || quest?.traffic_metadata_sealed);

            if (hasDecisionSealed && hasQuestTrafficSealed) {
                return;
            }

            const promises: Promise<any>[] = [];

            if (now - lastDecisionFetchAt > 60_000) {
                lastDecisionFetchAt = now;
                if (!QuestStore?.quests || QuestStore?.quests?.size === 0 || !hasQuestTrafficSealed) {
                    const fetchCurrentQuests = find(filters.byCode("QUESTS_FETCH_CURRENT_QUESTS_BEGIN"), { isIndirect: true });
                    if (typeof fetchCurrentQuests === "function") {
                        promises.push(Promise.resolve(fetchCurrentQuests()).catch(() => null));
                    }
                }
                if (!hasDecisionSealed) {
                    const fetchQuestToDeliver = find(filters.byCode("QUESTS_FETCH_QUEST_TO_DELIVER_BEGIN"), { isIndirect: true });
                    if (typeof fetchQuestToDeliver === "function") {
                        promises.push(Promise.resolve(fetchQuestToDeliver(1, "questBar-open")).catch(() => null));
                    }
                    const fetchQuestHomeHero = find(filters.byCode("QUESTS_FETCH_QUEST_HOME_HERO_BEGIN"), { isIndirect: true });
                    if (typeof fetchQuestHomeHero === "function") {
                        promises.push(Promise.resolve(fetchQuestHomeHero()).catch(() => null));
                    }
                }
            }

            if (questId && !hasQuestTrafficSealed && !fetchedEarnedQuestIds.has(questId)) {
                fetchedEarnedQuestIds.add(questId);
                const fetchEarnedQuestToDeliver = find(filters.byCode("QUESTS_FETCH_EARNED_QUEST_TO_DELIVER_BEGIN"), { isIndirect: true });
                if (typeof fetchEarnedQuestToDeliver === "function") {
                    promises.push(Promise.resolve(fetchEarnedQuestToDeliver([questId], 10, "quest_bar")).catch(() => null));
                }
            }

            if (promises.length > 0) {
                await Promise.allSettled(promises);
            }
        } catch { }
    },

    installRestApiQuestGuards() {
        try {
            if (!RestAPI?.post || stealthRestHookedFns.has(RestAPI.post)) return;
            const rawPost = RestAPI.post;
            const origPost = rawPost.bind(RestAPI);
            const self = this;

            const wrappedPost = cloakFunction(function (this: any, ...args: any[]) {
                const options = args[0];
                const url = typeof options === "string" ? options : options?.url;
                if (!settings.store.guardQuestEndpoints || typeof url !== "string" || !url.includes("/quests/")) {
                    return (origPost as any).apply(this ?? RestAPI, args);
                }

                try {
                    const body = options?.body;

                    // 1. Guard POST /quests/{id}/heartbeat synchronously
                    const hbMatch = url.match(/\/quests\/([^/]+)\/heartbeat/);
                    if (hbMatch?.[1] && body && typeof body === "object") {
                        const questId = hbMatch[1];
                        const isStreamHeartbeat = body.stream_key != null;
                        const isTerminalHeartbeat = body.terminal === true && body.executable_path == null && body.executable_fingerprint == null;

                        // Only attach executable_path & executable_fingerprint for PLAY_ON_DESKTOP heartbeats
                        // (Never attach desktop .exe telemetry to cloud PLAY_ACTIVITY / ACHIEVEMENT_IN_ACTIVITY heartbeats)
                        if (!isStreamHeartbeat && !isTerminalHeartbeat) {
                            const userId = UserStore?.getCurrentUser?.()?.id;
                            const meta = self.resolveQuestGameMetadata(questId, body.application_id);
                            const shouldAttachExe =
                                !meta.isPlayActivityOnly && (
                                    meta.isPlayOnDesktop ||
                                    body.executable_path != null ||
                                    body.executable_fingerprint != null ||
                                    meta.hasRunningDesktopGame
                                );

                            if (userId && shouldAttachExe) {
                                const fullPath = body.executable_path || meta.rawExePath;
                                // Always format executable_path with Module 973522 `o.Ic` (2 lowercase segments separated by '/')
                                body.executable_path = formatQuestExecutablePath(fullPath);

                                if (!body.application_id && meta.appId) {
                                    body.application_id = meta.appId;
                                }

                                if (isFingerprintSuspiciousOrMissing(body.executable_fingerprint, userId)) {
                                    const normPath = String(fullPath).replace(/\\/g, "/");
                                    const cacheKey = `${normPath.toLowerCase()}|${userId}|${meta.publisher}|${getEffectiveMachineGuid()}`;
                                    let fp = fingerprintCache.get(cacheKey) ?? null;

                                    if (!fp || fp.length !== 196) {
                                        fp = synthesizeSignedExecutableFingerprint(
                                            fullPath,
                                            userId,
                                            meta.publisher,
                                            meta.appName
                                        );
                                        if (Native?.generateExecutableFingerprint) {
                                            Native.generateExecutableFingerprint(fullPath, userId, meta.publisher)
                                                .then(nativeFp => {
                                                    if (nativeFp && typeof nativeFp === "string" && nativeFp.length === 196) {
                                                        fingerprintCache.set(cacheKey, nativeFp);
                                                    }
                                                })
                                                .catch(() => { });
                                        }
                                    }

                                    body.executable_fingerprint = fp;
                                    if (settings.store.debugLogging) {
                                        logger.info(`Protected QUESTS_HEARTBEAT (${questId}): executable_path="${body.executable_path}" + valid 196-char signed executable_fingerprint (${meta.publisher}).`);
                                    }
                                }
                            }
                        }
                    }

                    // 2. Guard POST /quests/{id}/enroll and /quests/{id}/claim-reward synchronously
                    const enrollOrClaimMatch = url.match(/\/quests\/([^/]+)\/(?:enroll|claim-reward)/);
                    if (enrollOrClaimMatch?.[1] && body && typeof body === "object") {
                        const questId = enrollOrClaimMatch[1];
                        const quest = QuestStore?.getQuest?.(questId) ?? QuestStore?.quests?.get?.(questId);
                        const adMap = AdDeliveryStore?.deliveryAdDecisionByPlacement;
                        const adDecision1 = adMap?.get?.(1);
                        const adDecision3 = adMap?.get?.(3);

                        if (body.metadata_sealed == null) {
                            const sealed =
                                quest?.metadataSealed ||
                                quest?.metadata_sealed ||
                                quest?.config?.metadataSealed ||
                                adDecision1?.metadataSealed ||
                                adDecision3?.metadataSealed;
                            if (sealed) {
                                body.metadata_sealed = sealed;
                                if (settings.store.debugLogging) {
                                    logger.info(`Backfilled metadata_sealed token into ${url}.`);
                                }
                            } else {
                                self.ensureQuestSealedMetadata(questId);
                            }
                        }
                        if (body.traffic_metadata_sealed == null) {
                            const trafficSealed =
                                quest?.trafficMetadataSealed ||
                                quest?.traffic_metadata_sealed ||
                                quest?.config?.trafficMetadataSealed ||
                                adDecision1?.trafficMetadataSealed ||
                                adDecision3?.trafficMetadataSealed;
                            if (trafficSealed) {
                                body.traffic_metadata_sealed = trafficSealed;
                                if (settings.store.debugLogging) {
                                    logger.info(`Backfilled traffic_metadata_sealed token into ${url}.`);
                                }
                            } else {
                                self.ensureQuestSealedMetadata(questId);
                            }
                        }
                    }

                    // 3. Guard POST /quests/{id}/video-progress (enforce 1x wall-clock rate limit + fractional jitter)
                    const vpMatch = url.match(/\/quests\/([^/]+)\/video-progress/);
                    if (vpMatch?.[1] && body && typeof body.timestamp === "number") {
                        const questId = vpMatch[1];
                        const nowMs = Date.now();
                        let ts = body.timestamp;
                        const quest = QuestStore?.getQuest?.(questId) ?? QuestStore?.quests?.get?.(questId);
                        const tasks = quest?.config?.taskConfigV2?.tasks ?? quest?.config?.taskConfig?.tasks ?? {};
                        const taskKey = ["WATCH_VIDEO", "WATCH_VIDEO_ON_MOBILE"].find(k => tasks[k] != null);
                        const targetDuration = Number((taskKey && tasks[taskKey]?.target) ?? 0);

                        let tracker = videoProgressTrackers.get(questId);
                        if (!tracker || ts < tracker.lastTs - 5) {
                            const currentStoreVal = (taskKey && quest?.userStatus?.progress?.[taskKey]?.value) ?? 0;
                            const baseTs = Math.min(ts, Number(currentStoreVal) || 0);
                            const initialWatchedMs = Math.min(15000, Math.max(0, (ts - baseTs) * 1000));
                            tracker = { startWallMs: nowMs - initialWatchedMs, startTs: baseTs, lastTs: baseTs };
                            videoProgressTrackers.set(questId, tracker);
                        }

                        const wallElapsedSec = Math.max(0, (nowMs - tracker.startWallMs) / 1000);
                        const maxRealisticTs = tracker.startTs + (wallElapsedSec * 1.15) + 10.5;
                        const isNearFinalCompletion = targetDuration > 0 && ts >= targetDuration && (targetDuration - maxRealisticTs) <= 15;
                        if (!isNearFinalCompletion && ts > maxRealisticTs) {
                            ts = maxRealisticTs;
                        }
                        if (targetDuration > 0 && ts >= targetDuration) {
                            ts = targetDuration;
                        } else if (Number.isInteger(ts) && ts > 0) {
                            const jitter = (Math.random() * 0.42) + 0.05;
                            ts = Number((ts + jitter).toFixed(3));
                            if (targetDuration > 0 && ts > targetDuration) {
                                ts = targetDuration;
                            }
                        } else {
                            ts = Number(ts.toFixed(3));
                        }
                        tracker.lastTs = ts;
                        body.timestamp = ts;
                    }
                } catch (err) {
                    logger.error("Error in RestAPI quest guard:", err);
                }
                return (origPost as any).apply(this ?? RestAPI, args);
            }, rawPost, "post");

            stealthRestHookedFns.add(wrappedPost);
            RestAPI.post = wrappedPost;
            cleanupCallbacks.push(() => {
                RestAPI.post = rawPost;
            });
        } catch (e) {
            logger.warn("RestAPI hook warning:", e);
        }
    },

    flux: {
        RUNNING_GAMES_CHANGE(event: any) {
            if (!settings.store.spoofSignedExeFingerprint) return;
            for (const list of [event?.games, event?.added]) {
                if (Array.isArray(list)) {
                    for (const g of list) ensureGameObjectHasValidFingerprint(g);
                }
            }
        }
    },

    async start() {
        if ((window as any).__OVERLAY__ || window.name === "DISCORD_OutOfProcessOverlay" || location.pathname.startsWith("/overlay")) return;

        getEffectiveMachineGuid();
        // Install all synchronous runtime hooks immediately (before awaiting IPC)
        this.installStackTraceSanitizer();
        this.scrubLiveSuperProperties();
        this.installRunningGameStoreHooks();
        this.installRestApiQuestGuards();
        setTimeout(() => {
            this.ensureQuestSealedMetadata();
        }, 3000);

        try {
            if (Native?.getMachineGuid) {
                const realGuid = await Native.getMachineGuid();
                if (realGuid && typeof realGuid === "string") {
                    cachedMachineGuid = realGuid;
                }
            }
        } catch {
            // Keep deterministic fallback GUID
        } finally {
            machineGuidLoaded = true;
            fingerprintCache.clear();
            // Refresh any games already in RunningGameStore if their fingerprint is missing or synthetic
            waitFor(["getRunningGames", "getGameForPID"], async (store: any) => {
                try {
                    const userId = UserStore?.getCurrentUser?.()?.id;
                    const games = store?.getRunningGames?.() ?? [];
                    for (const g of games) {
                        const currentFp = g?.executableFingerprint || g?.exeFingerprint;
                        if (!userId || !isFingerprintSuspiciousOrMissing(currentFp, userId)) {
                            continue;
                        }
                        if (g?.exePath && Native?.generateExecutableFingerprint) {
                            const normPath = String(g.exePath).replace(/\\/g, "/");
                            const publisher = resolvePublisherCommonName(g.publisher, g.name, normPath);
                            const nativeFp = await Native.generateExecutableFingerprint(g.exePath, userId, publisher).catch(() => null);
                            if (nativeFp && typeof nativeFp === "string" && nativeFp.length === 196) {
                                const cacheKey = `${normPath.toLowerCase()}|${userId}|${publisher}|${cachedMachineGuid}`;
                                fingerprintCache.set(cacheKey, nativeFp);
                                g.exeFingerprint = nativeFp;
                                g.executableFingerprint = nativeFp;
                                continue;
                            }
                        }
                        this.ensureGameObjectHasValidFingerprint(g);
                    }
                } catch { }
            });
        }

        logger.info("Active — launch_signature stealth, sub_a3990 signed executableFingerprint synthesis, and Quest endpoint guards enabled.");
    },

    stop() {
        while (cleanupCallbacks.length > 0) {
            const cb = cleanupCallbacks.pop();
            try {
                cb?.();
            } catch { }
        }
        fingerprintCache.clear();
        loggedFingerprints.clear();
        videoProgressTrackers.clear();
        fetchedEarnedQuestIds.clear();
        cachedWindowProxy = null;
    }
});
