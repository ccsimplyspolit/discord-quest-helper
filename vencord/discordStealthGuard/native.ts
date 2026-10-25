/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ConnectSrc, CspPolicies, ImageScriptsAndCssSrc } from "@main/csp";
import { execFileSync } from "child_process";
import { createHash, randomBytes, randomUUID } from "crypto";
import { app, IpcMainInvokeEvent, session } from "electron";
import * as fs from "fs";
import Module from "module";
import * as os from "os";

const ActivityFrameAndConnectSrc = [...ImageScriptsAndCssSrc, "frame-src", "child-src", "media-src"];
CspPolicies["*.discordsays.com"] = ActivityFrameAndConnectSrc;
CspPolicies["https://*.discordsays.com"] = ActivityFrameAndConnectSrc;
CspPolicies["wss://*.discordsays.com"] = ConnectSrc;
CspPolicies["*.ariseworlds.com"] = ActivityFrameAndConnectSrc;
CspPolicies["https://*.ariseworlds.com"] = ActivityFrameAndConnectSrc;
CspPolicies["wss://*.ariseworlds.com"] = ConnectSrc;

const LOG_PREFIX = "[StealthGuard:Main]";

let cachedMachineGuid: string | null = null;

function deriveHostFallbackGuid(): string {
    try {
        const seed = `HOST_GUID_V1:${os.hostname()}:${os.userInfo().username}:${os.platform()}:${os.arch()}`;
        const h = createHash("sha256").update(seed).digest();
        h[6] = (h[6] & 0x0f) | 0x40; // UUIDv4
        h[8] = (h[8] & 0x3f) | 0x80; // RFC 4122 variant
        const hex = h.subarray(0, 16).toString("hex");
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    } catch {
        return "a1b2c3d4-e5f6-4789-abcd-ef0123456789";
    }
}

function getMachineGuidSync(): string {
    if (cachedMachineGuid) return cachedMachineGuid;
    try {
        if (process.platform === "win32") {
            const out = execFileSync(
                "reg.exe",
                ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"],
                { encoding: "utf8", windowsHide: true, timeout: 3000 }
            );
            const match = out.match(/MachineGuid\s+REG_SZ\s+([0-9a-fA-F-]+)/i);
            if (match?.[1]) {
                cachedMachineGuid = match[1].trim();
                return cachedMachineGuid;
            }
        }
    } catch (e) {
        console.warn(LOG_PREFIX, "Fallback MachineGuid used:", e);
    }
    cachedMachineGuid = deriveHostFallbackGuid();
    return cachedMachineGuid;
}

export async function getMachineGuid(_: IpcMainInvokeEvent): Promise<string> {
    return getMachineGuidSync();
}

function sha256(data: Buffer | string): Buffer {
    return createHash("sha256").update(data).digest();
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
    },
};

function formatQuestExePath(exePath: string): string {
    const norm = (exePath || "").replace(/\\/g, "/").toLowerCase().replace(/\/+$/, "");
    const parts = norm.split("/").filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join("/") : norm;
}

function resolveLocalExecutablePath(exePath: string): string | null {
    if (!exePath) return null;
    try {
        if (fs.existsSync(exePath)) return exePath;
        const norm = exePath.replace(/\\/g, "/");
        const questPath = formatQuestExePath(norm);
        const knownDirectPaths: Record<string, string[]> = {
            "win64/cs2.exe": [
                "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe",
                "D:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe",
                "K:/SteamLibrary/steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe",
                "C:/Program Files (x86)/Steam/steamapps/content/app_730/depot_2347771/game/bin/win64/cs2.exe",
            ],
            "path of exile/pathofexilesteam.exe": [
                "D:/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe",
                "C:/Program Files (x86)/Steam/steamapps/common/Path of Exile/PathOfExileSteam.exe",
                "K:/SteamLibrary/steamapps/common/Path of Exile/PathOfExileSteam.exe",
            ],
            "arena/escapefromtarkovarena.exe": [
                "D:/Games/Arena/EscapeFromTarkovArena.exe",
                "C:/Games/Arena/EscapeFromTarkovArena.exe",
            ],
            "age of empires iv/reliccardinal.exe": [
                "D:/SteamLibrary/steamapps/common/Age of Empires IV/RelicCardinal.exe",
                "C:/Program Files (x86)/Steam/steamapps/common/Age of Empires IV/RelicCardinal.exe",
            ],
            "age of empires iv/gpuburner.exe": [
                "D:/SteamLibrary/steamapps/common/Age of Empires IV/GPUBurner.exe",
                "C:/Program Files (x86)/Steam/steamapps/common/Age of Empires IV/GPUBurner.exe",
            ],
            "age of empires iv/essenceeditor.exe": [
                "D:/SteamLibrary/steamapps/common/Age of Empires IV/EssenceEditor.exe",
                "C:/Program Files (x86)/Steam/steamapps/common/Age of Empires IV/EssenceEditor.exe",
            ],
            "win64/vconsole2.exe": [
                "D:/SteamLibrary/steamapps/common/dota 2 beta/game/bin/win64/vconsole2.exe",
                "C:/Program Files (x86)/Steam/steamapps/common/dota 2 beta/game/bin/win64/vconsole2.exe",
            ],
            "steam/steam.exe": [
                "C:/Program Files (x86)/Steam/steam.exe",
            ],
        };
        const directList = knownDirectPaths[questPath];
        if (directList) {
            for (const p of directList) {
                if (fs.existsSync(p)) return p;
            }
        }
        const commonIdx = norm.toLowerCase().indexOf("/steamapps/common/");
        const relAfterCommon = commonIdx !== -1 ? norm.slice(commonIdx + "/steamapps/common/".length) : questPath;
        const searchRoots = [
            "C:/Program Files (x86)/Steam/steamapps/common",
            "D:/SteamLibrary/steamapps/common",
            "K:/SteamLibrary/steamapps/common",
            "D:/Games",
            "K:/Games"
        ];
        for (const root of searchRoots) {
            const candidate = `${root}/${relAfterCommon}`;
            if (fs.existsSync(candidate)) return candidate;
        }
    } catch { }
    return null;
}

/**
 * Exact implementation of discord_utils.node sub_a3990 + sub_a4120 + sub_1350 + sub_116790
 * Builds the 146-byte (0x92) binary fingerprint, XORs bytes [1..145] with
 * SHA256(userId + "https://discord.com/careers"), and encodes as 196-char Base64.
 */
function buildExecutableFingerprintBuffer(
    exePath: string,
    userId: string,
    publisherName = "Valve Corp."
): string {
    const machineGuid = getMachineGuidSync();
    const questPath = formatQuestExePath(exePath);
    const profile = REAL_PE_PROFILES[questPath];
    if (profile && (!publisherName || publisherName === "Valve Corp.")) {
        publisherName = profile.publisherCn;
    }
    const normSeed = `${exePath.toLowerCase()}|${publisherName}`;

    let fileSize = 0n;
    let timeDateStamp = 0;
    let sizeOfImage = 0;
    let isPe64 = true;
    const isSigned = true; // Bit 0 of flags (0x01) — always report valid WinVerifyTrust == 0
    let hdrSha256: Buffer | null = null;
    let secSha256: Buffer | null = null;

    // If a real game binary exists on disk (> 512 KB, e.g. cs2.exe is 2.83 MB), read its actual PE headers & section table
    try {
        const resolvedDiskPath = resolveLocalExecutablePath(exePath);
        if (resolvedDiskPath) {
            const stat = fs.statSync(resolvedDiskPath);
            if (stat.isFile() && stat.size > 512 * 1024) {
                const fd = fs.openSync(resolvedDiskPath, "r");
                try {
                    const readLen = Math.min(stat.size, 0x10000);
                    const buf = Buffer.alloc(readLen);
                    fs.readSync(fd, buf, 0, readLen, 0);
                    if (buf.readUInt16LE(0) === 0x5a4d) {
                        const e_lfanew = buf.readInt32LE(0x3c);
                        if (e_lfanew > 0 && e_lfanew + 0x108 <= readLen && buf.readUInt32LE(e_lfanew) === 0x00004550) {
                            const numSections = buf.readUInt16LE(e_lfanew + 6);
                            const tds = buf.readUInt32LE(e_lfanew + 8);
                            const sizeOfOpt = buf.readUInt16LE(e_lfanew + 0x14);
                            const magic = buf.readUInt16LE(e_lfanew + 0x18);
                            const soi = buf.readUInt32LE(e_lfanew + 0x50);
                            const secStart = e_lfanew + 0x18 + sizeOfOpt;
                            const secEnd = secStart + numSections * 40;
                            if (
                                magic === 0x020b &&
                                numSections > 0 &&
                                tds !== 0 &&
                                soi >= 0x1000 &&
                                (soi & 0xfff) === 0 &&
                                secStart <= readLen &&
                                secEnd <= readLen
                            ) {
                                fileSize = BigInt(stat.size);
                                timeDateStamp = tds;
                                sizeOfImage = soi;
                                isPe64 = true;
                                hdrSha256 = sha256(buf.subarray(0, secStart));
                                secSha256 = sha256(buf.subarray(secStart, secEnd));
                            }
                        }
                    }
                } finally {
                    fs.closeSync(fd);
                }
            }
        }
    } catch {
        // Fallback to profile / deterministic synthesis below
    }

    if ((fileSize === 0n || !hdrSha256 || !secSha256) && profile) {
        fileSize = profile.fileSize;
        timeDateStamp = profile.timeDateStamp;
        sizeOfImage = profile.sizeOfImage;
        isPe64 = true;
        hdrSha256 = Buffer.from(profile.hdrSha256, "hex");
        secSha256 = Buffer.from(profile.secSha256, "hex");
    }

    const seedHash = sha256(normSeed);
    if (fileSize === 0n) {
        const baseMb = 48 + (seedHash.readUInt32LE(0) % 92);
        const extraBytes = (seedHash.readUInt32LE(4) % 1024) * 512;
        fileSize = BigInt(baseMb * 1024 * 1024 + extraBytes);
    }
    if (timeDateStamp === 0) {
        timeDateStamp = 1704067200 + (seedHash.readUInt32LE(8) % 55000000);
    }
    if (sizeOfImage === 0) {
        const pages = 0x3800 + (seedHash.readUInt16LE(12) % 0x4000);
        sizeOfImage = (pages * 0x1000) >>> 0;
    }
    if (!hdrSha256) {
        hdrSha256 = sha256(`PE_HEADERS_V1:${normSeed}:${timeDateStamp}:${sizeOfImage}`);
    }
    if (!secSha256) {
        secSha256 = sha256(`PE_SECTIONS_V1:${normSeed}:${sizeOfImage}`);
    }

    // sub_a3f60: SHA256(MachineGuid || userId)
    const hwSha256 = sha256(Buffer.from(machineGuid + userId, "utf8"));

    // sub_a4120: SHA256(UTF8(Cert_Subject_CN) || SHA256(SubjectPublicKeyInfo))
    const knownSpkiHex = REAL_PUBLISHER_SPKI_SHA256[publisherName];
    const spkiSha256 = knownSpkiHex
        ? Buffer.from(knownSpkiHex, "hex")
        : sha256(`AUTHENTICODE_SPKI_RSA4096:${publisherName}`);
    const certRawCn = publisherName === "Epic Games, Inc." ? "Epic Games Inc." : publisherName;
    const certSha256 = sha256(Buffer.concat([Buffer.from(certRawCn, "utf8"), spkiSha256]));

    // sub_1350: Pack 146 bytes (0x92)
    const packet = Buffer.alloc(0x92);
    packet.writeUInt8(1, 0x00); // Version = 1 (unencrypted)
    const flags = (isSigned ? 1 : 0) | (isPe64 ? 2 : 0); // 0x03
    packet.writeUInt8(flags, 0x01);
    packet.writeBigUInt64LE(fileSize, 0x02);
    packet.writeUInt32LE(timeDateStamp >>> 0, 0x0a);
    packet.writeUInt32LE(sizeOfImage >>> 0, 0x0e);
    hdrSha256.copy(packet, 0x12);
    hwSha256.copy(packet, 0x32);
    secSha256.copy(packet, 0x52);
    certSha256.copy(packet, 0x72);

    // sub_a35c0: Key32 = SHA256(userId + "https://discord.com/careers")
    const xorKey = sha256(Buffer.from(userId + "https://discord.com/careers", "utf8"));

    // sub_1350 loop (0x001420..0x00144a): XOR bytes [1..145] with xorKey[(i - 1) & 0x1f]
    for (let i = 1; i < 0x92; i++) {
        packet[i] ^= xorKey[(i - 1) & 0x1f];
    }

    return packet.toString("base64");
}

export async function generateExecutableFingerprint(
    _: IpcMainInvokeEvent,
    exePath: string,
    userId: string,
    publisherName?: string
): Promise<string> {
    return buildExecutableFingerprintBuffer(exePath, userId, publisherName || "Valve Corp.");
}

const hookedObjects = new WeakSet<object>();

// ============================================================================
// MAIN PROCESS HOOK: Block Discord Host & Module Auto-Updates via Module._load
// ============================================================================
function installMainProcessUpdaterAndStealthHooks() {
    const mod = Module as any;
    if (hookedObjects.has(mod)) return;
    hookedObjects.add(mod);

    const origLoad = mod._load;
    const wrappedLoad = function (this: any, request: string, parent: any, isMain: boolean) {
        const exportsObj = origLoad.apply(this, arguments);

        try {
            if (typeof request === "string" && request.endsWith("updater.node") && exportsObj?.Updater) {
                if (!hookedObjects.has(exportsObj.Updater)) {
                    const OrigUpdater = exportsObj.Updater;
                    class PatchedNativeUpdater extends OrigUpdater {
                        private _interceptedHandler: ((resp: string) => void) | null = null;

                        constructor(options: any) {
                            super(options);
                            if (typeof options?.response_handler === "function") {
                                this._interceptedHandler = options.response_handler;
                            }
                        }

                        command(cmdStr: string) {
                            try {
                                const parsed = JSON.parse(cmdStr);
                                const [reqId, detail] = parsed;
                                const isUpdateCmd =
                                    detail === "UpdateToLatest" ||
                                    (typeof detail === "object" && detail !== null && (
                                        "UpdateToLatest" in detail ||
                                        "Repair" in detail ||
                                        "InstallModule" in detail
                                    ));

                                if (isUpdateCmd && this._interceptedHandler) {
                                    const cmdLabel = typeof detail === "string" ? detail : Object.keys(detail).join(",");
                                    console.log(LOG_PREFIX, `Blocked native updater command #${reqId}: ${cmdLabel}`);
                                    setImmediate(() => {
                                        try {
                                            this._interceptedHandler!(JSON.stringify([reqId, "Ok"]));
                                        } catch (err) {
                                            console.error(LOG_PREFIX, "Updater callback error:", err);
                                        }
                                    });
                                    return;
                                }
                            } catch {
                                // Pass through non-JSON or unexpected commands
                            }
                            return super.command(cmdStr);
                        }
                    }
                    Object.defineProperty(PatchedNativeUpdater, "name", { value: OrigUpdater.name || "Updater", configurable: true });
                    hookedObjects.add(PatchedNativeUpdater);
                    exportsObj.Updater = PatchedNativeUpdater;
                    console.log(LOG_PREFIX, "Native updater.node hooked — Host & Module updates disabled.");
                }
            }
        } catch (e) {
            console.error(LOG_PREFIX, "Module._load hook error:", e);
        }

        return exportsObj;
    };
    Object.defineProperty(wrappedLoad, "name", { value: origLoad.name || "_load", configurable: true });
    mod._load = wrappedLoad;
}

const ACTIVITY_DOMAIN_RE = /^(?:https?|wss?):\/\/([a-z0-9-]+\.)*(?:discordsays|ariseworlds)\.com(?:\/|$)/i;
const DISCORDSAYS_DOMAIN_RE = /^https:\/\/([a-z0-9-]+\.discordsays\.com)(?:\/|$)/i;
const DISCORD_ORIGIN_RE = /^https:\/\/(?:ptb\.|canary\.)?discord\.com(?:\/|$)/i;

function findHeaderKey(headers: Record<string, any>, lowerName: string): string | undefined {
    return Object.keys(headers).find(k => k.toLowerCase() === lowerName);
}

function deleteHeaderCaseInsensitive(headers: Record<string, any>, lowerName: string): void {
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === lowerName) {
            delete headers[key];
        }
    }
}

function setHeaderCaseInsensitive(headers: Record<string, string[]>, lowerName: string, value: string[]): void {
    deleteHeaderCaseInsensitive(headers, lowerName);
    headers[lowerName] = value;
}

function extractOriginFromUrl(rawUrl: unknown): string {
    if (typeof rawUrl !== "string" || !rawUrl) return "";
    const match = rawUrl.match(/^(https?:\/\/[^/?#]+)/i);
    return match?.[1] ?? "";
}

function sanitizeActivityResponseHeaders(responseHeaders: Record<string, string[]>, callerOrigin?: string): void {
    const existingOriginKey = findHeaderKey(responseHeaders, "access-control-allow-origin");
    const existingOrigin = existingOriginKey ? responseHeaders[existingOriginKey]?.[0] : undefined;
    const allowOrigin = callerOrigin || (existingOrigin && existingOrigin !== "*" ? existingOrigin : "https://discord.com");
    setHeaderCaseInsensitive(responseHeaders, "access-control-allow-origin", [allowOrigin]);
    setHeaderCaseInsensitive(responseHeaders, "access-control-allow-credentials", ["true"]);
    setHeaderCaseInsensitive(responseHeaders, "access-control-allow-methods", [
        "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
    ]);
    setHeaderCaseInsensitive(responseHeaders, "access-control-allow-headers", [
        "Content-Type, Authorization, X-Auth-Token, X-Universe-ID, X-Discord-Activity-Id, X-Discord-Hostname, X-Arise-Client, X-Request-Id, *"
    ]);
    setHeaderCaseInsensitive(responseHeaders, "access-control-expose-headers", ["*"]);
    deleteHeaderCaseInsensitive(responseHeaders, "x-frame-options");
    deleteHeaderCaseInsensitive(responseHeaders, "content-security-policy-report-only");

    const cspKey = findHeaderKey(responseHeaders, "content-security-policy");
    if (cspKey && responseHeaders[cspKey]?.[0]) {
        const rawCsp = responseHeaders[cspKey][0];
        const parts = rawCsp
            .split(";")
            .map(s => s.trim())
            .filter(Boolean)
            .filter(s => !/^frame-ancestors\b/i.test(s) && !/^connect-src\b/i.test(s));
        parts.push("connect-src * blob: data: https://*.discordsays.com wss://*.discordsays.com https://*.ariseworlds.com wss://*.ariseworlds.com");
        parts.push("frame-ancestors * https://discord.com https://ptb.discord.com https://canary.discord.com");
        responseHeaders[cspKey] = [parts.join("; ")];
    }
}

function installActivityCorsAndPreflightBypass(): void {
    const g = globalThis as any;
    if (g.__vcActivityCorsWrapperInstalled) return;
    g.__vcActivityCorsWrapperInstalled = true;

    const requestOriginById: Map<number, string> = (g.__vcActivityRequestOriginById ??= new Map<number, string>());

    app.whenReady().then(() => {
        try {
            const webReq = session?.defaultSession?.webRequest;
            if (!webReq) return;

            if (!g.__vcActivityBeforeSendInstalled) {
                g.__vcActivityBeforeSendInstalled = true;
                webReq.onBeforeSendHeaders(
                    {
                        urls: [
                            "https://*.discordsays.com/*",
                            "wss://*.discordsays.com/*",
                            "https://*.ariseworlds.com/*",
                            "wss://*.ariseworlds.com/*"
                        ]
                    },
                    ({ id, url, requestHeaders, referrer }, cb) => {
                        if (requestHeaders) {
                            const originKey = findHeaderKey(requestHeaders, "origin");
                            const refererKey = findHeaderKey(requestHeaders, "referer");
                            const rawReferer = refererKey ? String(requestHeaders[refererKey] || "") : (typeof referrer === "string" ? referrer : "");
                            const rawOrigin = (originKey ? String(requestHeaders[originKey] || "") : "") || extractOriginFromUrl(rawReferer);
                            if (rawOrigin) {
                                if (requestOriginById.size > 2000) requestOriginById.clear();
                                requestOriginById.set(id, rawOrigin);
                            }

                            const discordsaysMatch = typeof url === "string" ? url.match(DISCORDSAYS_DOMAIN_RE) : null;
                            if (discordsaysMatch?.[1]) {
                                const targetHost = discordsaysMatch[1];
                                const isFromDiscord =
                                    (rawOrigin && DISCORD_ORIGIN_RE.test(rawOrigin)) ||
                                    (rawReferer && DISCORD_ORIGIN_RE.test(rawReferer)) ||
                                    (typeof referrer === "string" && DISCORD_ORIGIN_RE.test(referrer));
                                if (isFromDiscord) {
                                    if (originKey) delete requestHeaders[originKey];
                                    requestHeaders.Origin = `https://${targetHost}`;
                                    if (refererKey) delete requestHeaders[refererKey];
                                    requestHeaders.Referer = `https://${targetHost}/`;
                                }
                            }
                        }
                        cb({ cancel: false, requestHeaders });
                    }
                );
            }

            const origOnHeadersReceived = webReq.onHeadersReceived.bind(webReq);
            const wrapListener = (downstreamListener?: (details: any, cb: (resp: any) => void) => void) => {
                return (details: any, cb: (resp: any) => void) => {
                    const callerOrigin = requestOriginById.get(details.id);
                    if (callerOrigin !== undefined) {
                        requestOriginById.delete(details.id);
                    }

                    const finalize = (resp: any) => {
                        const isActivityUrl = typeof details.url === "string" && ACTIVITY_DOMAIN_RE.test(details.url);
                        const headers = resp?.responseHeaders || details.responseHeaders || (isActivityUrl ? {} : undefined);
                        if (headers && isActivityUrl) {
                            sanitizeActivityResponseHeaders(headers, callerOrigin);
                            if (details.method === "OPTIONS" || (details.method === "OPTIONS" && details.statusCode >= 400)) {
                                cb({
                                    ...resp,
                                    cancel: false,
                                    responseHeaders: headers,
                                    statusLine: "HTTP/1.1 204 No Content"
                                });
                                return;
                            }
                        }
                        cb(resp);
                    };

                    if (typeof downstreamListener === "function") {
                        downstreamListener(details, finalize);
                    } else {
                        finalize({ cancel: false, responseHeaders: details.responseHeaders });
                    }
                };
            };

            if (!g.__vcActivityCorsHookInstalled) {
                origOnHeadersReceived(wrapListener(undefined));
                webReq.onHeadersReceived = ((...args: any[]) => {
                    const listener = typeof args[0] === "function" ? args[0] : args[1];
                    if (typeof listener === "function") {
                        return origOnHeadersReceived(wrapListener(listener));
                    }
                }) as any;
            }
        } catch {}
    });
}

const DEFAULT_UNIVERSE_ID = "78a74ba6-b027-4b0e-a686-9a6f4124c068";
const DEFAULT_ARISE_CLIENT = "spades-prod-main-4835c58";

export type ActivityScoreMode = "top1_plus_1" | "custom" | "legit_pro" | "quest_only";

/**
 * Exact implementation of Arise Engine `module "lDfAK"` `buildRequestId(bodyStr)`
 * Packs a 58-bit cryptographic nonce and a 64-bit tag (`FNV-1a(UTF8(bodyStr)) ^ SplitMix64(0x6c1fd93a84b7250en ^ (nonce + 0x9e3779b97f4a7c15n))`)
 * into the 122 non-version/non-variant bits of a UUIDv4 string (`4n << 76n | 2n << 62n`).
 */
function buildAriseRequestId(bodyStr?: string): string {
    const mask64 = (1n << 64n) - 1n;
    const bitPositions: bigint[] = [];
    for (let b = 127; b >= 0; b--) {
        if (b !== 79 && b !== 78 && b !== 77 && b !== 76 && b !== 63 && b !== 62) {
            bitPositions.push(BigInt(b));
        }
    }
    const randBits = (bits: number): bigint => {
        let v = 0n;
        const bytes = randomBytes(Math.ceil(bits / 8));
        for (const byte of bytes) v = (v << 8n) | BigInt(byte);
        return v & ((1n << BigInt(bits)) - 1n);
    };
    const nonce58 = randBits(58);
    let tag64: bigint;
    if (bodyStr === undefined) {
        tag64 = randBits(64);
    } else {
        let fnv = 0xcbf29ce484222325n;
        for (const byte of Buffer.from(bodyStr, "utf8")) {
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
}

async function discoverAriseMetadata(baseOrigin: string): Promise<{ universeId: string; appVersion: string }> {
    let universeId = DEFAULT_UNIVERSE_ID;
    let appVersion = DEFAULT_ARISE_CLIENT;
    try {
        const htmlRes = await fetch(`${baseOrigin}/`, {
            method: "GET",
            headers: { "User-Agent": "Mozilla/5.0" },
            signal: AbortSignal.timeout(8000)
        });
        if (!htmlRes.ok) return { universeId, appVersion };
        const html = await htmlRes.text();
        const scriptMatch = html.match(/src=["']?(\/arise-frontend\.[^"'\s>]+\.js)["'\s>]/i);
        if (!scriptMatch?.[1]) return { universeId, appVersion };

        const jsRes = await fetch(`${baseOrigin}${scriptMatch[1]}`, {
            method: "GET",
            headers: { "User-Agent": "Mozilla/5.0" },
            signal: AbortSignal.timeout(10000)
        });
        if (!jsRes.ok) return { universeId, appVersion };
        const js = await jsRes.text();

        const univMatch =
            js.match(/["']X-Universe-ID["']\s*:\s*["']([0-9a-f-]{36})["']/i) ??
            js.match(/ARISE_UNIVERSEID["']\)\s*\|\|\s*["']([0-9a-f-]{36})["']/i);
        if (univMatch?.[1]) {
            universeId = univMatch[1];
        }

        const verMatch = js.match(/let\s+\w+=["']([0-9a-f]{6,12})["'],\s*\w+=["']([a-z0-9-]+)["']/i);
        if (verMatch?.[1] && verMatch?.[2]) {
            appVersion = `${verMatch[2]}-${verMatch[1]}`;
        }
    } catch {}
    return { universeId, appVersion };
}

const VALORANT_ACES_TITLES = [
    "chronicle-ace",
    "crashies-ace",
    "f0rsaken-ace",
    "tenz-ace",
    "jawgemo-ace",
    "aspas-ace",
    "jinggg-ace",
    "bstrdd-ace",
    "kangkang-ace",
    "mystery-ace"
] as const;

const VALORANT_ACES_BADGES = ["Bronze", "Silver", "Gold"] as const;

export interface ValorantAcesBoardMeta {
    boardId: string;
    aceTag: string;
    playerName: string;
    teamCode: string;
    experience: string;
    team: "ALPHA" | "OMEGA";
    ceiling: number;
    fallbackTop2: number;
    legitProScore: number;
}

const VALORANT_ACES_BOARDS: readonly ValorantAcesBoardMeta[] = [
    { boardId: "ace-1", aceTag: "ace:01", playerName: "Chronicle", teamCode: "GMB", experience: "BERLIN 21", team: "ALPHA", ceiling: 25766, fallbackTop2: 24367, legitProScore: 22340 },
    { boardId: "ace-2", aceTag: "ace:02", playerName: "crashies", teamCode: "OPTC", experience: "REYKJAVIK 22", team: "OMEGA", ceiling: 25766, fallbackTop2: 24378, legitProScore: 22185 },
    { boardId: "ace-3", aceTag: "ace:03", playerName: "f0rsakeN", teamCode: "PRX", experience: "COPENHAGEN 22", team: "ALPHA", ceiling: 25766, fallbackTop2: 24544, legitProScore: 22410 },
    { boardId: "ace-4", aceTag: "ace:04", playerName: "TenZ", teamCode: "SEN", experience: "MADRID 24", team: "OMEGA", ceiling: 25766, fallbackTop2: 24539, legitProScore: 22290 },
    { boardId: "ace-5", aceTag: "ace:05", playerName: "jawgemo", teamCode: "EG", experience: "LOS ANGELES 23", team: "ALPHA", ceiling: 25766, fallbackTop2: 24456, legitProScore: 22120 },
    { boardId: "ace-6", aceTag: "ace:08", playerName: "bstrdd", teamCode: "MIBR", experience: "SAO PAULO 23", team: "OMEGA", ceiling: 25766, fallbackTop2: 23343, legitProScore: 21980 },
    { boardId: "ace-7", aceTag: "ace:06", playerName: "Aspas", teamCode: "MIBR", experience: "TOKYO 23", team: "ALPHA", ceiling: 25137, fallbackTop2: 23629, legitProScore: 22050 },
    { boardId: "ace-8", aceTag: "ace:07", playerName: "jinggg", teamCode: "PRX", experience: "LOS ANGELES 23", team: "OMEGA", ceiling: 25137, fallbackTop2: 23837, legitProScore: 22160 },
    { boardId: "ace-9", aceTag: "ace:09", playerName: "KangKang", teamCode: "EDG", experience: "SEOUL 24", team: "ALPHA", ceiling: 25766, fallbackTop2: 23057, legitProScore: 21910 },
    { boardId: "ace-10", aceTag: "ace:10", playerName: "Jamppi", teamCode: "VIT", experience: "BANGKOK 25", team: "OMEGA", ceiling: 23748, fallbackTop2: 22422, legitProScore: 21840 }
] as const;

const VALORANT_ACES_APP_ID = "1536318183873454090";

export interface SolvedShotScoreRun {
    v: 2;
    total: number;
    matchScore: number;
    accMult: number;
    ttkMult: number;
    kills: number;
    takeovers: number;
    whiffs: number;
    shots: number;
    hits: number;
    acc: number;
    hs: number;
    meanTtk: number;
    bestTtk: number;
    ace: boolean;
    flawless: boolean;
    team: string;
    experience: string;
    levelId: string;
    at: number;
    previouslyCompleted: boolean;
    shotTtksMs: number[];
    cumulativeMs: number[];
}

function solveShotScoreRun(targetScore: number, meta: ValorantAcesBoardMeta): SolvedShotScoreRun {
    const rawNum = Number(targetScore);
    const validTarget = Number.isFinite(rawNum) && rawNum > 0 ? Math.round(rawNum) : (meta.fallbackTop2 + 1);
    const T = Math.max(2000, Math.min(meta.ceiling, validTarget));
    const maxMatchScore = Math.round(meta.ceiling / 5.2);

    let chosenS = maxMatchScore;
    let chosenTotalTtkMs = 3500;
    let chosenTtkMult = 2.6;
    let solved = false;

    const tryCandidateS = (s: number, minTtk: number, maxTtk: number, requireMultipleOf5: boolean): boolean => {
        const reqMult = T / (2.0 * s);
        if (reqMult < 0.999 || reqMult > 2.601) return false;
        const ratio = Math.max(0, Math.min(1, (reqMult - 1.0) / 1.6));
        const i = Math.pow(ratio, 1.0 / 1.4);
        const rawMeanTtk = 1.8 - 1.1 * i;
        if (rawMeanTtk < minTtk - 0.01 || rawMeanTtk > maxTtk + 0.01) return false;

        const baseTotalMs = Math.round(rawMeanTtk * 5000);
        for (let delta = -15; delta <= 15; delta++) {
            const candTotalMs = baseTotalMs + delta;
            if (candTotalMs < 3500 || candTotalMs > 9000) continue;
            if (requireMultipleOf5 && candTotalMs % 5 !== 0) continue;
            const candMeanTtk = Number((candTotalMs / 5000).toFixed(3));
            if (candMeanTtk < minTtk || candMeanTtk > maxTtk) continue;
            const actualI = Math.max(0, Math.min(1, (1.8 - candMeanTtk) / 1.1));
            const actualMult = 1.0 + 1.6 * Math.pow(actualI, 1.4);
            if (Math.round(s * actualMult * 2.0) === T) {
                chosenS = s;
                chosenTotalTtkMs = Math.round(candMeanTtk * 5000);
                chosenTtkMult = Number(actualMult.toFixed(4));
                return true;
            }
        }
        return false;
    };

    for (let s = maxMatchScore - 5; s >= 800; s--) {
        if (tryCandidateS(s, 0.71, 1.18, true)) {
            solved = true;
            break;
        }
    }

    if (!solved) {
        for (let s = maxMatchScore; s >= 500; s--) {
            if (tryCandidateS(s, 0.70, 1.80, true)) {
                solved = true;
                break;
            }
        }
    }

    if (!solved) {
        for (let s = maxMatchScore; s >= 300; s--) {
            if (tryCandidateS(s, 0.70, 1.80, false)) {
                solved = true;
                break;
            }
        }
    }

    const totalTtkMs = chosenTotalTtkMs;
    const meanTtk = Number((totalTtkMs / 5000).toFixed(3));
    const bestTtk = Number((meanTtk * 0.72).toFixed(3));
    const bestTtkMs = Math.round(bestTtk * 1000);

    const remMs = totalTtkMs - bestTtkMs;
    const remBase = Math.floor(remMs / 4);
    const remOffsets = [-34, -11, 14, 31];
    const otherFour = remOffsets.map(off => Math.max(bestTtkMs + 10, remBase + off));
    const otherSum = otherFour.reduce((a, b) => a + b, 0);
    otherFour[3] += remMs - otherSum;
    if (otherFour[3] < bestTtkMs) {
        const deficit = bestTtkMs - otherFour[3];
        otherFour[3] = bestTtkMs;
        otherFour[2] = Math.max(bestTtkMs, otherFour[2] - deficit);
    }
    const shotTtksMs = [bestTtkMs, ...otherFour].sort((a, b) => a - b);

    const cumulativeMs: number[] = [];
    let cursorMs = 1150;
    const interKillGaps = [0, 1420, 1680, 1340, 1590];
    for (let k = 0; k < 5; k++) {
        cursorMs += interKillGaps[k] + shotTtksMs[k];
        cumulativeMs.push(cursorMs);
    }

    return {
        v: 2,
        total: T,
        matchScore: chosenS,
        accMult: 2,
        ttkMult: chosenTtkMult,
        kills: 5,
        takeovers: 5,
        whiffs: 0,
        shots: 5,
        hits: 5,
        acc: 100,
        hs: 100,
        meanTtk,
        bestTtk,
        ace: true,
        flawless: true,
        team: meta.team,
        experience: meta.experience,
        levelId: meta.aceTag,
        at: Date.now(),
        previouslyCompleted: true,
        shotTtksMs,
        cumulativeMs
    };
}

interface AriseSessionTelemetryState {
    sessionId: string;
    deviceId: string;
    userId: string;
    universeId: string;
    appVersion: string;
    sessionDurationMs: number;
}

const ariseTelemetrySessionByUser = new Map<string, AriseSessionTelemetryState>();

function getOrCreateAriseSessionState(
    userKey: string,
    deviceIdHint?: string,
    universeId = DEFAULT_UNIVERSE_ID,
    appVersion = DEFAULT_ARISE_CLIENT
): AriseSessionTelemetryState {
    const key = userKey || "default";
    let state = ariseTelemetrySessionByUser.get(key);
    if (!state) {
        state = {
            sessionId: randomUUID(),
            deviceId: deviceIdHint || randomUUID(),
            userId: userKey !== "default" ? userKey : "",
            universeId,
            appVersion,
            sessionDurationMs: 48000 + Math.floor(Math.random() * 24000)
        };
        ariseTelemetrySessionByUser.set(key, state);
    } else {
        if (deviceIdHint) state.deviceId = deviceIdHint;
        if (userKey && userKey !== "default") state.userId = userKey;
        if (universeId) state.universeId = universeId;
        if (appVersion) state.appVersion = appVersion;
    }
    return state;
}

async function sendAriseScrollV2Event(
    baseOrigin: string,
    ariseToken: string,
    buildHeaders: (token?: string, extra?: Record<string, string>) => Record<string, string>,
    state: AriseSessionTelemetryState,
    eventType: string,
    strings: string[],
    numbers: number[]
): Promise<void> {
    state.sessionDurationMs += 1400 + Math.floor(Math.random() * 1900);
    const body = JSON.stringify({
        sessionId: state.sessionId,
        deviceId: state.deviceId,
        eventType,
        userId: state.userId || undefined,
        universeId: state.universeId || DEFAULT_UNIVERSE_ID,
        deviceType: "desktop",
        timestamp: Date.now(),
        sessionDuration: state.sessionDurationMs,
        platform: "discord",
        metadata: { strings, numbers },
        appVersion: state.appVersion || DEFAULT_ARISE_CLIENT,
        isExternal: true
    });
    await fetch(`${baseOrigin}/.proxy/api/scrollv2`, {
        method: "POST",
        headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
        body,
        signal: AbortSignal.timeout(8000)
    }).catch(() => null);
}

async function sendAriseScrollV2RunTelemetry(
    baseOrigin: string,
    ariseToken: string,
    buildHeaders: (token?: string, extra?: Record<string, string>) => Record<string, string>,
    meta: ValorantAcesBoardMeta,
    run: SolvedShotScoreRun,
    state: AriseSessionTelemetryState
): Promise<void> {
    await sendAriseScrollV2Event(
        baseOrigin,
        ariseToken,
        buildHeaders,
        state,
        "play_player",
        [meta.playerName, meta.teamCode, meta.aceTag],
        []
    );
    for (let i = 0; i < 5; i++) {
        await sendAriseScrollV2Event(
            baseOrigin,
            ariseToken,
            buildHeaders,
            state,
            "shot_taken",
            ["headshot"],
            [run.shotTtksMs[i], run.cumulativeMs[i]]
        );
    }
    await sendAriseScrollV2Event(
        baseOrigin,
        ariseToken,
        buildHeaders,
        state,
        "completed",
        [meta.aceTag, meta.team.toLowerCase()],
        [run.total, 1, run.total, 100, Number(run.meanTtk.toFixed(3)), Number(run.bestTtk.toFixed(3)), 0]
    );
}

function extractSubFromJwt(jwt: string): string {
    try {
        if (!jwt || jwt.split(".").length !== 3) return "";
        const payloadJson = Buffer.from(jwt.split(".")[1], "base64url").toString("utf8");
        const payload = JSON.parse(payloadJson);
        return typeof payload?.sub === "string" ? payload.sub.trim() : "";
    } catch {
        return "";
    }
}

interface BoardTargetResolution {
    meta: ValorantAcesBoardMeta;
    otherTopScore: number;
    myCurrentScore: number | null;
    myCurrentPosition: number | null;
    targetScore: number;
    shouldSubmit: boolean;
    solvedRun: SolvedShotScoreRun;
}

const resolvedTargetsCache = new Map<string, { at: number; resolutions: BoardTargetResolution[] }>();
const unlockedProfileRewardsByUser = new Set<string>();

async function resolveTargetScoresForBoards(
    baseOrigin: string,
    ariseToken: string,
    buildHeaders: (token?: string, extra?: Record<string, string>) => Record<string, string>,
    scoreMode: ActivityScoreMode = "top1_plus_1",
    customScore = 24500
): Promise<BoardTargetResolution[]> {
    const myUserId = extractSubFromJwt(ariseToken);
    const cacheKey = `${myUserId || "anon"}:${scoreMode}:${customScore}`;
    const cached = resolvedTargetsCache.get(cacheKey);
    if (cached && Date.now() - cached.at < 20000 && ariseToken) {
        return cached.resolutions;
    }

    const resolutions = await Promise.all(
        VALORANT_ACES_BOARDS.map(async (meta): Promise<BoardTargetResolution> => {
            let otherTopScore = meta.fallbackTop2;
            let myCurrentScore: number | null = null;
            let myCurrentPosition: number | null = null;

            if (ariseToken) {
                try {
                    const res = await fetch(`${baseOrigin}/.proxy/api/leaderboards/${meta.boardId}`, {
                        method: "GET",
                        headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(undefined) }),
                        signal: AbortSignal.timeout(8000)
                    });
                    if (res.ok) {
                        const data: any = await res.json().catch(() => null);
                        if (data) {
                            const { me } = data;
                            if (me && typeof me.score === "number") {
                                myCurrentScore = me.score;
                            }
                            if (me && typeof me.position === "number") {
                                myCurrentPosition = me.position;
                            }

                            const candidates: number[] = [];
                            const collect = (arr: any[]) => {
                                if (!Array.isArray(arr)) return;
                                for (const entry of arr) {
                                    if (!entry || typeof entry.score !== "number") continue;
                                    if (myUserId && entry.userId === myUserId) continue;
                                    if (me?.userId && entry.userId === me.userId) continue;
                                    candidates.push(entry.score);
                                }
                            };
                            collect(data.topN);
                            collect(me?.surrounding?.above);
                            collect(me?.surrounding?.below);

                            if (candidates.length > 0) {
                                otherTopScore = Math.max(...candidates);
                            }
                        }
                    }
                } catch {}
            }

            let targetScore: number;
            if (scoreMode === "custom") {
                const rawCustom = Math.round(Number(customScore) || 24500);
                targetScore = Math.max(1000, Math.min(meta.ceiling - 1, rawCustom));
            } else if (scoreMode === "legit_pro") {
                targetScore = meta.legitProScore;
            } else {
                targetScore = Math.max(1000, Math.min(meta.ceiling - 50, otherTopScore + 1));
            }

            let shouldSubmit = false;
            if (scoreMode === "quest_only") {
                shouldSubmit = false;
            } else if (scoreMode === "top1_plus_1") {
                if (myCurrentPosition === 1 && myCurrentScore !== null && myCurrentScore > otherTopScore) {
                    shouldSubmit = false;
                } else if (myCurrentScore === null || myCurrentScore <= otherTopScore) {
                    shouldSubmit = true;
                }
            } else {
                if (myCurrentScore === null || myCurrentScore < targetScore) {
                    shouldSubmit = true;
                }
            }

            const solvedRun = solveShotScoreRun(targetScore, meta);
            return {
                meta,
                otherTopScore,
                myCurrentScore,
                myCurrentPosition,
                targetScore,
                shouldSubmit,
                solvedRun
            };
        })
    );

    if (ariseToken) {
        resolvedTargetsCache.set(cacheKey, { at: Date.now(), resolutions });
    }
    return resolutions;
}

async function unlockAllAriseRewardsAndScores(
    baseOrigin: string,
    ariseToken: string,
    buildHeaders: (token?: string, extra?: Record<string, string>) => Record<string, string>,
    isValorantAces = true,
    scoreMode: ActivityScoreMode = "top1_plus_1",
    customScore = 24500,
    deviceIdHint?: string
): Promise<BoardTargetResolution[]> {
    let resolutions: BoardTargetResolution[] = [];
    try {
        const userKey = extractSubFromJwt(ariseToken) || "default";
        const sampleHeaders = buildHeaders(ariseToken);
        const universeId = sampleHeaders["X-Universe-ID"] || DEFAULT_UNIVERSE_ID;
        const appVersion = sampleHeaders["X-Arise-Client"] || DEFAULT_ARISE_CLIENT;

        const requests: Promise<any>[] = [];
        const profileKey = `${baseOrigin}:${userKey}:${isValorantAces ? "aces" : "generic"}`;
        if (!unlockedProfileRewardsByUser.has(profileKey)) {
            unlockedProfileRewardsByUser.add(profileKey);
            requests.push(
                fetch(`${baseOrigin}/.proxy/api/profile/mission-completed`, {
                    method: "POST",
                    headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(undefined) }),
                    body: undefined,
                    signal: AbortSignal.timeout(8000)
                }).catch(() => null)
            );

            if (isValorantAces) {
                requests.push(
                    ...VALORANT_ACES_TITLES.map(id => {
                        const body = JSON.stringify({ id });
                        return fetch(`${baseOrigin}/.proxy/api/profileTitle/add`, {
                            method: "POST",
                            headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
                            body,
                            signal: AbortSignal.timeout(8000)
                        }).catch(() => null);
                    }),
                    ...VALORANT_ACES_BADGES.map(rank => {
                        const body = JSON.stringify({ rank });
                        return fetch(`${baseOrigin}/.proxy/api/profileBadge/add`, {
                            method: "POST",
                            headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
                            body,
                            signal: AbortSignal.timeout(8000)
                        }).catch(() => null);
                    })
                );
            }
        }

        if (isValorantAces) {
            resolutions = await resolveTargetScoresForBoards(baseOrigin, ariseToken, buildHeaders, scoreMode, customScore);
            if (scoreMode !== "quest_only") {
                const sessionState = getOrCreateAriseSessionState(userKey, deviceIdHint, universeId, appVersion);

                for (const item of resolutions) {
                    if (!item.shouldSubmit) continue;
                    item.shouldSubmit = false;
                    item.myCurrentScore = Math.max(item.myCurrentScore ?? 0, item.targetScore);

                    await sendAriseScrollV2RunTelemetry(
                        baseOrigin,
                        ariseToken,
                        buildHeaders,
                        item.meta,
                        item.solvedRun,
                        sessionState
                    );
                    const submitBody = JSON.stringify({ score: item.targetScore });
                    await fetch(`${baseOrigin}/.proxy/api/leaderboards/${item.meta.boardId}/submit`, {
                        method: "POST",
                        headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(submitBody) }),
                        body: submitBody,
                        signal: AbortSignal.timeout(8000)
                    }).catch(() => null);
                }
            }
        }

        if (requests.length > 0) {
            await Promise.allSettled(requests);
        }
    } catch {}
    return resolutions;
}

export async function syncActivityMaxRecords(
    event: IpcMainInvokeEvent,
    applicationId = VALORANT_ACES_APP_ID,
    scoreMode: ActivityScoreMode = "top1_plus_1",
    customScore = 24500
): Promise<{ ok: boolean; syncedFrames: number; pcSyncedFrames: number }> {
    const appIdStr = String(applicationId || VALORANT_ACES_APP_ID);
    if (!/^\d+$/.test(appIdStr)) {
        return { ok: false, syncedFrames: 0, pcSyncedFrames: 0 };
    }

    const mainFrame = event?.sender?.mainFrame;
    if (!mainFrame || !Array.isArray(mainFrame.framesInSubtree)) {
        return { ok: false, syncedFrames: 0, pcSyncedFrames: 0 };
    }

    const matchesActivityUrl = (url: string): boolean =>
        url.includes(`${appIdStr}.discordsays.com`) || url.includes("ariseworlds.com");

    const targetFrames = mainFrame.framesInSubtree.filter(frame => {
        try {
            let cur: any = frame;
            while (cur) {
                const url = String(cur?.url || "");
                if (matchesActivityUrl(url)) return true;
                cur = cur.parent;
            }
            return false;
        } catch {
            return false;
        }
    });

    if (targetFrames.length === 0) {
        return { ok: true, syncedFrames: 0, pcSyncedFrames: 0 };
    }

    const probeScript = `
(function() {
    try {
        const tok = window.localStorage.getItem("ARISEENGINE_AUTHTOKEN") || "";
        const devId = window.localStorage.getItem("ARISE_DEVICE_ID") || "";
        let uid = "";
        if (tok && tok.split(".").length === 3) {
            const b64 = tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            const payload = JSON.parse(atob(b64));
            if (payload && typeof payload.sub === "string" && payload.sub.trim()) {
                uid = payload.sub.trim();
            }
        }
        if (!uid) {
            const cand = window.userData?.userId || window.pc?.Application?.getApplication?.()?.spadesAccountId;
            if (typeof cand === "string" && cand.trim()) uid = cand.trim();
        }
        if (!uid) {
            for (let i = 0; i < window.localStorage.length; i++) {
                const k = window.localStorage.key(i) || "";
                const m = k.match(/^globalaces\\.runs\\.v1\\.user\\.(.+)$/);
                if (m && m[1]) {
                    uid = decodeURIComponent(m[1]);
                    break;
                }
            }
        }
        return { uid, tok, devId };
    } catch {}
    return { uid: "", tok: "", devId: "" };
})();
`;

    let hostUserId = "";
    let discoveredToken = "";
    let discoveredDeviceId = "";
    for (const frame of targetFrames) {
        try {
            const probed: any = await frame.executeJavaScript(probeScript, true);
            if (probed?.uid && !hostUserId) hostUserId = String(probed.uid).trim();
            if (probed?.tok && !discoveredToken) discoveredToken = String(probed.tok).trim();
            if (probed?.devId && !discoveredDeviceId) discoveredDeviceId = String(probed.devId).trim();
            if (hostUserId && discoveredToken && discoveredDeviceId) break;
        } catch {}
    }

    const baseOrigin = `https://${appIdStr}.discordsays.com`;
    const buildSimpleHeaders = (token = "", extra: Record<string, string> = {}) => ({
        "Content-Type": "application/json",
        "Accept": "*/*",
        "X-Auth-Token": token,
        "X-Universe-ID": DEFAULT_UNIVERSE_ID,
        "X-Discord-Activity-Id": appIdStr,
        "X-Discord-Hostname": `${appIdStr}.discordsays.com`,
        "X-Arise-Client": DEFAULT_ARISE_CLIENT,
        "Origin": baseOrigin,
        "Referer": `${baseOrigin}/`,
        ...extra
    });

    const resolutions = await resolveTargetScoresForBoards(
        baseOrigin,
        discoveredToken,
        buildSimpleHeaders,
        scoreMode,
        customScore
    );

    const levelScoresMap: Record<string, number> = {};
    const solvedRunsList: Omit<SolvedShotScoreRun, "shotTtksMs" | "cumulativeMs">[] = [];
    for (const item of resolutions) {
        levelScoresMap[item.meta.aceTag] = item.solvedRun.total;
        const { shotTtksMs: _s, cumulativeMs: _c, ...cleanRun } = item.solvedRun;
        solvedRunsList.push(cleanRun);
    }
    const bestOverallRun = solvedRunsList.reduce((best, cur) => (cur.total > best.total ? cur : best), solvedRunsList[0]);

    const injectionScript = `
(function() {
    try {
        const HOST_USER_ID = ${JSON.stringify(hostUserId)};
        const TITLES = ${JSON.stringify(VALORANT_ACES_TITLES)};
        const BADGES = ${JSON.stringify(VALORANT_ACES_BADGES)};
        const LEVEL_SCORES = ${JSON.stringify(levelScoresMap)};
        const SOLVED_RUNS = ${JSON.stringify(solvedRunsList)};
        const BEST_RUN = ${JSON.stringify(bestOverallRun)};
        const MAX_SCORE = BEST_RUN.total;

        let userId = "";
        let ariseToken = "";
        try {
            ariseToken = window.localStorage.getItem("ARISEENGINE_AUTHTOKEN") || "";
            if (ariseToken && ariseToken.split(".").length === 3) {
                const b64 = ariseToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
                const payload = JSON.parse(atob(b64));
                if (payload && typeof payload.sub === "string" && payload.sub.trim()) {
                    userId = payload.sub.trim();
                }
            }
        } catch {}

        if (!userId) {
            try {
                const candidate = window.userData?.userId || window.pc?.Application?.getApplication?.()?.spadesAccountId || HOST_USER_ID;
                if (typeof candidate === "string" && candidate.trim()) {
                    userId = candidate.trim();
                }
            } catch {}
        }

        const levelsObj = {};
        for (const [lvl, bestScore] of Object.entries(LEVEL_SCORES)) {
            levelsObj[lvl] = { played: true, completed: true, bestScore };
        }

        const runsPayload = JSON.stringify({
            v: 2,
            best: BEST_RUN,
            runs: SOLVED_RUNS,
            levels: levelsObj
        });

        const sentMap = {};
        for (const t of TITLES) sentMap[t] = true;
        const sentPayload = JSON.stringify({
            v: 3,
            sent: sentMap,
            quest: {
                runs: 10,
                done: true,
                releaseKey: "release-02",
                firstQuestCompleted: true
            }
        });

        const writeStorageForUser = (win, uid) => {
            try {
                const ls = win?.localStorage;
                if (!ls) return;
                const discoveredUids = [];
                for (let i = 0; i < ls.length; i++) {
                    const k = ls.key(i) || "";
                    const m = k.match(/^(?:globalaces\\.runs\\.v1|globalAces\\.bestCombatScore|globalaces\\.arise\\.sent\\.v1)\\.user\\.(.+)$/);
                    if (m && m[1]) {
                        try { discoveredUids.push(decodeURIComponent(m[1])); } catch {}
                    }
                }
                const uidList = Array.from(new Set([uid, userId, HOST_USER_ID, ...discoveredUids].filter(Boolean)));
                for (const u of uidList) {
                    const uidEnc = encodeURIComponent(u);
                    ls.setItem("globalaces.runs.v1.user." + uidEnc, runsPayload);
                    ls.setItem("globalAces.bestCombatScore.user." + uidEnc, String(MAX_SCORE));
                    ls.setItem("globalaces.arise.sent.v1.user." + uidEnc, sentPayload);
                }
                ls.setItem("globalaces.runs.v1", runsPayload);
                ls.setItem("globalAces.bestCombatScore", String(MAX_SCORE));
                ls.setItem("globalaces.arise.sent.v1", sentPayload);
            } catch {}
        };

        writeStorageForUser(window, userId);

        const refreshPlayCanvasWindow = (win) => {
            try {
                const pcApp = win?.pc?.Application?.getApplication?.();
                if (!pcApp?.root) return false;
                const activeUid = pcApp.spadesAccountId || userId;
                if (activeUid) {
                    pcApp.spadesAccountId = activeUid;
                }
                writeStorageForUser(win, activeUid);

                const applyToPc = (targetUid) => {
                    const u = targetUid || pcApp.spadesAccountId || userId;
                    const uidEnc = u ? encodeURIComponent(u) : "";
                    writeStorageForUser(win, u);
                    let touched = false;

                    const allNodes = [];
                    const walk = (node) => {
                        if (!node) return;
                        allNodes.push(node);
                        const ch = node.children || node._children || [];
                        for (let i = 0; i < ch.length; i++) walk(ch[i]);
                    };
                    walk(pcApp.root);

                    for (const node of allNodes) {
                        const scr = node?.script;
                        if (!scr) continue;
                        if (scr.runHistory) {
                            const rh = scr.runHistory;
                            const baseKey = rh._accountBaseKey || rh._baseStorageKey || "globalaces.runs.v1";
                            if (u) {
                                rh._accountUserId = u;
                                rh._accountId = u;
                                rh._accountReady = true;
                                rh.storageKey = baseKey + ".user." + uidEnc;
                                rh._storageKey = rh.storageKey;
                            } else {
                                rh.storageKey = baseKey;
                                rh._storageKey = baseKey;
                            }
                            rh._runs = [];
                            rh._stored = null;
                            rh._storedRuns = [];
                            rh._levels = Object.create(null);
                            rh._prev = null;
                            rh._storageOk = true;
                            if (typeof rh._load === "function") rh._load();
                            touched = true;
                        }
                        if (scr.shotScore) {
                            const ss = scr.shotScore;
                            const baseHsKey = ss._accountBaseHighKey || ss._baseHighScoreKey || "globalAces.bestCombatScore";
                            if (u) {
                                ss._accountUserId = u;
                                ss._accountId = u;
                                ss._accountReady = true;
                                ss.highScoreKey = baseHsKey + ".user." + uidEnc;
                                ss._highScoreKey = ss.highScoreKey;
                            } else {
                                ss.highScoreKey = baseHsKey;
                                ss._highScoreKey = baseHsKey;
                            }
                            if (typeof ss._loadHigh === "function") ss._high = ss._loadHigh();
                            touched = true;
                        }
                        if (scr.ariseRewards) {
                            const ar = scr.ariseRewards;
                            const baseArKey = ar._accountBaseKey || ar._baseStorageKey || "globalaces.arise.sent.v1";
                            if (u) {
                                ar._accountUserId = u;
                                ar._accountId = u;
                                ar._accountReady = true;
                                ar.storageKey = baseArKey + ".user." + uidEnc;
                                ar._storageKey = ar.storageKey;
                            } else {
                                ar.storageKey = baseArKey;
                                ar._storageKey = baseArKey;
                            }
                            if (typeof ar._load === "function") ar._load();
                            touched = true;
                        }
                        if (scr.ariseLeaderboard && scr.ariseLeaderboard._cache) {
                            scr.ariseLeaderboard._cache = Object.create(null);
                        }
                    }

                    for (const node of allNodes) {
                        const es = node?.script?.experienceSelect;
                        if (!es) continue;
                        if (es._launchPreview && typeof es.setLaunchPreview === "function") {
                            es.setLaunchPreview(false);
                        }
                        if (typeof es._refreshProgress === "function") {
                            es._refreshProgress();
                        }
                        touched = true;
                    }

                    if (typeof pcApp.fire === "function") {
                        pcApp.fire("level:recorded", BEST_RUN);
                    }
                    return touched;
                };

                if (!pcApp.__vcMaxRecordsHooked && typeof pcApp.on === "function") {
                    pcApp.__vcMaxRecordsHooked = true;
                    pcApp.on("spades:accountChanged", (info) => {
                        try {
                            const nextUid = (info && (info.userId || info.id)) || pcApp.spadesAccountId || userId;
                            applyToPc(nextUid);
                            setTimeout(() => applyToPc(nextUid), 50);
                        } catch {}
                    });
                }

                return applyToPc(activeUid);
            } catch {
                return false;
            }
        };

        let pcSynced = refreshPlayCanvasWindow(window);
        try {
            const subIframes = Array.from(document.querySelectorAll("iframe"));
            for (const sub of subIframes) {
                if (sub?.contentWindow && refreshPlayCanvasWindow(sub.contentWindow)) {
                    pcSynced = true;
                }
            }
        } catch {}

        return { ok: true, pcSynced };
    } catch (e) {
        return { ok: false, pcSynced: false };
    }
})();
`;

    let syncedFrames = 0;
    let pcSyncedFrames = 0;
    for (const frame of targetFrames) {
        try {
            const res: any = await frame.executeJavaScript(injectionScript, true);
            if (res && res.ok) {
                syncedFrames++;
                if (res.pcSynced) pcSyncedFrames++;
            }
        } catch {}
    }

    if (discoveredToken) {
        await unlockAllAriseRewardsAndScores(
            baseOrigin,
            discoveredToken,
            buildSimpleHeaders,
            appIdStr === VALORANT_ACES_APP_ID,
            scoreMode,
            customScore,
            discoveredDeviceId
        ).catch(() => null);
    }

    return { ok: syncedFrames > 0, syncedFrames, pcSyncedFrames };
}

export async function completeActivityQuest(
    event: IpcMainInvokeEvent,
    applicationId: string,
    questId: string,
    oauthCode: string,
    target = 1,
    scoreMode: ActivityScoreMode = "top1_plus_1",
    customScore = 24500
): Promise<{ ok: boolean; status?: number; message?: string; step?: string }> {
    if (!applicationId || !/^\d+$/.test(String(applicationId))) {
        return { ok: false, message: "Invalid applicationId", step: "validate" };
    }
    if (!questId || !/^\d+$/.test(String(questId))) {
        return { ok: false, message: "Invalid questId", step: "validate" };
    }
    if (!oauthCode || typeof oauthCode !== "string") {
        return { ok: false, message: "Missing OAuth2 authorization code", step: "validate" };
    }

    const appIdStr = String(applicationId);
    const questIdStr = String(questId);
    const baseOrigin = `https://${appIdStr}.discordsays.com`;
    const { universeId, appVersion } = await discoverAriseMetadata(baseOrigin);

    const buildHeaders = (token = "", extra: Record<string, string> = {}) => ({
        "Content-Type": "application/json",
        "Accept": "*/*",
        "X-Auth-Token": token,
        "X-Universe-ID": universeId,
        "X-Discord-Activity-Id": appIdStr,
        "X-Discord-Hostname": `${appIdStr}.discordsays.com`,
        "X-Arise-Client": appVersion,
        "Origin": baseOrigin,
        "Referer": `${baseOrigin}/`,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9265 Chrome/148.0.7778.280 Electron/42.11.15 Safari/537.36",
        ...extra
    });

    try {
        const authRes = await fetch(`${baseOrigin}/.proxy/acf/authorize`, {
            method: "POST",
            headers: buildHeaders(""),
            body: JSON.stringify({ code: oauthCode, activityId: appIdStr }),
            signal: AbortSignal.timeout(12000)
        });
        const authText = await authRes.text();
        let authData: any = null;
        try {
            authData = JSON.parse(authText);
        } catch {}

        const acfToken: string = authData?.token || authData?.authToken || "";
        if (!authRes.ok || !acfToken) {
            return {
                ok: false,
                status: authRes.status,
                message: authData?.message || authText || "Failed to authorize with Activity backend",
                step: "authorize"
            };
        }

        let ariseToken = acfToken;
        try {
            const regRes = await fetch(`${baseOrigin}/.proxy/acf/arise/register`, {
                method: "POST",
                headers: buildHeaders(acfToken),
                signal: AbortSignal.timeout(10000)
            });
            if (regRes.ok) {
                const regData: any = await regRes.json().catch(() => null);
                if (regData?.authToken) {
                    ariseToken = regData.authToken;
                }
            }
        } catch {}

        const isValorantAces = appIdStr === VALORANT_ACES_APP_ID;
        await unlockAllAriseRewardsAndScores(baseOrigin, ariseToken, buildHeaders, isValorantAces, scoreMode, customScore);
        if (isValorantAces) {
            await syncActivityMaxRecords(event, appIdStr, scoreMode, customScore).catch(() => null);
        }

        const progressValue = Math.max(1, Number(target) || 1);
        const progRes = await fetch(`${baseOrigin}/.proxy/acf/quest/progress`, {
            method: "POST",
            headers: buildHeaders(acfToken),
            body: JSON.stringify({ progress: progressValue, quest_id: questIdStr }),
            signal: AbortSignal.timeout(12000)
        });
        const progText = await progRes.text();
        let progData: any = null;
        try {
            progData = JSON.parse(progText);
        } catch {}

        const ok = progRes.ok && (progData?.status === "ok" || progData?.success !== false);
        return {
            ok,
            status: progRes.status,
            message: progData?.message || progData?.status || progText,
            step: "progress"
        };
    } catch (err: any) {
        return {
            ok: false,
            message: String(err?.message || err),
            step: "exception"
        };
    }
}

installMainProcessUpdaterAndStealthHooks();
installActivityCorsAndPreflightBypass();

