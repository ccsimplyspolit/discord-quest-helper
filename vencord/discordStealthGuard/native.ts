/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ConnectSrc, CspPolicies } from "@main/csp";
import { execFileSync } from "child_process";
import { createHash, randomBytes } from "crypto";
import { IpcMainInvokeEvent } from "electron";
import * as fs from "fs";
import Module from "module";
import * as os from "os";

CspPolicies["*.discordsays.com"] = ConnectSrc;
CspPolicies["https://*.discordsays.com"] = ConnectSrc;
CspPolicies["wss://*.discordsays.com"] = ConnectSrc;

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
                            fileSize = BigInt(stat.size);
                            const numSections = buf.readUInt16LE(e_lfanew + 6);
                            timeDateStamp = buf.readUInt32LE(e_lfanew + 8);
                            const sizeOfOpt = buf.readUInt16LE(e_lfanew + 0x14);
                            const magic = buf.readUInt16LE(e_lfanew + 0x18);
                            sizeOfImage = buf.readUInt32LE(e_lfanew + 0x50);
                            isPe64 = magic === 0x020b;

                            const hdrEnd = Math.min(readLen, e_lfanew + 0x18 + sizeOfOpt);
                            hdrSha256 = sha256(buf.subarray(0, hdrEnd));

                            const secStart = e_lfanew + 0x18 + sizeOfOpt;
                            const secEnd = secStart + numSections * 40;
                            if (secEnd <= readLen) {
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

const DEFAULT_UNIVERSE_ID = "78a74ba6-b027-4b0e-a686-9a6f4124c068";
const DEFAULT_ARISE_CLIENT = "spades-prod-main-4835c58";

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

const VALORANT_ACES_LEADERBOARD_SCORES: Readonly<Record<string, number>> = {
    "ace-1": 25766,
    "ace-2": 25766,
    "ace-3": 25766,
    "ace-4": 25766,
    "ace-5": 25766,
    "ace-6": 25766,
    "ace-7": 25137,
    "ace-8": 25137,
    "ace-9": 25766,
    "ace-10": 23748
};

const VALORANT_ACES_LEVEL_SCORES: Readonly<Record<string, number>> = {
    "ace:01": 25766,
    "ace:02": 25766,
    "ace:03": 25766,
    "ace:04": 25766,
    "ace:05": 25766,
    "ace:06": 25137,
    "ace:07": 25137,
    "ace:08": 25766,
    "ace:09": 25766,
    "ace:10": 23748
};

async function unlockAllAriseRewardsAndScores(
    baseOrigin: string,
    ariseToken: string,
    buildHeaders: (token?: string, extra?: Record<string, string>) => Record<string, string>
): Promise<void> {
    try {
        await Promise.allSettled([
            ...VALORANT_ACES_TITLES.map(id => {
                const body = JSON.stringify({ id });
                return fetch(`${baseOrigin}/.proxy/api/profileTitle/add`, {
                    method: "POST",
                    headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
                    body,
                    signal: AbortSignal.timeout(8000)
                });
            }),
            ...VALORANT_ACES_BADGES.map(rank => {
                const body = JSON.stringify({ rank });
                return fetch(`${baseOrigin}/.proxy/api/profileBadge/add`, {
                    method: "POST",
                    headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
                    body,
                    signal: AbortSignal.timeout(8000)
                });
            }),
            ...Object.entries(VALORANT_ACES_LEADERBOARD_SCORES).map(([board, score]) => {
                const body = JSON.stringify({ score });
                return fetch(`${baseOrigin}/.proxy/api/leaderboards/${board}/submit`, {
                    method: "POST",
                    headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(body) }),
                    body,
                    signal: AbortSignal.timeout(8000)
                });
            }),
            fetch(`${baseOrigin}/.proxy/api/profile/mission-completed`, {
                method: "POST",
                headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(undefined) }),
                body: undefined,
                signal: AbortSignal.timeout(8000)
            })
        ]);
    } catch {}
}

export async function syncActivityMaxRecords(
    event: IpcMainInvokeEvent,
    applicationId = "1536318183873454090"
): Promise<{ ok: boolean; syncedFrames: number; pcSyncedFrames: number }> {
    const appIdStr = String(applicationId || "1536318183873454090");
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
        if (tok && tok.split(".").length === 3) {
            const b64 = tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            const payload = JSON.parse(atob(b64));
            if (payload && typeof payload.sub === "string" && payload.sub.trim()) {
                return payload.sub.trim();
            }
        }
        const cand = window.userData?.userId || window.pc?.Application?.getApplication?.()?.spadesAccountId;
        if (typeof cand === "string" && cand.trim()) return cand.trim();
    } catch {}
    return "";
})();
`;

    let hostUserId = "";
    for (const frame of targetFrames) {
        try {
            const uid = await frame.executeJavaScript(probeScript, true);
            if (typeof uid === "string" && uid.trim()) {
                hostUserId = uid.trim();
                break;
            }
        } catch {}
    }

    const injectionScript = `
(function() {
    try {
        const FALLBACK_USER_ID = "612ee591-cc52-4b49-a285-395035377abd";
        const HOST_USER_ID = ${JSON.stringify(hostUserId)};
        const TITLES = ${JSON.stringify(VALORANT_ACES_TITLES)};
        const BADGES = ${JSON.stringify(VALORANT_ACES_BADGES)};
        const BOARD_SCORES = ${JSON.stringify(VALORANT_ACES_LEADERBOARD_SCORES)};
        const LEVEL_SCORES = ${JSON.stringify(VALORANT_ACES_LEVEL_SCORES)};
        const MAX_SCORE = 25766;

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
        if (!userId) {
            userId = FALLBACK_USER_ID;
        }

        const levelsObj = {};
        for (const [lvl, bestScore] of Object.entries(LEVEL_SCORES)) {
            levelsObj[lvl] = { played: true, completed: true, bestScore };
        }

        const runsPayload = JSON.stringify({
            v: 2,
            best: {
                v: 2,
                total: MAX_SCORE,
                matchScore: 4955,
                accMult: 2,
                ttkMult: 2.6,
                kills: 5,
                takeovers: 5,
                whiffs: 0,
                shots: 5,
                hits: 5,
                acc: 100,
                hs: 100,
                meanTtk: 0.15,
                bestTtk: 0.12,
                ace: true,
                flawless: true,
                team: "ALPHA",
                experience: "MADRID 24",
                levelId: "ace:03",
                at: Date.now(),
                previouslyCompleted: true
            },
            runs: [],
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
                const uidList = Array.from(new Set([uid, userId, HOST_USER_ID, FALLBACK_USER_ID].filter(Boolean)));
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
                pcApp.spadesAccountId = activeUid;
                writeStorageForUser(win, activeUid);

                const applyToPc = (targetUid) => {
                    const u = targetUid || pcApp.spadesAccountId || userId;
                    const uidEnc = encodeURIComponent(u);
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
                            rh._accountId = u;
                            rh._accountReady = true;
                            rh._storageKey = (rh._baseStorageKey || "globalaces.runs.v1") + ".user." + uidEnc;
                            if (typeof rh._load === "function") rh._load();
                            touched = true;
                        }
                        if (scr.shotScore) {
                            const ss = scr.shotScore;
                            ss._accountId = u;
                            ss._accountReady = true;
                            ss._highScoreKey = (ss._baseHighScoreKey || "globalAces.bestCombatScore") + ".user." + uidEnc;
                            if (typeof ss._loadHigh === "function") ss._high = ss._loadHigh();
                            touched = true;
                        }
                        if (scr.ariseRewards) {
                            const ar = scr.ariseRewards;
                            ar._accountId = u;
                            ar._accountReady = true;
                            ar._storageKey = (ar._baseStorageKey || "globalaces.arise.sent.v1") + ".user." + uidEnc;
                            if (typeof ar._load === "function") ar._load();
                            touched = true;
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
                        pcApp.fire("level:recorded", null);
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

        if (ariseToken && !window.__vcAriseMaxSynced) {
            window.__vcAriseMaxSynced = true;
            const buildReqId = (bodyStr) => {
                const mask64 = (1n << 64n) - 1n;
                const bitPositions = [];
                for (let b = 127; b >= 0; b--) {
                    if (b !== 79 && b !== 78 && b !== 77 && b !== 76 && b !== 63 && b !== 62) {
                        bitPositions.push(BigInt(b));
                    }
                }
                const randBits = (bits) => {
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
                return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
            };

            const universeId = window.localStorage.getItem("ARISE_UNIVERSEID") || "${DEFAULT_UNIVERSE_ID}";
            const postApi = (path, payloadObj) => {
                const body = payloadObj !== undefined ? JSON.stringify(payloadObj) : undefined;
                return fetch("/.proxy/api" + path, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Auth-Token": ariseToken,
                        "X-Universe-ID": universeId,
                        "X-Request-Id": buildReqId(body)
                    },
                    body
                }).catch(() => null);
            };

            for (const id of TITLES) postApi("/profileTitle/add", { id });
            for (const rank of BADGES) postApi("/profileBadge/add", { rank });
            for (const [board, score] of Object.entries(BOARD_SCORES)) {
                postApi("/leaderboards/" + board + "/submit", { score });
            }
            postApi("/profile/mission-completed", undefined);
        }
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

    return { ok: syncedFrames > 0, syncedFrames, pcSyncedFrames };
}

export async function completeActivityQuest(
    event: IpcMainInvokeEvent,
    applicationId: string,
    questId: string,
    oauthCode: string,
    target = 1
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

        await unlockAllAriseRewardsAndScores(baseOrigin, ariseToken, buildHeaders);
        await syncActivityMaxRecords(event, appIdStr).catch(() => null);

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

