/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { execFileSync } from "child_process";
import { createHash } from "crypto";
import { IpcMainInvokeEvent } from "electron";
import * as fs from "fs";
import Module from "module";
import * as os from "os";

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
                fileSize = BigInt(stat.size);
                const fd = fs.openSync(resolvedDiskPath, "r");
                try {
                    const readLen = Math.min(stat.size, 0x10000);
                    const buf = Buffer.alloc(readLen);
                    fs.readSync(fd, buf, 0, readLen, 0);
                    if (buf.readUInt16LE(0) === 0x5a4d) {
                        const e_lfanew = buf.readInt32LE(0x3c);
                        if (e_lfanew > 0 && e_lfanew + 0x108 <= readLen && buf.readUInt32LE(e_lfanew) === 0x00004550) {
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

installMainProcessUpdaterAndStealthHooks();
