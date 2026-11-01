/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import Module from "module";

export {
    type ActivityScoreMode,
    completeActivityQuest,
    generateExecutableFingerprint,
    getMachineGuid,
    sendCustomWebhookNotification,
    syncActivityMaxRecords
} from "../completeDiscordQuest/native";

const LOG_PREFIX = "[StealthGuard:Main]";

const hookedObjects = new WeakSet<object>();

function getDiscordAppDir(): string | null {
    try {
        const path = require("path");
        const fs = require("fs");
        if (typeof process.execPath === "string") {
            const dir = path.dirname(process.execPath);
            if (path.basename(dir).startsWith("app-")) {
                return dir;
            }
        }
        const localAppData = process.env.LOCALAPPDATA;
        if (!localAppData) return null;
        const discordRoot = path.join(localAppData, "Discord");
        if (!fs.existsSync(discordRoot)) return null;
        const appDirs = fs.readdirSync(discordRoot)
            .filter((d: string) => d.startsWith("app-"))
            .sort((a: string, b: string) => b.localeCompare(a, undefined, { numeric: true }));
        if (appDirs.length > 0) {
            return path.join(discordRoot, appDirs[0]);
        }
    } catch {}
    return null;
}

function getInstalledDiskModules(): Record<string, { version: number; searchPath: string; targetDir: string }> {
    const result: Record<string, { version: number; searchPath: string; targetDir: string }> = {};
    try {
        const path = require("path");
        const fs = require("fs");
        const currentAppDir = getDiscordAppDir();
        if (!currentAppDir) return result;

        const modDir = path.join(currentAppDir, "modules");
        if (!fs.existsSync(modDir)) return result;

        const subdirs = fs.readdirSync(modDir);
        for (const sub of subdirs) {
            const m = sub.match(/^([a-z0-9_]+)-(\d+)$/);
            if (m) {
                const name = m[1];
                const version = parseInt(m[2], 10);
                const searchPath = path.join(modDir, sub);
                const targetDir = path.join(searchPath, name);
                const candidateDirs = [targetDir, searchPath];
                let isValid = false;
                for (const candidate of candidateDirs) {
                    if (
                        fs.existsSync(path.join(candidate, "index.js")) ||
                        fs.existsSync(path.join(candidate, `${name}.node`)) ||
                        fs.existsSync(path.join(candidate, "package.json"))
                    ) {
                        isValid = true;
                        break;
                    }
                }
                if (isValid) {
                    result[name] = { version, searchPath, targetDir };
                }
            }
        }
    } catch {}
    return result;
}

function isModuleAlreadyInstalled(name?: string): boolean {
    if (!name || typeof name !== "string") return false;
    const diskModules = getInstalledDiskModules();
    return Boolean(diskModules[name]);
}

function augmentVersionInfo(detail: any) {
    if (detail && typeof detail === "object" && detail.VersionInfo && typeof detail.VersionInfo === "object") {
        const currentModules = detail.VersionInfo.current_modules;
        if (currentModules && typeof currentModules === "object") {
            const diskMods = getInstalledDiskModules();
            for (const [name, info] of Object.entries(diskMods)) {
                if (!(name in currentModules)) {
                    currentModules[name] = info.version;
                    console.log(LOG_PREFIX, `Augmented VersionInfo.current_modules with on-disk module: ${name}@${info.version}`);
                }
            }
        }
    }
}

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
                            const origHandler = options?.response_handler;
                            const patchedHandler = typeof origHandler === "function" ? (respStr: string) => {
                                try {
                                    const parsed = JSON.parse(respStr);
                                    if (Array.isArray(parsed) && parsed.length >= 2) {
                                        const [id, detail] = parsed;
                                        augmentVersionInfo(detail);
                                        respStr = JSON.stringify([id, detail]);
                                    }
                                } catch {}
                                origHandler(respStr);
                            } : origHandler;

                            super({ ...options, response_handler: patchedHandler });
                            this._interceptedHandler = patchedHandler;
                        }

                        command_blocking(cmdStr: string) {
                            const respStr = super.command_blocking(cmdStr);
                            try {
                                const detail = JSON.parse(respStr);
                                augmentVersionInfo(detail);
                                return JSON.stringify(detail);
                            } catch {
                                return respStr;
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
                                        ("InstallModule" in detail && isModuleAlreadyInstalled(detail.InstallModule?.name))
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
                    console.log(LOG_PREFIX, "Native updater.node hooked — Host & Module updates disabled with on-disk module persistence.");
                }
            }
        } catch (e) {
            console.error(LOG_PREFIX, "Module._load hook error:", e);
        }

        return exportsObj;
    };
    Object.defineProperty(wrappedLoad, "name", { value: origLoad.name || "_load", configurable: true });
    mod._load = wrappedLoad;

    // Deferred safety pass: ensure any on-disk module search paths are present in Module.globalPaths
    setTimeout(() => {
        try {
            const diskMods = getInstalledDiskModules();
            const modObj = Module as any;
            const globalPaths: string[] = modObj.globalPaths || [];
            for (const info of Object.values(diskMods)) {
                if (!globalPaths.includes(info.searchPath)) {
                    globalPaths.push(info.searchPath);
                    console.log(LOG_PREFIX, `Added fallback global path for module: ${info.searchPath}`);
                }
            }
        } catch {}
    }, 2000);
}

installMainProcessUpdaterAndStealthHooks();
