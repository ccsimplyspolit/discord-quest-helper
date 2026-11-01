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

function isModuleAlreadyInstalled(name?: string): boolean {
    if (!name || typeof name !== "string") return false;
    try {
        const path = require("path");
        const fs = require("fs");
        let currentAppDir: string | null = null;
        if (typeof process.execPath === "string") {
            const dir = path.dirname(process.execPath);
            if (path.basename(dir).startsWith("app-")) {
                currentAppDir = dir;
            }
        }
        if (!currentAppDir) {
            const localAppData = process.env.LOCALAPPDATA;
            if (!localAppData) return false;
            const discordRoot = path.join(localAppData, "Discord");
            if (!fs.existsSync(discordRoot)) return false;
            const appDirs = fs.readdirSync(discordRoot)
                .filter((d: string) => d.startsWith("app-"))
                .sort((a: string, b: string) => b.localeCompare(a, undefined, { numeric: true }));
            if (appDirs.length > 0) {
                currentAppDir = path.join(discordRoot, appDirs[0]);
            }
        }
        if (!currentAppDir) return false;

        const modDir = path.join(currentAppDir, "modules");
        if (!fs.existsSync(modDir)) return false;

        const subdirs = fs.readdirSync(modDir);
        for (const sub of subdirs) {
            if (sub.startsWith(`${name}-`) || sub === name) {
                const targetModDir = path.join(modDir, sub);
                const candidateDirs = [targetModDir, path.join(targetModDir, name)];
                for (const candidate of candidateDirs) {
                    if (
                        fs.existsSync(path.join(candidate, "index.js")) ||
                        fs.existsSync(path.join(candidate, `${name}.node`)) ||
                        fs.existsSync(path.join(candidate, "package.json"))
                    ) {
                        return true;
                    }
                }
            }
        }
    } catch {}
    return false;
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
