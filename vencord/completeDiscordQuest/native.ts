/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ConnectSrc, CspPolicies } from "@main/csp";
import { randomBytes } from "crypto";
import { IpcMainInvokeEvent } from "electron";

CspPolicies["*.discordsays.com"] = ConnectSrc;
CspPolicies["https://*.discordsays.com"] = ConnectSrc;
CspPolicies["wss://*.discordsays.com"] = ConnectSrc;

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
        // 1. Exchange Discord OAuth2 code at /.proxy/acf/authorize
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

        // 2. Register with Arise backend (/.proxy/acf/arise/register) to obtain Arise session JWT
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

        // 3. Unlock all 10 Ace titles, all 3 pack badges, submit max scores to ace-1..10, and complete mission
        await unlockAllAriseRewardsAndScores(baseOrigin, ariseToken, buildHeaders);
        await syncActivityMaxRecords(event, appIdStr).catch(() => null);

        // 4. Submit quest completion progress to /.proxy/acf/quest/progress
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

