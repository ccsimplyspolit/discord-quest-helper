/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ConnectSrc, CspPolicies, ImageScriptsAndCssSrc } from "@main/csp";
import { randomBytes, randomUUID } from "crypto";
import { app, IpcMainInvokeEvent, session } from "electron";

const ActivityFrameAndConnectSrc = [...ImageScriptsAndCssSrc, "frame-src", "child-src", "media-src"];
CspPolicies["*.discordsays.com"] = ActivityFrameAndConnectSrc;
CspPolicies["https://*.discordsays.com"] = ActivityFrameAndConnectSrc;
CspPolicies["wss://*.discordsays.com"] = ConnectSrc;
CspPolicies["*.ariseworlds.com"] = ActivityFrameAndConnectSrc;
CspPolicies["https://*.ariseworlds.com"] = ActivityFrameAndConnectSrc;
CspPolicies["wss://*.ariseworlds.com"] = ConnectSrc;

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

function sanitizeActivityResponseHeaders(responseHeaders: Record<string, string[]>, callerOrigin?: string): void {
    const allowOrigin = callerOrigin || "https://discord.com";
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

    const requestOriginById = new Map<number, string>();

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
                            const rawOrigin = originKey ? String(requestHeaders[originKey] || "") : "";
                            if (rawOrigin) {
                                if (requestOriginById.size > 2000) requestOriginById.clear();
                                requestOriginById.set(id, rawOrigin);
                            }

                            const discordsaysMatch = typeof url === "string" ? url.match(DISCORDSAYS_DOMAIN_RE) : null;
                            if (discordsaysMatch?.[1]) {
                                const targetHost = discordsaysMatch[1];
                                const isFromDiscord =
                                    (rawOrigin && DISCORD_ORIGIN_RE.test(rawOrigin)) ||
                                    (typeof referrer === "string" && DISCORD_ORIGIN_RE.test(referrer));
                                if (isFromDiscord) {
                                    if (originKey) delete requestHeaders[originKey];
                                    requestHeaders.Origin = `https://${targetHost}`;
                                    const refererKey = findHeaderKey(requestHeaders, "referer");
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
                        const headers = resp?.responseHeaders || details.responseHeaders;
                        if (headers && typeof details.url === "string" && ACTIVITY_DOMAIN_RE.test(details.url)) {
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

installActivityCorsAndPreflightBypass();

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

/**
 * Exact board mapping from PlayCanvas `2578194.json` (`ariseLeaderboard.boardMap: "ace:06=ace-7,ace:07=ace-8,ace:08=ace-6"`)
 * and live verified Top-2 scores on `1536318183873454090.discordsays.com`.
 */
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

/**
 * Exact Mathematical Inverse Solver for PlayCanvas `ShotScore` (`game-scripts.js` + `2578194.json`):
 * - `ttkSlow = 1.8`, `ttkFast = 0.7` (`span = 1.1`), `ttkGain = 1.6`, `ttkShape = 1.4`, `accGain = 1.0`
 * - `i = clamp((1.8 - meanTtk) / 1.1, 0, 1)`
 * - `ttkMult = 1 + 1.6 * i^1.4`
 * - `accMult = 2.0` (5/5 headshots, 0 whiffs)
 * - `total = Math.round(matchScore * ttkMult * 2.0)`
 */
function solveShotScoreRun(targetScore: number, meta: ValorantAcesBoardMeta): SolvedShotScoreRun {
    const rawNum = Number(targetScore);
    const validTarget = Number.isFinite(rawNum) && rawNum > 0 ? Math.round(rawNum) : (meta.fallbackTop2 + 1);
    const T = Math.max(2000, Math.min(meta.ceiling, validTarget));
    const maxMatchScore = Math.round(meta.ceiling / 5.2);

    let chosenS = maxMatchScore;
    let chosenTotalTtkMs = 3500;
    let chosenTtkMult = 2.6;
    let solved = false;

    const tryCandidateS = (s: number, minTtk: number, maxTtk: number): boolean => {
        const reqMult = T / (2.0 * s);
        if (reqMult < 1.0 || reqMult > 2.6) return false;
        const ratio = Math.max(0, Math.min(1, (reqMult - 1.0) / 1.6));
        const i = Math.pow(ratio, 1.0 / 1.4);
        const rawMeanTtk = 1.8 - 1.1 * i;
        if (rawMeanTtk < minTtk || rawMeanTtk > maxTtk) return false;

        const baseTotalMs = Math.round(rawMeanTtk * 5000);
        for (let delta = -6; delta <= 6; delta++) {
            const candTotalMs = baseTotalMs + delta;
            if (candTotalMs < 3500 || candTotalMs > 9000) continue;
            const candMeanTtk = candTotalMs / 5000;
            const actualI = Math.max(0, Math.min(1, (1.8 - candMeanTtk) / 1.1));
            const actualMult = 1.0 + 1.6 * Math.pow(actualI, 1.4);
            if (Math.round(s * actualMult * 2.0) === T) {
                chosenS = s;
                chosenTotalTtkMs = candTotalMs;
                chosenTtkMult = Number(actualMult.toFixed(4));
                return true;
            }
        }
        return false;
    };

    // Pass 1: Prefer realistic human pro TTK window (0.76s .. 1.18s)
    for (let s = maxMatchScore - 5; s >= 800; s--) {
        if (tryCandidateS(s, 0.76, 1.18)) {
            solved = true;
            break;
        }
    }

    // Pass 2: Full valid dynamic curve window (0.70s .. 1.80s)
    if (!solved) {
        for (let s = maxMatchScore; s >= 500; s--) {
            if (tryCandidateS(s, 0.70, 1.80)) {
                solved = true;
                break;
            }
        }
    }

    // Construct 5 individual shot TTKs in ms whose sum is `chosenTotalTtkMs`
    const totalTtkMs = chosenTotalTtkMs;
    const baseMs = Math.floor(totalTtkMs / 5);
    const offsets = [-68, -29, 4, 37, 56];
    const shotTtksMs = offsets.map(off => Math.max(380, baseMs + off));
    const currentSum = shotTtksMs.reduce((a, b) => a + b, 0);
    shotTtksMs[4] += totalTtkMs - currentSum;
    shotTtksMs.sort((a, b) => a - b);

    const bestTtkMs = shotTtksMs[0];
    const bestTtk = Number((bestTtkMs / 1000).toFixed(3));
    const meanTtk = Number((totalTtkMs / 5000).toFixed(4));

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
    sessionDurationMs: number;
}

const ariseTelemetrySessionByUser = new Map<string, AriseSessionTelemetryState>();

function getOrCreateAriseSessionState(userKey: string): AriseSessionTelemetryState {
    const key = userKey || "default";
    let state = ariseTelemetrySessionByUser.get(key);
    if (!state) {
        state = {
            sessionId: randomUUID(),
            deviceId: randomUUID(),
            sessionDurationMs: 48000 + Math.floor(Math.random() * 24000)
        };
        ariseTelemetrySessionByUser.set(key, state);
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
        sessionDuration: state.sessionDurationMs,
        eventType,
        metadata: { strings, numbers },
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
        [run.total, 1, run.total, 100, run.meanTtk, run.bestTtk, 0]
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
                // "top1_plus_1" (or UI fallback for "quest_only"): strictly Top-2 + 1, capped below ceiling - 50
                targetScore = Math.max(1000, Math.min(meta.ceiling - 50, otherTopScore + 1));
            }

            let shouldSubmit = false;
            if (scoreMode === "quest_only") {
                shouldSubmit = false;
            } else if (scoreMode === "top1_plus_1") {
                // If already #1 above otherTopScore, do not spam redundant submissions; otherwise beat otherTopScore by +1
                if (myCurrentPosition === 1 && myCurrentScore !== null && myCurrentScore > otherTopScore) {
                    shouldSubmit = false;
                } else if (myCurrentScore === null || myCurrentScore <= otherTopScore) {
                    shouldSubmit = true;
                }
            } else {
                // "custom" or "legit_pro": Arise server only accepts improvements (score > existing)
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
    customScore = 24500
): Promise<BoardTargetResolution[]> {
    let resolutions: BoardTargetResolution[] = [];
    try {
        const requests: Promise<any>[] = [
            fetch(`${baseOrigin}/.proxy/api/profile/mission-completed`, {
                method: "POST",
                headers: buildHeaders(ariseToken, { "X-Request-Id": buildAriseRequestId(undefined) }),
                body: undefined,
                signal: AbortSignal.timeout(8000)
            }).catch(() => null)
        ];

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

            resolutions = await resolveTargetScoresForBoards(baseOrigin, ariseToken, buildHeaders, scoreMode, customScore);
            if (scoreMode !== "quest_only") {
                const userKey = extractSubFromJwt(ariseToken) || "default";
                const sessionState = getOrCreateAriseSessionState(userKey);

                for (const item of resolutions) {
                    if (!item.shouldSubmit) continue;
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

        await Promise.allSettled(requests);
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
        return { uid, tok };
    } catch {}
    return { uid: "", tok: "" };
})();
`;

    let hostUserId = "";
    let discoveredToken = "";
    for (const frame of targetFrames) {
        try {
            const probed: any = await frame.executeJavaScript(probeScript, true);
            if (probed?.uid && !hostUserId) hostUserId = String(probed.uid).trim();
            if (probed?.tok && !discoveredToken) discoveredToken = String(probed.tok).trim();
            if (hostUserId && discoveredToken) break;
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
            customScore
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

        // 3. Unlock all 10 Ace titles, all 3 pack badges, submit humanized scores to ace-1..10, and complete mission
        const isValorantAces = appIdStr === VALORANT_ACES_APP_ID;
        await unlockAllAriseRewardsAndScores(baseOrigin, ariseToken, buildHeaders, isValorantAces, scoreMode, customScore);
        if (isValorantAces) {
            await syncActivityMaxRecords(event, appIdStr, scoreMode, customScore).catch(() => null);
        }

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

