/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./QuestButton.css";

import { Flex } from "@components/Flex";
import { findByCodeLazy, findComponentByCodeLazy } from "@webpack";
import { RestAPI, Tooltip, useEffect, useState } from "@webpack/common";

import settings from "../settings";
import { QuestsStore, UserStore } from "../stores";

interface UserBadgeProgress {
    current?: number | null;
    unit?: string | null;
}

interface UserBadge {
    badge_id: number;
    owned?: boolean;
    name?: string;
    info_label?: string | null;
    progress?: UserBadgeProgress[] | null;
}

interface AccountBadgeStats {
    questsCompleted: number | null;
    gamesPlayed: number | null;
    hoursPlayed: number | null;
    orbsBalance: number | null;
}

const cachedBadgeStats: AccountBadgeStats = {
    questsCompleted: null,
    gamesPlayed: null,
    hoursPlayed: null,
    orbsBalance: null
};
let lastBadgeFetchAt = 0;
let cachedUserId = "";

export function clearCachedBadgeStats(): void {
    cachedUserId = "";
    lastBadgeFetchAt = 0;
    cachedBadgeStats.questsCompleted = null;
    cachedBadgeStats.gamesPlayed = null;
    cachedBadgeStats.hoursPlayed = null;
    cachedBadgeStats.orbsBalance = null;
}

function parseBadgeMetric(badge: UserBadge | undefined, unit: string | null): number | null {
    if (!badge) return null;
    const progress = Array.isArray(badge.progress)
        ? (unit ? badge.progress.find(p => p?.unit === unit) : badge.progress[0])
        : undefined;
    const current = progress?.current;
    if (typeof current === "number" && Number.isSafeInteger(current) && current >= 0) return current;

    if (Array.isArray(badge.progress) && badge.progress.length > 0) {
        const firstCurrent = badge.progress[0]?.current;
        if (typeof firstCurrent === "number" && Number.isSafeInteger(firstCurrent) && firstCurrent >= 0) {
            return firstCurrent;
        }
    }

    if (badge.badge_id === 14 && typeof badge.info_label === "string") {
        const match = badge.info_label.match(/^\s*(\d+(?:,\d{3})*)\s+Quests?\s+completed\s*$/i);
        if (match) {
            const count = Number(match[1].replace(/,/g, ""));
            if (Number.isSafeInteger(count)) return count;
        }
        const numMatch = badge.info_label.match(/(\d+(?:[,\s]\d{3})*|\d+)/);
        if (numMatch) {
            const count = Number(numMatch[1].replace(/[,\s]/g, ""));
            if (Number.isSafeInteger(count) && count >= 0) return count;
        }
    } else if (typeof badge.info_label === "string") {
        const numMatch = badge.info_label.match(/(\d+(?:[,\s]\d{3})*|\d+)/);
        if (numMatch) {
            const count = Number(numMatch[1].replace(/[,\s]/g, ""));
            if (Number.isSafeInteger(count) && count >= 0) return count;
        }
    }
    return null;
}

async function fetchAccountStats(): Promise<AccountBadgeStats> {
    const currentUserId = String(UserStore?.getCurrentUser?.()?.id || "");
    if (currentUserId && currentUserId !== cachedUserId) {
        cachedUserId = currentUserId;
        lastBadgeFetchAt = 0;
        cachedBadgeStats.questsCompleted = null;
        cachedBadgeStats.gamesPlayed = null;
        cachedBadgeStats.hoursPlayed = null;
        cachedBadgeStats.orbsBalance = null;
    }

    const now = Date.now();
    if (now - lastBadgeFetchAt < 120_000 && (cachedBadgeStats.questsCompleted != null || cachedBadgeStats.orbsBalance != null)) {
        return cachedBadgeStats;
    }
    lastBadgeFetchAt = now;
    try {
        const [badgesRes, balanceRes] = await Promise.allSettled([
            RestAPI.get({ url: "/users/@me/badges" }),
            RestAPI.get({ url: "/users/@me/virtual-currency/balance" })
        ]);

        if (badgesRes.status === "fulfilled") {
            const body: any = (badgesRes.value as any)?.body;
            const rawBadges: UserBadge[] = Array.isArray(body?.badges) ? body.badges : (Array.isArray(body) ? body : []);
            const b14 = rawBadges.find(b => b?.badge_id === 14);
            const b21 = rawBadges.find(b => b?.badge_id === 21);
            const b20 = rawBadges.find(b => b?.badge_id === 20);
            cachedBadgeStats.questsCompleted = parseBadgeMetric(b14, null);
            cachedBadgeStats.gamesPlayed = parseBadgeMetric(b21, "games");
            cachedBadgeStats.hoursPlayed = parseBadgeMetric(b20, "hours");
        }

        if (balanceRes.status === "fulfilled") {
            const body: any = (balanceRes.value as any)?.body;
            const bal = body?.balance ?? body?.virtual_currency_balance;
            if (typeof bal === "number" && Number.isSafeInteger(bal)) {
                cachedBadgeStats.orbsBalance = bal;
            }
        }
    } catch {}
    return cachedBadgeStats;
}

const QuestIcon = findByCodeLazy("\"M7.5 21.7a8.95");
const rawNavigateToQuestHome = findByCodeLazy(".QUEST_HOME,{search:");
const navigateToQuestHome = () => rawNavigateToQuestHome?.({});
const TopBarButton = findComponentByCodeLazy(".HEADER_BAR_BADGE_BOTTOM,", 'position:"bottom"');
const SettingsBarButton = findComponentByCodeLazy(".GREEN,positionKeyStemOverride:");
const CountBadge = findComponentByCodeLazy("renderBadgeCount", "disableColor");

function questsStatus() {
    try {
        const availableQuests = QuestsStore?.quests ? [...QuestsStore.quests.values()] : [];
        return availableQuests.reduce((acc, x) => {
            if (!x?.config?.expiresAt) return acc;
            if (new Date(x.config.expiresAt).getTime() < Date.now()) {
                acc.expired++;
            } else if (x.userStatus?.claimedAt) {
                acc.claimed++;
            } else if (x.userStatus?.completedAt) {
                acc.claimable++;
            } else if (x.userStatus?.enrolledAt) {
                acc.enrolled++;
            } else {
                acc.enrollable++;
            }
            return acc;
        }, { enrollable: 0, enrolled: 0, claimable: 0, claimed: 0, expired: 0 });
    } catch {
        return { enrollable: 0, enrolled: 0, claimable: 0, claimed: 0, expired: 0 };
    }
}

export function QuestsCount() {
    const [status, setStatus] = useState(questsStatus());

    const checkForNewQuests = () => {
        setStatus(questsStatus());
    };

    useEffect(() => {
        try {
            QuestsStore?.addChangeListener?.(checkForNewQuests);
        } catch { }
        return () => {
            try {
                QuestsStore?.removeChangeListener?.(checkForNewQuests);
            } catch { }
        };
    }, []);

    return (
        <Flex flexDirection={"row"} justifyContent={"flex-end"} className={"quest-button-badges"} gap={"5px"}>
            {status.enrollable > 0 && (
                <Tooltip text={"Enrollable"}>
                    {({ onMouseEnter, onMouseLeave }) => (
                        <CountBadge
                            onMouseEnter={onMouseEnter}
                            onMouseLeave={onMouseLeave}
                            count={status.enrollable}
                            color={"var(--status-danger)"}
                            style={{ color: "var(--background-base-lowest)" }}
                        />
                    )}
                </Tooltip>
            )}
            {status.enrolled > 0 && (
                <Tooltip text={"Enrolled"}>
                    {({ onMouseEnter, onMouseLeave }) => (
                        <CountBadge
                            onMouseEnter={onMouseEnter}
                            onMouseLeave={onMouseLeave}
                            count={status.enrolled}
                            color={"var(--status-warning)"}
                            style={{ color: "var(--background-base-lowest)" }}
                        />
                    )}
                </Tooltip>
            )}
            {status.claimable > 0 && (
                <Tooltip text={"Claimable"}>
                    {({ onMouseEnter, onMouseLeave }) => (
                        <CountBadge
                            onMouseEnter={onMouseEnter}
                            onMouseLeave={onMouseLeave}
                            count={status.claimable}
                            color={"var(--status-positive)"}
                            style={{ color: "var(--background-base-lowest)" }}
                        />
                    )}
                </Tooltip>
            )}
            {status.claimed > 0 && (
                <Tooltip text={"Claimed"}>
                    {({ onMouseEnter, onMouseLeave }) => (
                        <CountBadge
                            onMouseEnter={onMouseEnter}
                            onMouseLeave={onMouseLeave}
                            count={status.claimed}
                            color={"var(--blurple-50)"}
                            style={{ color: "var(--background-base-lowest)" }}
                        />
                    )}
                </Tooltip>
            )}
        </Flex>
    );
}

export function QuestButton({ type }: { type: "top-bar" | "settings-bar"; }) {
    const [state, setState] = useState(questsStatus());
    const [badgeStats, setBadgeStats] = useState<AccountBadgeStats>(cachedBadgeStats);

    const checkForNewQuests = () => {
        setState(questsStatus());
        if (settings.store.showAccountBadges) {
            fetchAccountStats().then(stats => setBadgeStats({ ...stats }));
        }
    };

    useEffect(() => {
        try {
            QuestsStore?.addChangeListener?.(checkForNewQuests);
        } catch { }
        if (settings.store.showAccountBadges) {
            fetchAccountStats().then(stats => setBadgeStats({ ...stats }));
        }
        return () => {
            try {
                QuestsStore?.removeChangeListener?.(checkForNewQuests);
            } catch { }
        };
    }, []);

    const className = state.enrollable ? "quest-button-enrollable" : state.enrolled ? "quest-button-enrolled" : state.claimable ? "quest-button-claimable" : "";
    let tooltip = state.enrollable ? `${state.enrollable} Enrollable Quests` : state.enrolled ? `${state.enrolled} Enrolled Quests` : state.claimable ? `${state.claimable} Claimable Quests` : "Quests";

    if (settings.store.showAccountBadges) {
        const badgeParts: string[] = [];
        if (badgeStats.questsCompleted != null) badgeParts.push(`${badgeStats.questsCompleted} completed`);
        if (badgeStats.gamesPlayed != null) badgeParts.push(`${badgeStats.gamesPlayed} games`);
        if (badgeStats.hoursPlayed != null) badgeParts.push(`${badgeStats.hoursPlayed}h`);
        if (badgeStats.orbsBalance != null) badgeParts.push(`${badgeStats.orbsBalance} Orbs`);
        if (badgeParts.length > 0) {
            tooltip += ` • ${badgeParts.join(" | ")}`;
        }
    }
    if (type === "top-bar") {
        return (
            <TopBarButton
                className={className}
                iconClassName={undefined}
                disabled={navigateToQuestHome === undefined}
                showBadge={state.enrollable > 0 || state.enrolled > 0 || state.claimable > 0}
                badgePosition={"bottom"}
                icon={QuestIcon}
                iconSize={20}
                onClick={navigateToQuestHome}
                onContextMenu={undefined}
                tooltip={tooltip}
                tooltipPosition={"bottom"}
                hideOnClick={false}
            />
        );
    } else if (type === "settings-bar") {
        return (
            <SettingsBarButton
                tooltipText={tooltip}
                onContextMenu={undefined}
                onClick={navigateToQuestHome}
                disabled={navigateToQuestHome === undefined}
                icon={QuestIcon}
                className={`quest-button ${className}`}
            >
                {(state.enrollable > 0 || state.enrolled > 0 || state.claimable > 0) && (
                    <span className={`quest-button-badge ${className}`} style={{
                        position: "absolute",
                        bottom: 4,
                        right: 4,
                        width: 8,
                        height: 8,
                        borderRadius: "50%",
                        backgroundColor: state.claimable > 0 ? "var(--status-positive)" : state.enrolled > 0 ? "var(--brand-experiment)" : "var(--status-warning)",
                        pointerEvents: "none"
                    }} />
                )}
            </SettingsBarButton>
        );
    }
}
