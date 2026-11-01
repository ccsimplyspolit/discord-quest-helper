/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { Button } from "@components/Button";
import { OptionType } from "@utils/types";
import { React, showToast } from "@webpack/common";

import { sendRendererWebhookNotification } from "./webhook";

let keepAliveSettingChangedHandler: ((enabled: boolean) => void) | null = null;
let skipKeepAliveHandler: (() => number) | null = null;

export function registerKeepAliveSettingChangedHandler(handler: ((enabled: boolean) => void) | null): void {
    keepAliveSettingChangedHandler = handler;
}

export function registerSkipKeepAliveHandler(handler: (() => number) | null): void {
    skipKeepAliveHandler = handler;
}

const settings = definePluginSettings({
    hasAcceptedToUsePlugin: {
        type: OptionType.BOOLEAN,
        description: "Enables automatic quest completion after accepting the usage notice. Turn off in plugin settings at any time to stop active tasks.",
        default: false
    },
    acceptQuestsAutomatically: {
        type: OptionType.BOOLEAN,
        description: "Automatically accepts new eligible quests when they appear. Toggle on or off in plugin settings.",
        default: true
    },
    humanizeEnrollDelay: {
        type: OptionType.BOOLEAN,
        description: "Spaces out automatic quest acceptances one by one with natural pauses. Toggle on or off in plugin settings.",
        default: true
    },
    claimRewardsAutomatically: {
        type: OptionType.BOOLEAN,
        description: "Automatically claims rewards for completed quests using your preferred platform order below. Toggle on or off in plugin settings.",
        default: true
    },
    rewardPlatformPriority: {
        type: OptionType.SELECT,
        description: "Chooses which gaming platform to select first when claiming multi-platform reward codes. Pick an order from the dropdown.",
        options: [
            { label: "PC -> PlayStation (PS5) -> Xbox -> Switch (Default)", value: "4,2,1,3,0", default: true },
            { label: "PC -> Xbox -> PlayStation (PS5) -> Switch", value: "4,1,2,3,0" },
            { label: "PlayStation (PS5) -> PC -> Xbox -> Switch", value: "2,4,1,3,0" },
            { label: "Xbox -> PC -> PlayStation (PS5) -> Switch", value: "1,4,2,3,0" },
            { label: "Switch -> PC -> PlayStation (PS5) -> Xbox", value: "3,4,2,1,0" },
            { label: "Skip multi-platform rewards (choose manually)", value: "manual" }
        ]
    },
    showQuestsButtonTopBar: {
        type: OptionType.BOOLEAN,
        description: "Displays a quick-access Quests shortcut button in the top bar. Toggle in plugin settings and restart Discord to apply.",
        default: true,
        restartNeeded: true
    },
    showQuestsButtonSettingsBar: {
        type: OptionType.BOOLEAN,
        description: "Displays a quick-access Quests shortcut button next to your account controls. Toggle in plugin settings and restart Discord to apply.",
        default: false,
        restartNeeded: true
    },
    showQuestsButtonBadges: {
        type: OptionType.BOOLEAN,
        description: "Shows live quest status counters on the Quests shortcut button. Toggle on or off in plugin settings.",
        default: true
    },
    showAccountBadges: {
        type: OptionType.BOOLEAN,
        description: "Shows your completed quest count, gaming hours, and Orbs balance in the Quests shortcut tooltip. Toggle on or off in plugin settings.",
        default: true
    },
    farmVideos: {
        type: OptionType.BOOLEAN,
        description: "Automatically completes video quests in the background. Toggle on or off in plugin settings.",
        default: true
    },
    farmPlayOnDesktop: {
        type: OptionType.BOOLEAN,
        description: "Automatically completes desktop game quests in the background. Toggle on or off in plugin settings.",
        default: true
    },
    farmStreamOnDesktop: {
        type: OptionType.BOOLEAN,
        description: "Automatically completes stream quests in the background. Toggle on or off in plugin settings.",
        default: true
    },
    farmPlayActivity: {
        type: OptionType.BOOLEAN,
        description: "Automatically completes voice and activity time quests in the background. Toggle on or off in plugin settings.",
        default: true
    },
    farmAchievementInActivity: {
        type: OptionType.BOOLEAN,
        description: "Automatically completes interactive activity and achievement quests in the background. Toggle on or off in plugin settings.",
        default: true
    },
    activityScoreMode: {
        type: OptionType.SELECT,
        description: "Chooses how your score and personal record are submitted during interactive Activity quests. Select a mode from the dropdown.",
        options: [
            { label: "World #1 (Top-2 + 1, humanized, never max ceiling)", value: "top1_plus_1", default: true },
            { label: "Custom Score (Use exact custom score below)", value: "custom" },
            { label: "Humanized Pro (21,800–22,450 legit 5-headshot range)", value: "legit_pro" },
            { label: "Quest Only (Do not submit leaderboard scores)", value: "quest_only" }
        ]
    },
    activityCustomScore: {
        type: OptionType.NUMBER,
        description: "Sets your target score for interactive Activity leaderboards and personal record cards. Enter a value here after selecting Custom Score above.",
        default: 24500
    },
    postQuestKeepAliveEnabled: {
        type: OptionType.BOOLEAN,
        description: "Keeps the active game session open for extra minutes after completing a desktop game quest before closing or moving to the next quest. Toggle on or off in plugin settings.",
        default: true,
        onChange: (enabled: boolean) => {
            keepAliveSettingChangedHandler?.(enabled);
        }
    },
    postQuestKeepAliveMode: {
        type: OptionType.SELECT,
        description: "Selects whether post-quest session time uses a randomized range or a fixed number of minutes. Pick a mode from the dropdown.",
        options: [
            { label: "Random range between Min and Max minutes (Default)", value: "random", default: true },
            { label: "Fixed duration using Min minutes", value: "fixed" }
        ]
    },
    postQuestKeepAliveMinutes: {
        type: OptionType.NUMBER,
        description: "Sets the minimum (or fixed) minutes to keep a completed desktop game session open. Enter the desired number of minutes.",
        default: 4
    },
    postQuestKeepAliveMaxMinutes: {
        type: OptionType.NUMBER,
        description: "Sets the maximum minutes to keep a completed desktop game session open when Random mode is selected. Enter the desired number of minutes.",
        default: 10
    },
    skipActiveKeepAliveAction: {
        type: OptionType.COMPONENT,
        component: () => React.createElement(
            Button,
            {
                size: "small",
                variant: "secondary",
                onClick: () => {
                    const count = typeof skipKeepAliveHandler === "function" ? skipKeepAliveHandler() : 0;
                    try {
                        showToast({
                            text: count > 0 ? `Skipped ${count} active post-quest cooldown(s).` : "No active cooldowns to skip.",
                            variant: count > 0 ? "success" : "default"
                        });
                    } catch {}
                }
            },
            "Skip Active Cooldown"
        )
    },
    simulateCrashReopen: {
        type: OptionType.BOOLEAN,
        description: "Briefly pauses and reopens long desktop game sessions partway through completion. Enable and adjust the minute and second ranges below.",
        default: false
    },
    crashAfterMinutesMin: {
        type: OptionType.NUMBER,
        description: "Sets the minimum minutes of play before pausing the active game session. Enter a number of minutes.",
        default: 5
    },
    crashAfterMinutesMax: {
        type: OptionType.NUMBER,
        description: "Sets the maximum minutes of play before pausing the active game session. Enter a number of minutes.",
        default: 12
    },
    reopenDelaySecondsMin: {
        type: OptionType.NUMBER,
        description: "Sets the minimum seconds to wait before reopening a paused game session. Enter a number of seconds.",
        default: 25
    },
    reopenDelaySecondsMax: {
        type: OptionType.NUMBER,
        description: "Sets the maximum seconds to wait before reopening a paused game session. Enter a number of seconds.",
        default: 55
    },
    farmRewardCodes: {
        type: OptionType.BOOLEAN,
        description: "Includes quests that grant redeemable reward codes. Toggle on or off in plugin settings.",
        default: true
    },
    farmInGame: {
        type: OptionType.BOOLEAN,
        description: "Includes quests that grant direct in-game items. Toggle on or off in plugin settings.",
        default: true
    },
    farmCollectibles: {
        type: OptionType.BOOLEAN,
        description: "Includes quests that grant profile decorations and collectibles. Toggle on or off in plugin settings.",
        default: true
    },
    farmVirtualCurrency: {
        type: OptionType.BOOLEAN,
        description: "Includes quests that grant Discord Orbs and virtual currency. Toggle on or off in plugin settings.",
        default: true
    },
    farmFractionalPremium: {
        type: OptionType.BOOLEAN,
        description: "Includes quests that grant Nitro trial time. Toggle on or off in plugin settings.",
        default: true
    },
    showToastNotifications: {
        type: OptionType.BOOLEAN,
        description: "Shows in-app notifications when a quest starts, finishes, or claims a reward. Toggle on or off in plugin settings.",
        default: true
    },
    webhookEnabled: {
        type: OptionType.BOOLEAN,
        description: "Sends automatic notifications to your configured notification link when quests start, finish, or claim rewards. Toggle on or off in plugin settings.",
        default: false
    },
    webhookUrl: {
        type: OptionType.STRING,
        description: "Destination link for external quest notifications. Paste a Discord webhook link or custom notification address.",
        default: ""
    },
    webhookBearerToken: {
        type: OptionType.STRING,
        description: "Optional access token for custom notification addresses. Leave blank if your destination link does not require one.",
        default: ""
    },
    webhookFormat: {
        type: OptionType.SELECT,
        description: "Chooses the message style sent to your notification link. Select an option from the dropdown.",
        options: [
            { label: "Automatic (Discord Card for Discord links, Standard Message otherwise)", value: "auto", default: true },
            { label: "Discord Notification Card", value: "discord" },
            { label: "Standard Notification Message", value: "dqh_v1" }
        ]
    },
    webhookNotifyOnStart: {
        type: OptionType.BOOLEAN,
        description: "Sends an external notification when a quest begins. Toggle on or off in plugin settings.",
        default: true
    },
    webhookNotifyOnComplete: {
        type: OptionType.BOOLEAN,
        description: "Sends an external notification when a quest finishes. Toggle on or off in plugin settings.",
        default: true
    },
    webhookNotifyOnClaim: {
        type: OptionType.BOOLEAN,
        description: "Sends an external notification when a quest reward is claimed. Toggle on or off in plugin settings.",
        default: true
    },
    webhookNotifyOnQueue: {
        type: OptionType.BOOLEAN,
        description: "Sends an external notification when a quest queue finishes processing. Toggle on or off in plugin settings.",
        default: true
    },
    webhookTemplateTitle: {
        type: OptionType.STRING,
        description: "Customizes the notification title. Available tags: {quest-name}, {event-type}, {event-id}, {timestamp}, {estimated-complete-at}, {reward-image}, {succeeded}, {failed}, {skipped}.",
        default: "Discord Quest: {quest-name}"
    },
    webhookTemplateContent: {
        type: OptionType.STRING,
        description: "Customizes the notification text. Available tags: {quest-name}, {event-type}, {event-id}, {timestamp}, {estimated-complete-at}, {reward-image}, {succeeded}, {failed}, {skipped}.",
        default: "[{event-type}] {quest-name} ({timestamp})"
    },
    webhookTestAction: {
        type: OptionType.COMPONENT,
        component: () => React.createElement(
            Button,
            {
                size: "small",
                variant: "secondary",
                onClick: async () => {
                    const url = String(settings.store.webhookUrl || "").trim();
                    if (settings.store.showToastNotifications) {
                        try {
                            showToast({ text: "Test notification: Sample Quest", variant: "success" });
                        } catch {}
                    }
                    if (!url) {
                        if (!settings.store.showToastNotifications) {
                            try {
                                showToast({ text: "Enter a notification link above to test external delivery.", variant: "critical" });
                            } catch {}
                        }
                        return;
                    }
                    const nativeHelper = (VencordNative as any)?.pluginHelpers?.CompleteDiscordQuest;
                    const webhookParams = {
                        url,
                        bearerToken: String(settings.store.webhookBearerToken || ""),
                        format: (settings.store.webhookFormat as any) || "auto",
                        eventType: "quest_completed",
                        locale: (typeof navigator !== "undefined" && navigator.language) || "en",
                        isTest: true,
                        questName: "Sample Quest",
                        templateTitle: settings.store.webhookTemplateTitle,
                        templateContent: settings.store.webhookTemplateContent
                    };
                    let res: { ok: boolean; message?: string } | null = null;
                    if (typeof nativeHelper?.sendCustomWebhookNotification === "function") {
                        res = await nativeHelper.sendCustomWebhookNotification(webhookParams).catch((err: any) => ({
                            ok: false,
                            message: err?.message || "Delivery failed"
                        }));
                    } else {
                        res = await sendRendererWebhookNotification(webhookParams).catch((err: any) => ({
                            ok: false,
                            message: err?.message || "Delivery failed"
                        }));
                    }
                    try {
                        showToast({
                            text: res?.ok
                                ? `External test notification delivered (${res.message || "Sent"}).`
                                : `External test notification failed (${res?.message || "Rejected"}).`,
                            variant: res?.ok ? "success" : "critical"
                        });
                    } catch {}
                }
            },
            "Send Test Notification"
        )
    }
});

export default settings;
