/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export interface WebhookNotificationOptions {
    url: string;
    bearerToken?: string;
    format: "auto" | "discord" | "dqh_v1";
    eventType: string;
    locale: string;
    isTest: boolean;
    questId?: string;
    questName?: string;
    taskType?: string;
    estimatedCompleteAt?: string | null;
    rewardImage?: string | null;
    queue?: any;
    templateTitle?: string;
    templateContent?: string;
}

export const WEBHOOK_TEMPLATE_TOKEN_RE = /\{\{([A-Za-z][A-Za-z0-9_-]*)\}\}|\{([A-Za-z][A-Za-z0-9_-]*)\}/g;

export function renderWebhookTemplate(template: string, vars: Record<string, string>): string {
    if (!template || typeof template !== "string") return "";
    return template.replace(WEBHOOK_TEMPLATE_TOKEN_RE, (fullMatch, escaped?: string, tokenKey?: string) => {
        if (escaped) return `{${escaped}}`;
        if (tokenKey && Object.prototype.hasOwnProperty.call(vars, tokenKey)) {
            return vars[tokenKey] ?? "";
        }
        return fullMatch;
    });
}

export async function sendRendererWebhookNotification(opts: WebhookNotificationOptions): Promise<{ ok: boolean; status?: number; message?: string }> {
    try {
        const urlStr = opts.url;
        if (!urlStr || typeof urlStr !== "string") return { ok: false, message: "Missing URL" };
        const isQueue = opts.eventType === "queue_completed";
        const eventId = `${crypto.randomUUID()}:${isQueue ? "completed" : opts.eventType === "quest_started" ? "started" : opts.eventType === "reward_claimed" ? "claimed" : "completed"}`;
        const isoTimestamp = new Date().toISOString();
        const questName = isQueue ? "" : String(opts.questName || opts.questId || "Quest");
        const queueStats = opts.queue || null;

        const templateVars: Record<string, string> = {
            "quest-name": questName,
            "event-type": opts.eventType,
            "event-id": eventId,
            "timestamp": isoTimestamp,
            "estimated-complete-at": opts.estimatedCompleteAt ?? "",
            "reward-image": opts.rewardImage ?? "",
            "succeeded": queueStats ? String(queueStats.succeeded) : "",
            "failed": queueStats ? String(queueStats.failed) : "",
            "skipped": queueStats ? String(queueStats.skipped) : ""
        };

        const defaultTitle = isQueue ? "Queue processing completed" : "Discord Quest: {quest-name}";
        const defaultContent = isQueue ? "Succeeded: {succeeded}; failed: {failed}; skipped: {skipped}" : "[{event-type}] {quest-name} ({timestamp})";
        const rawTitle = opts.templateTitle || defaultTitle;
        const rawContent = opts.templateContent || defaultContent;
        const renderedTitle = renderWebhookTemplate(rawTitle, templateVars);
        const renderedContent = renderWebhookTemplate(rawContent, templateVars);

        let discordTarget = false;
        try {
            const u = new URL(urlStr);
            discordTarget = /^(?:(?:ptb|canary)\.)?discord(?:app)?\.com$/i.test(u.hostname) && /^\/api\/(?:v\d+\/)?webhooks\/[^/]+\/[^/]+/i.test(u.pathname);
        } catch {}
        const useDiscord = opts.format === "discord" || (opts.format === "auto" && discordTarget);

        let targetUrl = urlStr;
        if (discordTarget && !targetUrl.includes("wait=")) {
            targetUrl += (targetUrl.includes("?") ? "&" : "?") + "wait=true";
        }

        let payload: any;
        if (useDiscord) {
            const embedColor = opts.eventType === "quest_completed" || isQueue ? 0x57f287 : opts.eventType === "reward_claimed" ? 0xfee75c : 0x5865f2;
            const fields: any[] = [];
            if (!isQueue) fields.push({ name: "Quest", value: questName.slice(0, 1024), inline: true });
            fields.push({ name: "Event", value: opts.eventType, inline: true });
            if (!isQueue && opts.taskType) fields.push({ name: "Task", value: String(opts.taskType).slice(0, 1024), inline: true });
            if (opts.estimatedCompleteAt) fields.push({ name: "Estimated Completion", value: String(opts.estimatedCompleteAt).slice(0, 1024), inline: false });
            if (queueStats) {
                fields.push(
                    { name: "Succeeded", value: String(queueStats.succeeded), inline: true },
                    { name: "Failed", value: String(queueStats.failed), inline: true },
                    { name: "Skipped", value: String(queueStats.skipped), inline: true }
                );
            }
            const embed: any = {
                title: renderedTitle.slice(0, 256),
                description: renderedContent.slice(0, 4096),
                color: embedColor,
                timestamp: isoTimestamp,
                fields,
                footer: { text: `ID: ${eventId}` }
            };
            if (opts.rewardImage && /^https:\/\//i.test(opts.rewardImage)) {
                embed.thumbnail = { url: opts.rewardImage };
            }
            payload = {
                content: renderedContent.slice(0, 2000),
                embeds: [embed],
                allowed_mentions: { parse: [] }
            };
        } else {
            payload = {
                schema_version: 1,
                event_id: eventId,
                event_type: opts.eventType,
                timestamp: isoTimestamp,
                locale: opts.locale,
                is_test: opts.isTest,
                title: renderedTitle,
                content: renderedContent,
                quest: isQueue ? null : { name: questName, reward_image: opts.rewardImage || null, estimated_complete_at: opts.estimatedCompleteAt },
                queue: queueStats
            };
        }

        const headers: Record<string, string> = { "Content-Type": "application/json", "Accept": "application/json, text/plain, */*" };
        if (opts.bearerToken) {
            headers["Authorization"] = `Bearer ${String(opts.bearerToken).replace(/^Bearer\s+/i, "")}`;
        }
        const resp = await fetch(targetUrl, {
            method: "POST",
            headers,
            body: JSON.stringify(payload),
            redirect: "manual",
            signal: AbortSignal.timeout(10000)
        });
        const isRedirect = resp.type === "opaqueredirect" || (resp.status >= 300 && resp.status < 400);
        const isAccepted = !isRedirect && resp.ok && resp.status >= 200 && resp.status < 300;
        const statusSummary = isAccepted
            ? (resp.status === 202 ? "Submitted" : "Delivered")
            : (isRedirect
                ? `Rejected HTTP redirect (${resp.status || 300})`
                : `HTTP ${resp.status}`);
        return { ok: isAccepted, status: resp.status, message: statusSummary };
    } catch (e: any) {
        return { ok: false, message: e?.message || "Delivery failed" };
    }
}
