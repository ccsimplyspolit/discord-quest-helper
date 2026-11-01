> [!CAUTION]
> As of April 7th 2026, Discord has expressed their intent to crack down on automating quest completion (`Quest Activity Notice`). Use quest automation responsibly and at your own risk.

# CompleteDiscordQuest

Automatically enrolls in, completes, and claims Discord Quests in the background while you use Discord normally.

## Features & How to Use

1. **Automatic Quest Enrollment**
   - **What it does:** Automatically accepts eligible quests as soon as they appear, spacing enrollments out naturally one at a time.
   - **How to use:** Open **User Settings -> Plugins -> CompleteDiscordQuest** and toggle **Accept Quests Automatically** and **Humanize Enroll Delay**.

2. **Background Quest Completion**
   - **What it does:** Completes Video quests, Desktop Game quests, Stream quests, and Activity / Achievement quests in the background without interrupting your active games.
   - **How to use:** Enable the quest categories you want to complete (**Farm Videos**, **Farm Play On Desktop**, **Farm Stream On Desktop**, **Farm Play Activity**, **Farm Achievement In Activity**) and choose which reward types to target (**Reward Codes**, **In-Game**, **Collectibles**, **Virtual Currency**, **Fractional Premium**).

3. **Natural Post-Quest Session Cooldown & Optional Session Pause/Reopen**
   - **What it does:** Keeps an active game session open for a few extra minutes after quest completion before closing or moving to the next desktop quest, and can optionally pause and reopen long sessions partway through.
   - **How to use:** Toggle **Post-Quest Keep-Alive** (choose **Random** or **Fixed** duration and set the minute range), or enable **Simulate Crash/Reopen** and configure the pause/reopen intervals in the plugin settings.

4. **Automatic Reward Claiming & Platform Priority**
   - **What it does:** Claims completed quest rewards automatically and selects your preferred gaming platform when a reward code supports multiple platforms.
   - **How to use:** Enable **Claim Rewards Automatically** and choose your preferred order under **Reward Platform Priority** (for example `PC -> PlayStation (PS5) -> Xbox -> Switch`, or `Skip multi-platform rewards` to pick manually).

5. **Activity Leaderboard & Personal Best Modes**
   - **What it does:** Configures how scores and personal records are submitted during interactive Activity quests.
   - **How to use:** Select your preferred option under **Activity Score Mode** (**World #1**, **Custom Score**, **Humanized Pro**, or **Quest Only**) and adjust **Activity Custom Score** if using Custom mode.

6. **Quick-Access Quests Button & Live Status Badges**
   - **What it does:** Displays a one-click shortcut to the Quests page with live counters for enrollable, active, claimable, and claimed quests, plus your account's completed quests, gaming hours, and Orbs balance in the hover tooltip.
   - **How to use:** Toggle **Show Quests Button Top Bar**, **Show Quests Button Settings Bar**, **Show Quests Button Badges**, and **Show Account Badges** in the plugin settings.

7. **Manual Session Cooldown Skip**
   - **What it does:** Immediately skips any active post-quest cooldown and advances to the next queued quest without waiting for the remaining cooldown time.
   - **How to use:** Open **User Settings -> Plugins -> CompleteDiscordQuest** and click **Skip Active Cooldown**.

8. **In-App & External Notifications**
   - **What it does:** Alerts you inside Discord or sends custom messages to a Discord notification link or custom web address whenever a quest starts, completes, claims a reward, or when the entire quest queue finishes processing.
   - **How to use:** Toggle **Show Toast Notifications**, **Webhook Notify On Start**, **Webhook Notify On Complete**, **Webhook Notify On Claim**, and **Webhook Notify On Queue**. Enter your **Webhook URL** (and optional **Webhook Bearer Token**), choose **Webhook Format**, customize **Webhook Template Title** and **Webhook Template Content** using `{quest-name}`, `{event-type}`, `{event-id}`, `{timestamp}`, `{estimated-complete-at}`, `{reward-image}`, `{succeeded}`, `{failed}`, and `{skipped}`, and click **Send Test Notification** to verify delivery.
