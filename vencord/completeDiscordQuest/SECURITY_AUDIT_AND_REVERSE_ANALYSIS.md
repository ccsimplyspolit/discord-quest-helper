# Full Reverse-Engineering Audit of Discord Quest Anti-Fraud Protection (`discord_utils.node`, `libdiscore-wasm`, `discord_web_bundle.js`)

## 1. Executive Summary: Why Existing Quest Tools Trigger `Quest Activity Notice`

Through static and dynamic reverse engineering of the Windows Discord Desktop client (`app-1.0.9265`), specifically:
- **`discord_utils.node`** (Native C++ process scanner & Authenticode verifier, analyzed in IDA Pro)
- **`libdiscore-wasm`** (Rust/WASM telemetry & client-modification detector)
- **`discord_web_bundle.js`** (Webpack modules `396813`, `378187`, `973522`, `952818`, `499785`, `174459`, `70298`)

we identified the exact client-side and server-side detection vectors that cause Discord to issue **`Quest Activity Notice`** warnings and suspend Quest access when users run:
1. **`aamiaa/CompleteDiscordQuest.md`** (DevTools Console script)
2. **`nicola02nb/completeDiscordQuest`** (Vencord / BetterDiscord plugin)
3. **`Masterain98/discord-quest-helper`** (Tauri + Rust + CDP + dummy PE runner)

---

## 2. Native Process Fingerprinting (`discord_utils.node`: `sub_a3990` -> `sub_a4120` -> `sub_1350`)

When a real game is detected by Discord's native process observer (`setObservedGamesCallback` in `discord_utils.node`), function `sub_a3990` (`0x1800a3990`) invokes `sub_a4120` (`0x1800a4120`), `sub_a3f60` (`0x1800a3f60`), and `sub_1350` (`0x180001350`) to construct and encrypt a **146-byte (`0x92`) binary fingerprint** for the running `.exe` into a **196-character Base64 string** named **`executableFingerprint`**.

### 2.1 Binary Layout of the 146-Byte (`0x92`) Struct (`sub_1350` at `0x180001350`)

| Offset | Size | Field | Native Source in `discord_utils.node` |
| :--- | :--- | :--- | :--- |
| `0x00` | `1 B` | `version` | Always `0x01` (un-XORed plaintext header byte in `sub_1350`) |
| `0x01` | `1 B` | `flags` | Bitfield (`0x03` for signed PE64): `Bit 0 (0x01)` = `is_signed` (`WinVerifyTrust == 0` at `0x1800a4224`), `Bit 1 (0x02)` = `is_pe64` (`OptionalHeader.Magic == 0x20B` at `0x1800a3d3b`) |
| `0x02..0x09` | `8 B` | `file_size` | `uint64 LE` from `GetFileSizeEx` (`0x1800a3b97`) |
| `0x0A..0x0D` | `4 B` | `time_date_stamp` | `uint32 LE` PE COFF `FileHeader.TimeDateStamp` (`e_lfanew + 0x08`) |
| `0x0E..0x11` | `4 B` | `size_of_image` | `uint32 LE` PE `OptionalHeader.SizeOfImage` (`e_lfanew + 0x50`, page-aligned) |
| `0x12..0x31` | `32 B` | `pe_headers_sha256` | `SHA-256` of DOS + NT + Optional PE headers (`0x1800a3cb3..0x1800a3cd2`) |
| `0x32..0x51` | `32 B` | `hw_sha256` | Hardware + user hash from `sub_a3f60` (`0x1800a3f60`): `SHA-256(RegGetValueW("HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid") \|\| userId)` |
| `0x52..0x71` | `32 B` | `sections_sha256` | `SHA-256` of the PE `IMAGE_SECTION_HEADER` table (`NumSections * 40` bytes at `0x1800a3cd7..0x1800a3d16`) |
| `0x72..0x91` | `32 B` | `cert_sha256` | Authenticode certificate hash from `sub_a4120` (`0x1800a4120`): `SHA-256(UTF8(Publisher_CN) \|\| SHA256(SubjectPublicKeyInfo))` |

### 2.2 Stream Obfuscation (`sub_1350` at `0x180001350` & `sub_116790` at `0x180116790`)

Before returning `executableFingerprint` to JavaScript (`RunningGameStore`), `sub_1350` derives a 32-byte key:

$$\text{Key} = \text{SHA-256}(\text{userId} \mathbin{\Vert} \text{"https:}\text{//discord.com/careers"})$$

keeps byte `0x00` (`version = 0x01`) un-XORed, and XORs bytes `i = 1..145` (`0x01..0x91`):

$$\text{cipher}[0] = 1, \quad \text{cipher}[i] = \text{plain}[i] \oplus \text{Key}[(i - 1) \bmod 32] \quad (1 \le i \le 145)$$

Finally, `sub_116790` Base64-encodes the 146-byte buffer into a **196-character string** (`executableFingerprint`).

---

## 3. Quest Heartbeat & Telemetry Pipeline in `discord_web_bundle.js`

### 3.1 `Module 396813` (`ea(e)` — `QUESTS_HEARTBEAT`) & `Module 973522` (`o.Ic`)

When `QuestProgressManager` (`Module 378187`) sends a desktop play heartbeat, it executes `ea(e)` in `Module 396813`:
```js
let t = m.Ay.getRunningGames().find(t => t.id === n),
    r = (0, o.Ic)(t?.exePath),
    i = t?.executableFingerprint;
return L.A.post({
    url: R.Rsh.QUESTS_HEARTBEAT(e),
    body: {
        stream_key: a,
        container_id: s,
        application_id: n,
        terminal: l,
        executable_path: r,
        executable_fingerprint: i
    }
});
```
where `o.Ic` (`Module 973522`) normalizes `exePath` to the **last 2 lowercase `/` segments**:
```js
function u(e) {
    return null == e ? null : e.toLowerCase().replaceAll("\\", "/").split("/").filter(e => "" !== e).slice(-2).join("/");
}
```

### 3.2 `Module 499785` (`L.A.post` — `HTTPWithAnalytics`) Stack Trace Leak

Crucially, `Module 396813` does **not** use raw `RestAPI.post` (`o.Bo.post`). It calls `L.A.post` (`Module 499785`), which wraps `RestAPI.post` and dispatches the `network_action_quest_heartbeat` science analytics event containing:
```js
{
    quest_id: i,
    application_id: t.body?.application_id,
    executable_path: t.body?.executable_path,
    executable_fingerprint: t.body?.executable_fingerprint,
    stack_trace: Error().stack ?? "",
    is_playtime_eligible: a
}
```
- If a tool calls raw `RestAPI.post({ url: "/quests/.../heartbeat" })`, Discord's backend receives the HTTP heartbeat **without** the corresponding `network_action_quest_heartbeat` science event.
- If a tool triggers `QuestProgressManager` from a Vencord plugin or DevTools console without sanitizing `Error.prototype.stack`, `stack_trace` directly transmits `vencord://`, `CompleteDiscordQuest`, or `<anonymous>:` frames!

### 3.3 `libdiscore-wasm` + `Module 70298` `generateLaunchSignature` (128-Bit Client-Mod & DevTools Bitfield) and `Module 174459` Closure Bypass

Every API request includes `X-Super-Properties` (Base64 JSON). Inside `libdiscore-wasm` and `Module 70298` (called by `Module 174459`), `generateLaunchSignature()` generates a 128-bit UUIDv4 and probes `window` properties (`window.$`, `window.Vencord`, `window.VencordNative`, `window.Vesktop`, `window.VesktopNative`, `window.Equicord`, `window.EquicordNative`, `window.BdApi`, `window.BetterDiscord`, `window.rambox`, etc.) as well as DevTools docking dimensions (`outerWidth - innerWidth > 160` -> **Bit 8**), setting **13 detection bits** in the UUID (`[0, 8, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116]`, MSB-first where Bit 0 is `window.$`, Bit 8 is DevTools docked, and Bit 43 is `window.Vencord`).
- Furthermore, in Discord Build `657850` (`web.f86c748842ee176f.js`), `Module 174459` caches `let N = ...` in a private module closure and overwrites `t.launch_signature = N` inside its internal `track()` builder right *before* running `C.forEach(e => e(t))` decorators registered via `addExtraAnalyticsDecorator`. Patching `SuperPropertiesStore` alone is insufficient if `Module 174459` initialized before the plugin; registering an `addExtraAnalyticsDecorator` callback guarantees `launch_signature`, `has_client_mods`, `stack_trace`, and `fullscreen_type` are scrubbed on every outgoing science event.

### 3.4 `Module 396813`, `Module 710969`, & `Module 738822`: Sealed Ad-Decision Metadata, Interactive Quests (`ACHIEVEMENT_IN_ACTIVITY`), & Multi-Platform Reward Claiming

1. **Background Fetching & Backfilling of `metadata_sealed` / `traffic_metadata_sealed` (`Module 396813` & `Module 710969`):**
   - When Discord fetches quests or ad decisions (`N1` = `fetchCurrentQuests("quest_home")`, `r8` = `fetchQuestToDeliver(placement)`, `yO` = `fetchEarnedQuestToDeliver()`), `QuestsStore` and `AdDeliveryStore` (`getQuestAdDecisionByQuestId(questId)`) populate `metadataSealed`, `trafficMetadataRaw`, and `trafficMetadataSealed`.
   - When enrolling (`Oy` -> `POST /quests/{id}/enroll`) or claiming a reward (`Oq` -> `POST /quests/{id}/claim-reward`), `Module 396813` uses `Module 710969` (`p(questContent)`) to map `questContent` (`1` = `QUEST_BAR_V2`, `11` = `QUEST_HOME_DESKTOP`) to placement `1`, attaches `metadata_sealed` when appropriate, and always attaches `traffic_metadata_sealed`.
2. **Interactive Activity Quests (`ACHIEVEMENT_IN_ACTIVITY` / `PLAY_ACTIVITY` — `Module 396813` `R2`):**
   - Interactive activity quests (such as `VALORANT Aces`) use task type `ACHIEVEMENT_IN_ACTIVITY` or `PLAY_ACTIVITY` with `questContentCTA: "START_QUEST"`.
   - In `Module 396813`, activity heartbeats (`POST /quests/{id}/heartbeat`) send `{ stream_key: "call:<channelId>:1", application_id: "<appId>", terminal: false }` (and `terminal: true` on completion) via `QuestSendHeartbeatAction` (`QUEST_HEARTBEAT` tracked action) without desktop `.exe` fields (`executable_path` / `executable_fingerprint`).
3. **Configurable Multi-Platform Reward Priority (`Module 738822` `QuestRewardPlatform`):**
   - `Module 738822` defines `QuestRewardPlatform`: `CROSS_PLATFORM = 0`, `XBOX = 1`, `PLAYSTATION = 2`, `SWITCH = 3`, `PC = 4`.
   - For multi-platform `REWARD_CODE` quests (`rewardsConfig.platforms.length > 1`), selecting the highest-priority available platform according to a configurable priority order (default `[4, 2, 1, 3, 0]` = `PC -> PS5/PlayStation -> Xbox -> Switch -> Cross-Platform`) enables automatic reward claiming without user intervention.

### 3.5 `Module 19575` (`GetWindowFullscreenTypeByPid` & `GetSystemServicePerformanceMonitorSnapshot`) Windowless Game Anomaly

In Build `657850`, `DiscordUtils` (`getDiscordUtils` / `setObservedGamesCallback`) and the Overlay/Performance bridge (`Module 19575` exporting `GetWindowFullscreenTypeByPid` and `GetSystemServicePerformanceMonitorSnapshot`) live in **separate** Webpack modules.
- `GetWindowFullscreenTypeByPid(pid, name, defaultType)` is **synchronous** (`returns number` indexing `MB.aI`: `0 = UNKNOWN`, `1 = WINDOWED`, `2 = MAXIMIZED`, `3 = BORDERLESS_FULLSCREEN`, `4 = FULLSCREEN`). `ScreenTypeAnalytics.update()` checks `if (!(t in this.counters)) L.error(...)`; returning a Promise or leaving a windowless spoofed game at `0` (`UNKNOWN`) produces Sentry errors or `LAUNCH_GAME` events with `fullscreen_type: "UNKNOWN"` for the entire 15-minute quest session.
- `GetSystemServicePerformanceMonitorSnapshot(pid)` returns a Promise resolving to a 33-field `game_foreground_*` / `game_background_*` FPS & frame-jitter summary; returning `null` for an active PID flags the game as a windowless phantom process.

---

## 4. Vulnerability Breakdown by Repository

### 4.1 `aamiaa/CompleteDiscordQuest.md`
1. **`executableFingerprint` is `undefined`:** `fakeGame` only defines 11 properties and omits `executableFingerprint`. Every `PLAY_ON_DESKTOP` heartbeat sends `executable_fingerprint: undefined`.
2. **Destructive `RunningGameStore` overwrite:** Replaces `getRunningGames()` with `[fakeGame]` and dispatches `removed: realGames`, causing an unnatural simultaneous drop of all background processes.
3. **Late `delete window.$`:** Does not scrub already-set detection bits (`Bit 0`, `Bit 8`, `Bit 43`, etc.) in `X-Super-Properties.launch_signature`, nor does it sanitize `Error.prototype.stack`.
4. **Exact integer `timestamp` on final `WATCH_VIDEO` POST:** Sends `{ timestamp: secondsNeeded }` as an exact integer and does not rate-gate against `enrolledAt` in the main snippet.

### 4.2 `nicola02nb/completeDiscordQuest` (Vencord Plugin)
1. **Guaranteed Client-Mod Flag (`Bit 43` in `launch_signature`) + `vencord://` in `stack_trace`:** Because it runs as a Vencord plugin without scrubbing `launch_signature` or `Error.prototype.stack`, every Quest heartbeat carries Vencord's bitfield signature in `X-Super-Properties` and Vencord stack frames in `network_action_quest_heartbeat`.
2. **Missing `executableFingerprint` & incomplete 22-key `RunningGameStore` schema:** `fakeGame` in `index.tsx` lacks `executableFingerprint`, sending `executable_fingerprint: undefined` on `PLAY_ON_DESKTOP` heartbeats.
3. **Unnatural `STREAM_ON_DESKTOP` metadata & Simultaneous `/enroll` Bursts:** Sets `name: "FakeApp ${applicationName} (CompleteDiscordQuest)"` on `fakeApp`, fires parallel `/enroll` bursts without spacing, and terminates spoofed games on the exact millisecond a quest completes.

### 4.3 `Masterain98/discord-quest-helper`
1. **Unsigned Dummy PE (`stagecraft.exe` / `stealth_pe.rs`) Fails `WinVerifyTrust`:**
   - When `discord_utils.node` scans the dummy process, `WinVerifyTrust` (`0x1800a4224`) returns non-zero (`is_signed = 0`, so `flags` bit 0 is `0`), `cert_sha256` (`[0x72..0x91]`) is 32 zero bytes (`00..00`), and `file_size` is ~150 KB instead of a 48–140 MB Authenticode-signed game binary.
2. **CDP Spoof Explicitly Sets `executableFingerprint: undefined` (`cdp_quest.rs:497`):**
   - In CDP mode (`js_spoof_play_game_for`), `fakeGame.executableFingerprint` is hardcoded to `undefined`!
3. **Direct API Game Heartbeat Omits `executable_path` & `executable_fingerprint` (`discord_api.rs:900`):**
   - `GameHeartbeatPayload` only serializes `{ application_id, terminal }`, omitting `executable_path` and `executable_fingerprint` completely.
4. **Video Progress Float Jitter Destroyed by `timestamp.round() as u64` (`discord_api.rs:195`):**
   - `quest_completer.rs:123` adds `rand::rng().random_range(0.0..0.5)`, but `discord_api.rs:195` immediately calls `timestamp.round() as u64`, turning every timestamp back into an integer!
5. **Positive Behavioral Defenses Worth Porting (Oct–Nov 2026 commits):**
   - Post-quest keep-alive cooldown (`random` or `fixed` extra minutes after `100%` completion, chunked safely across 32-bit timer boundaries), sequential humanized `/enroll` delays, optional mid-session game pause/reopen simulation with fresh PIDs, multi-account/logout session cleanup, and single-pass templated webhook notifications (`dqh_v1` & Discord Embeds).

---

## 5. Summary of Applied Stealth Fixes

1. **`sub_a3990` / `sub_a4120` / `sub_a3f60` / `sub_1350` Signed `executableFingerprint` Synthesis:**
   - Synthesizes a valid 146-byte (`0x92`) binary payload with un-XORed `version = 0x01`, `flags = 0x03` (`is_signed | is_pe64`), realistic 48–140 MB `file_size`, valid PE `time_date_stamp` and page-aligned `size_of_image`, deterministic `pe_headers_sha256` (`[0x12..0x31]`), real local `hw_sha256` (`[0x32..0x51]`, harvested from existing native process entries or computed from `SHA-256(MachineGuid || userId)`), `sections_sha256` (`[0x52..0x71]`), and `cert_sha256` (`[0x72..0x91]`, `SHA-256(UTF8(Publisher_CN) || SPKI_SHA256)`), XORed on bytes `1..145` with `SHA-256(userId + "https://discord.com/careers")` and Base64-encoded to 196 characters.
2. **`Module 973522` (`o.Ic`) 2-Segment `executable_path` Formatting:**
   - Ensures all `exePath` and `executable_path` values conform to Discord's 2-segment lowercase forward-slash format.
3. **13-Bit `launch_signature` Client-Mod/DevTools Scrubber, `addExtraAnalyticsDecorator` Closure Guard, & `Error.prepareStackTrace` Sanitizer:**
   - Clears all 13 detection bits (`[0, 8, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116]`) in `X-Super-Properties` AND inside `Module 174459`'s `addExtraAnalyticsDecorator` pipeline, hides `Vencord` / `Vesktop` / `Equicord` / `BetterDiscord` / `rambox` globals via `Proxy(window)`, and strips `<anonymous>`, `vencord://`, and plugin frames via `Error.prepareStackTrace`.
4. **Synchronous `WINDOWED` (`1`) Fullscreen Normalization, 33-Field Performance Monitor Synthesis, & `getGameForName` Parity:**
   - Normalizes windowless spoofed games to `fullscreenType = 1` (`WINDOWED`), hooks `Module 19575`'s `GetWindowFullscreenTypeByPid` synchronously and `GetSystemServicePerformanceMonitorSnapshot` asynchronously with realistic foreground/background FPS & jitter metrics, hooks `RunningGameStore.getGameForName` alongside `getRunningGames` and `getGameForPID`, and retains a 15-second PID tombstone cache.
5. **Native Tracked-Action Parity (`QuestVideoProgressAction` / `QuestSendHeartbeatAction`) & Dynamic Electron `User-Agent`:**
   - Routes `WATCH_VIDEO` progress and `PLAY_ACTIVITY` heartbeats through Discord's own `HTTPWithAnalytics` tracked actions (`QUEST_VIDEO_PROGRESS` and `QUEST_HEARTBEAT`) while preserving millisecond float jitter (`f64`), and dynamically resolves Electron's runtime `session.getUserAgent()` in main-process HTTP helpers.
6. **Behavioral Cadence Hardening, Multi-Account Lifecycle Cleanup, & Notifications:**
   - Sequentializes `/enroll` calls with randomized human delays, adds startup jitter + periodic `lastFocused` refreshes + configurable post-quest keep-alive (`2_147_000_000` ms chunked timers) + optional mid-session crash/reopen simulation on `PLAY_ON_DESKTOP`, cleans up all active timers/fake games on `LOGOUT` and `CONNECTION_OPEN` account switches, and provides native Mana Toast + single-pass templated Webhook notifications (`Discord` Embed & `dqh_v1` JSON).

---

## 6. Reference Implementations & Patches

- **Flagship Repository (Console Script, Vencord Plugins, Python CLI & Full IDA Write-up):** [`ccsimplyspolit/discord-quest-stealth`](https://github.com/ccsimplyspolit/discord-quest-stealth)
- **Standalone Console Script & Full Audit Gist:** [`ccsimplyspolit/CompleteDiscordQuest.md`](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)
- **Vencord Plugin Implementation:** [`ccsimplyspolit/completeDiscordQuest`](https://github.com/ccsimplyspolit/completeDiscordQuest) (Upstream PR: [`nicola02nb/completeDiscordQuest#28`](https://github.com/nicola02nb/completeDiscordQuest/pull/28))
- **Rust / Tauri / CDP Implementation:** [`ccsimplyspolit/discord-quest-helper`](https://github.com/ccsimplyspolit/discord-quest-helper) (Upstream PR: [`Masterain98/discord-quest-helper#218`](https://github.com/Masterain98/discord-quest-helper/pull/218))
- **Author & Security Research Portfolio:** [`@ccsimplyspolit`](https://github.com/ccsimplyspolit)


