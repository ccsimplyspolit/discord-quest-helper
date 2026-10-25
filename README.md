# Discord Quest Stealth Suite (`executableFingerprint` + `launch_signature` + Vencord & Console Completer)

> **Full Reverse-Engineering Audit (`discord_utils.node` `sub_a3990` / `sub_a4120` / `sub_a3f60` / `sub_1350` & `libdiscore-wasm`) + Stealth-Hardened Console Script, Vencord Plugins, and Python Fingerprint CLI**

[![Gist Console Script](https://img.shields.io/badge/Gist-CompleteDiscordQuest.md-blue?logo=github)](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)
[![Vencord PR #28](https://img.shields.io/badge/Vencord_Plugin-PR_%2328-success?logo=github)](https://github.com/nicola02nb/completeDiscordQuest/pull/28)
[![Tauri/Rust PR #218](https://img.shields.io/badge/Tauri_Desktop_Helper-PR_%23218-orange?logo=rust)](https://github.com/Masterain98/discord-quest-helper/pull/218)

---

## Why Unpatched Quest Completers Trigger `Quest Activity Notice`

Starting in August 2026 (`app-1.0.9265+`), Discord deployed native and WebAssembly anti-fraud checks across `discord_utils.node`, `libdiscore-wasm`, and `discord_web_bundle.js` (`Module 396813`, `Module 378187`, `Module 499785`, `Module 973522`). Legacy scripts and plugins (`aamiaa/CompleteDiscordQuest.md`, unpatched `nicola02nb/completeDiscordQuest`, unpatched `Masterain98/discord-quest-helper`) get flagged because of six concrete telemetry mismatches:

1. **Missing `executableFingerprint` on `POST /quests/{id}/heartbeat` (`discord_utils.node` `sub_a3990` -> `sub_1350`):**
   - When `RunningGameStore.getRunningGames()` is spoofed without `executableFingerprint`, `Module 396813` (`ea(e)`) sends `executable_fingerprint: undefined` on every `PLAY_ON_DESKTOP` heartbeat.
2. **Unsigned Dummy `.exe` Fails `WinVerifyTrust` (`sub_a4120` at `0x1800a4120`):**
   - Spawning an unsigned dummy executable causes `WinVerifyTrust` (`0x1800a4224`) to return non-zero (`is_signed = 0` in `flags`), leaving `cert_sha256` (`[0x72..0x91]`) as 32 zero bytes (`00..00`).
3. **12-Bit Client-Mod Signature in `X-Super-Properties.launch_signature` (`libdiscore-wasm`):**
   - `generateLaunchSignature()` probes `window.Vencord`, `window.VencordNative`, `window.$`, `window.BdApi`, etc. and sets 12 specific bits (`[0, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116]`, MSB-first) inside the 128-bit `launch_signature` UUIDv4 sent in `X-Super-Properties`. Bit `43` specifically flags `window.Vencord`; Bit `0` flags `window.$`.
4. **`vencord://` & `<anonymous>` Leak in `network_action_quest_heartbeat.stack_trace` (`Module 499785`):**
   - `HTTPWithAnalytics.post` (`Module 499785`) captures `Error().stack ?? ""` on every Quest heartbeat and sends it in the `network_action_quest_heartbeat` science event.
5. **Destructive `RunningGameStore.getRunningGames` Override & `OverlayRenderStore` Untracked PID Warnings:**
   - Replacing `getRunningGames()` instead of merging drops all genuine running games simultaneously, omits 11 of the 22 native process observer fields, and triggers `[OverlayRenderStore] Tried to determine initial overlay method for untracked pid` on teardown if no PID tombstone cache is kept.
6. **Missing Sealed Ad-Decision Tokens (`metadata_sealed` / `traffic_metadata_sealed`) & Integer `WATCH_VIDEO` Timestamps:**
   - Background `/enroll` and `/claim-reward` calls omit `metadata_sealed` (`Module 396813` `Oy` / `Oq`) if Quest Home was not manually opened, and sending an exact integer `timestamp: secondsNeeded` on the final `/video-progress` call flags synthetic video completion.

---

## Native `executableFingerprint` Architecture (`discord_utils.node`)

When Discord's native process scanner (`setObservedGamesCallback` in `discord_utils.node`) observes a running game `.exe`, `sub_a3990` (`0x1800a3990`) invokes `sub_a4120` (`0x1800a4120`), `sub_a3f60` (`0x1800a3f60`), and `sub_1350` (`0x180001350`) to build and encrypt a **146-byte (`0x92`) binary struct** into a **196-character Base64 string** (`executableFingerprint`):

| Offset | Size | Field | Native Source in `discord_utils.node` |
| :--- | :--- | :--- | :--- |
| `0x00` | `1 B` | `version` | Always `0x01` (**un-XORed** plaintext header byte in `sub_1350`) |
| `0x01` | `1 B` | `flags` | Bitfield (`0x03` for signed PE64): `Bit 0 (0x01)` = `is_signed` (`WinVerifyTrust == 0` at `0x1800a4224`), `Bit 1 (0x02)` = `is_pe64` (`OptionalHeader.Magic == 0x20B` at `0x1800a3d3b`) |
| `0x02..0x09` | `8 B` | `file_size` | `uint64 LE` from `GetFileSizeEx` (`0x1800a3b97`) |
| `0x0A..0x0D` | `4 B` | `time_date_stamp` | `uint32 LE` PE COFF `FileHeader.TimeDateStamp` (`e_lfanew + 0x08`) |
| `0x0E..0x11` | `4 B` | `size_of_image` | `uint32 LE` PE `OptionalHeader.SizeOfImage` (`e_lfanew + 0x50`, page-aligned) |
| `0x12..0x31` | `32 B` | `pe_headers_sha256` | `SHA-256` of DOS + NT + Optional PE headers (`[0..SizeOfHeaders)` at `0x1800a3cb3..0x1800a3cd2`) |
| `0x32..0x51` | `32 B` | `hw_sha256` | Hardware + user hash from `sub_a3f60` (`0x1800a3f60`): `SHA-256(RegGetValueW("HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid") \|\| userId)` |
| `0x52..0x71` | `32 B` | `sections_sha256` | `SHA-256` of the PE `IMAGE_SECTION_HEADER` table (`NumSections * 40` bytes at `0x1800a3cd7..0x1800a3d16`) |
| `0x72..0x91` | `32 B` | `cert_sha256` | Authenticode certificate hash from `sub_a4120` (`0x1800a4120`): `SHA-256(UTF8(Publisher_CN) \|\| SHA256(SubjectPublicKeyInfo))` |

### Stream XOR Encryption (`sub_1350` at `0x180001350` & `sub_116790` at `0x180116790`)

Before returning `executableFingerprint` to JavaScript (`RunningGameStore`), `sub_1350` derives a 32-byte key:

$$\text{Key} = \text{SHA-256}(\text{userId} \mathbin{\Vert} \text{"https:}\text{//discord.com/careers"})$$

keeps byte `0x00` (`version = 0x01`) **un-XORed**, and XORs bytes `i = 1..145` (`0x01..0x91`):

$$\text{cipher}[0] = 1, \quad \text{cipher}[i] = \text{plain}[i] \oplus \text{Key}[(i - 1) \bmod 32] \quad (1 \le i \le 145)$$

Finally, `sub_116790` Base64-encodes the 146-byte buffer into a **196-character string** (`executableFingerprint`).

> Full IDA disassembly, decompilation, and module analysis: **[`SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md`](./SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md)**

---

## Repository Contents & Quick Start

| Path | Description |
| :--- | :--- |
| **[`console/CompleteDiscordQuest.js`](./console/CompleteDiscordQuest.js)** | Ready-to-paste DevTools Console script with WebCrypto `sub_1350` `executableFingerprint` synthesis, `launch_signature` 12-bit scrubber, `Error.prepareStackTrace` cloaking, `metadata_sealed` auto-backfill, `ACHIEVEMENT_IN_ACTIVITY` support, and multi-platform reward auto-claim (`PC -> PS5 -> Xbox -> Switch`). |
| **[`console/CompleteDiscordQuest.md`](./console/CompleteDiscordQuest.md)** | Full Markdown guide & FAQ for the standalone Console script (synced with [Gist `f323e1b626dff79bfc08b24bc3dc27bd`](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)). |
| **[`vencord/completeDiscordQuest/`](./vencord/completeDiscordQuest/)** | Stealth-hardened Vencord userplugin for automatic background Quest enrollment, completion, and multi-platform reward claiming. |
| **[`vencord/discordStealthGuard/`](./vencord/discordStealthGuard/)** | Companion Vencord userplugin providing global `launch_signature` bit-scrubbing, native `RunningGameStore` fingerprint synthesis/harvesting, and `/quests/*` payload sanitization. |
| **[`tools/discord_exe_fingerprint.py`](./tools/discord_exe_fingerprint.py)** | Bit-for-bit Python 3 port of `sub_a3990`, `sub_a4120` (Win32 `WinVerifyTrust` + `CryptHashPublicKeyInfo`), `sub_a3f60`, and `sub_1350` for extracting, synthesizing, and decrypting 196-char `executableFingerprint` tokens. |
| **[`SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md`](./SECURITY_AUDIT_AND_REVERSE_ANALYSIS.md)** | Complete reverse-engineering write-up of `discord_utils.node`, `libdiscore-wasm`, and `discord_web_bundle.js`. |

### Option 1: Standalone DevTools Console Script (Zero Install)
1. Open the **Discord Desktop App** and accept a quest (or let the script auto-enroll & complete).
2. Press <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd> to open DevTools -> **Console** tab.
3. Copy the contents of **[`console/CompleteDiscordQuest.js`](./console/CompleteDiscordQuest.js)** (or from **[Gist `f323e1b626dff79bfc08b24bc3dc27bd`](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)**), paste into Console, and press <kbd>Enter</kbd>.

### Option 2: Vencord Userplugins (`completeDiscordQuest` + `discordStealthGuard`)
1. Copy `vencord/completeDiscordQuest` and `vencord/discordStealthGuard` into your Vencord `src/userplugins/` directory:
   ```bash
   cp -r vencord/completeDiscordQuest vencord/discordStealthGuard /path/to/Vencord/src/userplugins/
   pnpm build
   ```
2. Enable **CompleteDiscordQuest** and **DiscordStealthGuard** in Vencord Settings -> Plugins.

### Option 3: Python CLI Extractor, Synthesizer & Decryptor
```bash
# Run built-in round-trip encryption/decryption verification test
python tools/discord_exe_fingerprint.py --self-test

# Synthesize a valid 196-char signed PE64 executableFingerprint without needing the game installed
python tools/discord_exe_fingerprint.py --synthesize "C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe" --publisher "Valve Corp." --user-id 123456789012345678

# Decrypt and inspect any 196-char Base64 executableFingerprint captured from Discord
python tools/discord_exe_fingerprint.py --decrypt "<196-char-base64>" --user-id 123456789012345678
```

---

## Ecosystem & Upstream Pull Requests

- **Standalone Console Script & Full Audit Gist:** [`ccsimplyspolit/CompleteDiscordQuest.md`](https://gist.github.com/ccsimplyspolit/f323e1b626dff79bfc08b24bc3dc27bd)
- **Vencord Plugin Upstream PR & Fork:** [`nicola02nb/completeDiscordQuest#28`](https://github.com/nicola02nb/completeDiscordQuest/pull/28) ([`ccsimplyspolit/completeDiscordQuest`](https://github.com/ccsimplyspolit/completeDiscordQuest))
- **Desktop Tauri / Rust Helper Upstream PR & Fork:** [`Masterain98/discord-quest-helper#218`](https://github.com/Masterain98/discord-quest-helper/pull/218) ([`ccsimplyspolit/discord-quest-helper`](https://github.com/ccsimplyspolit/discord-quest-helper))

---

## 🇷🇺 Инструкция и описание на русском языке

В этом репозитории собраны результаты полного реверс-инжиниринга антифрод-системы Discord Quests (`discord_utils.node` `sub_a3990` / `sub_a4120` / `sub_a3f60` / `sub_1350`, `libdiscore-wasm` и `discord_web_bundle.js`) и готовые защищённые решения, предотвращающие табличку **`Quest Activity Notice`**:

1. **Генерация валидной 196-символьной подписи `executableFingerprint` (`sub_1350`):**
   - Формируется точный 146-байтный (`0x92`) бинарный пакет (`version = 0x01` без XOR, `flags = 0x03` `is_signed | is_pe64`, `file_size`, `time_date_stamp`, `size_of_image`, `pe_headers_sha256` `[0x12..0x31]`, локальный `hw_sha256` `[0x32..0x51]`, `sections_sha256` `[0x52..0x71]` и Authenticode `cert_sha256` `[0x72..0x91]`), зашифрованный потоковым XOR с ключом `SHA-256(userId + "https://discord.com/careers")` на байтах `1..145`.
2. **Очистка 12 бит детекта клиент-модов в `X-Super-Properties.launch_signature` и стека вызовов:**
   - Сбрасываются все 12 бит модификаций клиента (`[0, 19, 27, 36, 43, 52, 66, 72, 79, 89, 103, 116]`) и очищаются фреймы `vencord://` / `<anonymous>` через `Error.prepareStackTrace` в событии `network_action_quest_heartbeat`.
3. **Авто-подстановка `metadata_sealed` / `traffic_metadata_sealed`, мгновенное прохождение интерактивных активностей (`ACHIEVEMENT_IN_ACTIVITY`) и авто-клейм наград (`PC -> PS5 -> Xbox -> Switch`):**
   - Поддерживаются все типы заданий (`WATCH_VIDEO`, `PLAY_ON_DESKTOP`, `STREAM_ON_DESKTOP`, `PLAY_ACTIVITY`, `ACHIEVEMENT_IN_ACTIVITY`), включая полностью автоматическое серверное завершение интерактивных активностей (`/.proxy/acf/authorize` -> `/.proxy/acf/arise/register` -> `/.proxy/api/profileTitle/add` с 122-битным криптографическим MAC `X-Request-Id` из `module "lDfAK"` -> `/.proxy/acf/quest/progress`, пред-подтверждение `/applications/{id}/disclosures` и обход бага `GET_QUEST` для многораундовых квестов вроде *Эйсы VALORANT: раунд 3*), а также автоматический сбор наград без открытия вкладки «Задания».