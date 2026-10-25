# DreamShield

DreamShield is an Android DNS filtering VPN for Android 8.0/API 26 and newer. It uses Android's `VpnService`; it is not a mock UI and does not install a root certificate or inspect HTTPS.

## Architecture

The VPN interface assigns `10.77.0.2` to its local endpoint, advertises a DNS resolver at `10.77.0.1`, and routes only that resolver address to its TUN file descriptor. The packet loop accepts IPv4 UDP DNS requests, parses the question, returns NXDOMAIN for blocked names, and forwards other questions to Quad9 (`9.9.9.9`, with `149.112.112.112` as fallback). Upstream datagram and TCP sockets are explicitly protected from the VPN to avoid routing loops. If an upstream UDP answer is truncated, DreamShield retries over protected TCP. Unavailable or invalid upstream replies produce SERVFAIL. Other IP traffic remains on Android's ordinary network path.

Rules include an allowlist, a user blocklist, and the AdGuard DNS filter. Matching checks the requested host and each parent suffix. Plain domain and hosts rules plus simple AdGuard domain rules and exceptions are supported. Type/client scoped rules, DNS rewrites, and other non-hostname filter behavior are skipped because the engine makes decisions by hostname. The downloaded filter is stored on-device, updated only when the user taps **Update blocklist**, and retained if a download fails. Size and minimum-valid-rule checks reject obviously incomplete feeds. DreamShield does not collect domain names in logs; it stores an aggregate blocked-query count and generic lifecycle/error diagnostics locally.

### Blocklist source and license

- Feed: [AdGuard DNS filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt), maintained by AdGuard and composed/simplified for DNS filtering.
- Source repository and license: [AdGuardTeam/AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter), GPL-3.0. DreamShield downloads the list at the user's request instead of bundling a snapshot. The feed host receives the update request's normal connection metadata; the feed request does not include this phone's DNS query history.
- A broad list can block domains used by legitimate app functions. Allowlist specific domains if needed. Refresh is manual, not automatic.

## Permissions and privacy

- `INTERNET`: download the selected filter and resolve unblocked DNS requests.
- `FOREGROUND_SERVICE` / `FOREGROUND_SERVICE_SPECIAL_USE`: keep the user-started VPN active with an ongoing notification on current Android versions.
- Android VPN consent is requested through `VpnService.prepare()`. Android permits one active VPN at a time.
- Android's Settings-managed **Always-on VPN** option is explicitly disabled for this first version; start and stop protection in DreamShield.
- DNS is sent to Quad9 at `9.9.9.9` over ordinary DNS (UDP/TCP port 53), not encrypted DNS. Quad9 receives domain queries and the network-visible source address while resolving them. Quad9's [privacy policy](https://www.quad9.net/privacy/policy/) says it does not collect or hold end-user IP addresses; consult its current policy for details. A carrier or Wi-Fi network can observe unencrypted DNS unless it separately encrypts or proxies it.
- DreamShield itself does not upload DNS logs. Local diagnostics omit queried domain names. Block counts and the cached blocklist remain in app-private preferences.

## Build and tests

The project targets SDK 35, min SDK 26, uses Kotlin and Android Gradle Plugin 8.7.3, and needs JDK 17, Gradle 8.9, and Android SDK platform 35/build tools. From this directory:

```sh
gradle testDebugUnitTest
gradle assembleDebug
```

The phone environment used to start this project reports Android 15/API 35, but has no Java/JDK, Gradle, Kotlin compiler, Android SDK, or `adb` installed. `.github/workflows/android.yml` runs unit tests, builds a debug APK, and uploads it as an artifact on GitHub Actions. The latest verified run passed the unit tests and APK build for commit `b7c913cf409bbbf35183e4fde9b4634376b30cbd`. Device-level VPN behavior and runtime tests are still outstanding.

Unit tests cover rule parsing/matching, NXDOMAIN construction, IPv4 UDP endpoint swapping, and checksums. TUN integration, live DNS, Android permission prompts, Xiaomi background survival, Phoenix Browser, and YouTube app behavior need on-device testing with the built APK. No successful Android build or runtime test is claimed yet.

## Install and device test

1. Build `app/build/outputs/apk/debug/app-debug.apk`, or download that artifact from a successful GitHub Actions run.
2. Install the APK from the phone's Downloads/files UI (allow Android's one-time unknown-app install prompt if needed).
3. Open DreamShield, read onboarding, tap **Update blocklist**, then **Start protection** and approve Android's VPN prompt.
4. Confirm DreamShield says **Protection active**, Android shows its VPN key/notification, blocked counts change for a known blocked test domain, and normal browsing succeeds for an allowed domain. Check Android Settings > Network & internet > VPN if Android reports disconnection.
5. On Xiaomi HyperOS, if protection is killed after backgrounding or reboot, Xiaomi's general guidance is to set the app battery mode to **No restrictions**; its autostart settings are under Settings > Apps > Permissions > Background autostart on supported builds. Labels vary by build. Do not enable **Block connections without VPN** until reconnect behavior is reliable; that switch can cut off all network access while the filter is unavailable. [Xiaomi battery guidance](https://www.mi.com/uk/support/faq/details/KA-538010/) · [Xiaomi autostart guidance](https://www.mi.com/global/support/faq/details/KA-507611/)
6. Retest after switching Wi-Fi/mobile data, with Android Private DNS enabled and disabled, and with any other VPN off. Browser-specific secure DNS can bypass system DNS filtering.

## Limits and video/browser testing

DNS filtering blocks hostnames, not page elements. It cannot selectively remove an ad when a service delivers ads and requested video/content from the same host. Some apps and browsers use DNS-over-HTTPS, DNS-over-TLS, hard-coded resolver IPs, or their own VPN and can bypass a local DNS VPN. This version routes the VPN-provided IPv4 DNS endpoint; it is not a general traffic tunnel or IPv6 packet filter. IPv6 and arbitrary DNS-over-TCP packets sent by apps are not processed by the packet loop. Android's resolver normally issues UDP queries and DreamShield handles truncated upstream results over TCP, but this path needs device validation.

- **Official YouTube app:** Expect ads to remain. Ads and content may share delivery infrastructure, so DNS filtering cannot separate them reliably. The app has not been tested on the Xiaomi device. YouTube's [viewer help](https://support.google.com/youtube/answer/14129599) points viewers to allow ads or use YouTube Premium and warns that ad blockers can affect playback.
- **Phoenix Browser:** Not installed or tested here. Phoenix's [official browser page](https://phoenix-browser.com/about) describes its built-in ad block, which is the appropriate first browser-specific control. DreamShield can filter only DNS names Phoenix resolves through Android's VPN DNS. If it uses encrypted or custom DNS, system DNS filtering may not apply. Verify Phoenix's DNS/privacy settings on-device.
- **Browser-based video:** Use browser content controls where supported. Mozilla documents add-ons for Firefox on Android, whose add-on catalog includes content blockers such as uBlock Origin, subject to current compatibility. YouTube Premium is the official option for ad-free YouTube playback. Extensions affect only that browser and may not work in all builds or private tabs.

## Git status

This standalone project is pushed to the private [ZaccyDreamer/DreamShield repository](https://github.com/ZaccyDreamer/DreamShield), on branch `main`. The DreamShield working tree is tracked in its own repository under `Projects/DreamShield`; the parent home folder is a separate, unrelated worktree.
