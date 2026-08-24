# Project X

[Project X](https://github.com/XTLS) originates from XTLS protocol, providing a set of network tools such as [Xray-core](https://github.com/XTLS/Xray-core) and [REALITY](https://github.com/XTLS/REALITY).

[README](https://github.com/XTLS/Xray-core#readme) is open, so feel free to submit your project [here](https://github.com/XTLS/Xray-core/pulls).

## Fork features

This repository tracks upstream Xray-core and maintains additional server-focused features and hardening:

- **In-tree sing-mux stack:** sing-mux-compatible `smux` and `h2mux` clients and servers with TCP/UDP streams, optional padding, bounded connection pools, and no runtime dependency on an external mux library. H2MUX is selected outbound with `smux.protocol` and auto-detected inbound. See the [wire protocol specification](common/singmux/SPEC.md).
- **Brutal congestion control:** opt-in Brutal bandwidth negotiation for outbound SMUX/H2MUX clients and per-inbound servers through `smux.brutal-opts` (`enabled`, `up`, and `down`). Linux servers need the `brutal` congestion-control module.
- **Structured logging:** multiple independent console, JSONL file, and Unix-socket outputs with event filtering, batching, bounded queues, and configurable backpressure. Legacy logging remains supported. See the [configuration guide](common/log/CONFIGURATION.md).
- **Exact online presence:** when `statsUserOnline` is enabled, `user>>><email>>>online`, `GetStatsOnlineIpList`, and `GetAllOnlineUsers` follow authenticated logical traffic rather than long-lived carriers. This covers direct traffic, SMUX/H2MUX, legacy Mux/XUDP, reverse connections, and WireGuard flows.
- **Operator-controlled REALITY client versions:** server-side `minClientVer` and `maxClientVer` are optional and have no built-in default. An omitted bound rejects no client on that side of the range.
- **Expanded protocol sniffing:** QUIC v2 Initial packets and BitTorrent UDP traffic (uTP, DHT, and UDP trackers) can be identified for routing or blocking.
- **Hysteria/Realm extensions:** Realm supports `ipMode` selection and optional UPnP/NAT-PMP port mapping; finalmask QUIC settings expose loss-compensation, Chrome-parrot, and GSO controls synchronized with Hysteria 2.12.1 behavior.
- **uTLS fingerprint fidelity:** session resumption falls back to a full handshake when adding ticket or PSK extensions would change the selected fingerprint's original ClientHello shape.
- **Server-path hardening:** the fork carries additional VLESS/REALITY/Vision, mux lifecycle, buffering, half-close, and UDP correctness fixes. Exact changes and validation results are documented in the [fork releases](https://github.com/Jolymmiles/Xray-core/releases).

Official fork release artifacts currently target Linux. Other platforms can be built from source with the commands below. New configuration surfaces are opt-in, and existing upstream configurations remain supported.

## Sponsors

[![Remnawave](https://github.com/user-attachments/assets/a22d34ae-01ee-441c-843a-85356748ed1e)](https://docs.rw)

[**Sponsor Xray-core**](https://github.com/XTLS/Xray-core/issues/3668)

## Donation & NFTs

### [Collect a Project X NFT to support the development of Project X!](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

[<img alt="Project X NFT" width="150px" src="https://raw2.seadn.io/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/7fa9ce900fb39b44226348db330e32/8b7fa9ce900fb39b44226348db330e32.svg" />](https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1)

- **TRX(Tron)/USDT/USDC: `TNrDh5VSfwd4RPrwsohr6poyNTfFefNYan`**
- **TON: `UQApeV-u2gm43aC1uP76xAC1m6vCylstaN1gpfBmre_5IyTH`**
- **BTC: `1JpqcziZZuqv3QQJhZGNGBVdCBrGgkL6cT`**
- **XMR: `4ABHQZ3yJZkBnLoqiKvb3f8eqUnX4iMPb6wdant5ZLGQELctcerceSGEfJnoCk6nnyRZm73wrwSgvZ2WmjYLng6R7sR67nq`**
- **SOL/USDT/USDC: `3x5NuXHzB5APG6vRinPZcsUv5ukWUY1tBGRSJiEJWtZa`**
- **ETH/USDT/USDC: `0xDc3Fe44F0f25D13CACb1C4896CD0D321df3146Ee`**
- **Project X NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/1**
- **VLESS NFT: https://opensea.io/collection/vless**
- **REALITY NFT: https://opensea.io/item/ethereum/0x5ee362866001613093361eb8569d59c4141b76d1/2**
- **Related links: [VLESS Post-Quantum Encryption](https://github.com/XTLS/Xray-core/pull/5067), [XHTTP: Beyond REALITY](https://github.com/XTLS/Xray-core/discussions/4113), [Announcement of NFTs by Project X](https://github.com/XTLS/Xray-core/discussions/3633)**

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## Documentation

[Project X Official Website](https://xtls.github.io)

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

[Project VLESS](https://t.me/projectVless) (Русский)

[Project XHTTP](https://t.me/projectXhttp) (Persian)

## Installation

- Linux Script
  - [XTLS/Xray-install](https://github.com/XTLS/Xray-install) (**Official**)
  - [tempest](https://github.com/team-cloudchaser/tempest) (supports [`systemd`](https://systemd.io) and [OpenRC](https://github.com/OpenRC/openrc); Linux-only)
- Docker
  - [ghcr.io/xtls/xray-core](https://ghcr.io/xtls/xray-core) (**Official**)
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
  - [wulabing/xray_docker](https://github.com/wulabing/xray_docker)
- Web Panel
  - [Remnawave](https://github.com/remnawave/panel)
  - [3X-UI](https://github.com/MHSanaei/3x-ui)
  - [PasarGuard](https://github.com/PasarGuard/panel)
  - [Xray-UI](https://github.com/qist/xray-ui)
  - [X-Panel](https://github.com/xeefei/X-Panel)
  - [Marzban](https://github.com/Gozargah/Marzban)
  - [Hiddify](https://github.com/hiddify/Hiddify-Manager)
  - [TX-UI](https://github.com/AghayeCoder/tx-ui)
  - [CELERITY](https://github.com/ClickDevTech/CELERITY-panel)
- One Click
  - [Xray-REALITY](https://github.com/zxcvos/Xray-script), [xray-reality](https://github.com/sajjaddg/xray-reality), [reality-ezpz](https://github.com/aleskxyz/reality-ezpz)
  - [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey), [XTool](https://github.com/LordPenguin666/XTool), [VPainLess](https://github.com/vpainless/vpainless)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent), [Xray_onekey](https://github.com/wulabing/Xray_onekey), [ProxySU](https://github.com/proxysu/ProxySU)
- Magisk
  - [Magic_V2Ray](https://github.com/vincentng295/Magic_V2Ray)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`

## Usage

- Example
  - [VLESS-XTLS-uTLS-REALITY](https://github.com/XTLS/REALITY#readme)
  - [VLESS-TCP-XTLS-Vision](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)
  - [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)
- Xray-examples
  - [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples)
  - [chika0801/Xray-examples](https://github.com/chika0801/Xray-examples)
  - [lxhao61/integrated-examples](https://github.com/lxhao61/integrated-examples)
- Tutorial
  - [XTLS Vision](https://github.com/chika0801/Xray-install)
  - [REALITY (English)](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)
  - [XTLS-Iran-Reality (English)](https://github.com/SasukeFreestyle/XTLS-Iran-Reality)
  - [Xray REALITY with 'steal oneself' (English)](https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html)
  - [Xray with WireGuard inbound (English)](https://g800.pages.dev/wireguard)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/Openwrt-Passwall/openwrt-passwall), [PassWall 2](https://github.com/Openwrt-Passwall/openwrt-passwall2)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Asuswrt-Merlin
  - [XRAYUI](https://github.com/DanielLavrushin/asuswrt-merlin-xrayui)
  - [fancyss](https://github.com/hq450/fancyss)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [Invisible Man - Xray](https://github.com/InvisibleManVPN/InvisibleMan-XRayClient)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [XrayUI-dev](https://github.com/PhoenixNil/XrayUI-dev)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [X-flutter](https://github.com/XTLS/X-flutter)
  - [SaeedDev94/Xray](https://github.com/SaeedDev94/Xray)
  - [SimpleXray](https://github.com/lhear/SimpleXray)
  - [XrayFA](https://github.com/Q7DF1/XrayFA)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [AsteriskNG](https://github.com/Asterisk4Magisk/AsteriskNG)
- iOS & macOS arm64 & tvOS
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973) | [Happ tvOS](https://apps.apple.com/us/app/happ-proxy-utility-for-tv/id6748297274)
  - [Streisand](https://apps.apple.com/app/streisand/id6450534064)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [INCY](https://apps.apple.com/en/app/incy/id6756943388)
- macOS arm64 & x64
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973)
  - [V2rayU](https://github.com/yanue/V2rayU)
  - [V2RayXS](https://github.com/tzmax/V2RayXS)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [INCY](https://apps.apple.com/en/app/incy/id6756943388)
- Linux
  - [v2rayA](https://github.com/v2rayA/v2rayA)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [GorzRay](https://github.com/ketetefid/GorzRay)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [GenyConnect](https://github.com/genyleap/GenyConnect)
  - [OneXray](https://github.com/OneXray/OneXray)
- HarmonyOS
  - [Hey](https://github.com/popsiclelmlm/Hey)

## Others that support VLESS, XTLS, REALITY, XUDP, PLUX...

- iOS & macOS arm64 & tvOS
  - [Anywhere](https://github.com/NodePassProject/Anywhere)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Loon](https://apps.apple.com/us/app/loon/id1373567447)
  - [Egern](https://apps.apple.com/us/app/egern/id1616105820)
  - [Quantumult X](https://apps.apple.com/us/app/quantumult-x/id1443988620)
- Xray Tools
  - [xray-knife](https://github.com/lilendian0x00/xray-knife)
  - [xray-checker](https://github.com/kutovoys/xray-checker)
- Xray Wrapper
  - [XTLS/libXray](https://github.com/XTLS/libXray)
  - [xtls-sdk](https://github.com/remnawave/xtls-sdk)
  - [xtlsapi](https://github.com/hiddify/xtlsapi)
  - [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite)
  - [flutter_vless](https://github.com/XIIIFOX/flutter_vless)
  - [Xray-core-python](https://github.com/LorenEteval/Xray-core-python)
  - [xray-api](https://github.com/XVGuardian/xray-api)
- [XrayR](https://github.com/XrayR-project/XrayR)
  - [XrayR-release](https://github.com/XrayR-project/XrayR-release)
  - [XrayR-V2Board](https://github.com/missuo/XrayR-V2Board)
- Cores
  - [Amnezia VPN](https://github.com/amnezia-vpn)
  - [mihomo](https://github.com/MetaCubeX/mihomo)
  - [sing-box](https://github.com/SagerNet/sing-box)

## Contributing

[Code of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/XTLS/Xray-core)

## Credits

- [Xray-core v1.0.0](https://github.com/XTLS/Xray-core/releases/tag/v1.0.0) was forked from [v2fly-core 9a03cc5](https://github.com/v2fly/v2ray-core/commit/9a03cc5c98d04cc28320fcee26dbc236b3291256), and we have made & accumulated a huge number of enhancements over time, check [the release notes for each version](https://github.com/XTLS/Xray-core/releases).
- For third-party projects used in [Xray-core](https://github.com/XTLS/Xray-core), check your local or [the latest go.mod](https://github.com/XTLS/Xray-core/blob/main/go.mod).

### Bundled Third-Party Components Redistribution

**Certain optional features dynamically load third-party components. These optional components are separate works distributed under their own licenses, and are bundled into the ZIP package for ease of use. Users may replace these components under the licenses from these components.**

These components include:

#### Wintun

This distribution contains unmodified official precompiled and pre-signed Wintun binaries.

- Project: Wintun
- Copyright: Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
- Redistribution License: Prebuilt Binaries License (PBL) bundled with official precompiled and pre-signed binaries from wintun.net
- Component(s): wintun.dll
- Source: https://www.wintun.net/
- Included in:
  - Windows x86 (windows-32, win7-32)
  - Windows x86-64 (windows-64, win7-64)
  - Windows AArch64 (windows-arm64)
- Notes: Wintun is an optional runtime-loaded component only used for TUN inbound functionality on supported Windows platforms.

## One-line Compilation

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Reproducible Releases

Make sure that you are using the same Go version, and remember to set the git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

For Android:

```bash
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=/path/to/aarch64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=/path/to/x86_64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
```

If you are compiling a 32-bit MIPS/MIPSLE target, use this command instead:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```
