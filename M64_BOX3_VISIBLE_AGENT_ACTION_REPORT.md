# M64 BOX-3 Visible Agent Action Report

Date: 2026-08-10  
Status: hardware adapter and development composition PASS; physical and production release gates pending

## Outcome

M64 completes the first visible device-action adapter in the combined XiaoZhi
voice and ESP-Claw Agent runtime. The action is not an arbitrary GPIO tool.
`VOICE_AGENT_KIT_BOX3` freezes one active-high status indicator on GPIO 47,
matching the ESP32-S3-BOX-3 display-backlight wiring used by the pinned XiaoZhi
board source. The ESP-Claw surface remains the exact typed
`device.set_indicator({"on": bool})` capability.

The product adapter resets and drives the backlight inactive before returning
from create, stores only a boolean state, and drives it inactive again before
releasing the GPIO. `device.get_status` now reports bounded
`indicator_available` and `indicator_on` fields without voice, prompt, session,
owner or credential content.

## Authorization boundary

The hardware callback runs only after all existing checks succeed:

1. the tool is in the closed native enum and the compiled SKU action allowlist;
2. the build-time feature gate exposes the separate action group;
3. ESP-Claw validates root-Agent caller, request/session and exact JSON;
4. the device registers an argument-bound owner-epoch challenge;
5. the trusted foreground App approves that exact on/off action;
6. the result is delivered once and consumed by a request/session/argument-bound grant;
7. cancellation and the atomic action commit are rechecked before GPIO mutation;
8. a metadata-only executed/denied/failure counter is recorded.

The callback accepts no GPIO number, URL, command, provider payload or dynamic
capability name. Voice text is never consent.

## Build policy

- `sdkconfig.live-runtime-compile.defaults` enables the action only in the
  non-routable `.example.invalid` development composition, ensuring the real
  adapter and complete consent chain compile together.
- `sdkconfig.production-security.defaults` explicitly disables it.
- `main/CMakeLists.txt` fails the build if production security and the action
  are enabled together.

This separation is intentional. The real adapter removes the former firmware
stub, but does not manufacture evidence for a signed App, managed account
service, live PostgreSQL, physical display behavior or market release.

## Implemented artifacts

- `components/product_status_indicator/`: product-owned GPIO lifecycle and
  bounded on/off adapter;
- `components/product_sku/`: BOX-3 indicator geometry plus closed action
  capability policy;
- `main/app_main.c`: SKU/build intersection, hardware callback and bounded
  status response;
- `main/Kconfig.projbuild`, development and production defaults, and CMake:
  explicit development enablement plus production fail-closed enforcement;
- `tools/verify_indicator_action_build.py`: final-ELF gate that requires the
  complete adapter in development and rejects every related symbol in
  production;
- host and policy tests for profile geometry, read/action separation, GPIO
  ownership and build gates;
- updated capability, action-consent, product-runtime and XiaoZhi integration
  runbooks.

## Build and regression evidence

The ESP-IDF 6.0.2 development gate records
`CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE=y` and finds all five required
symbols in the final ELF: the private action callback plus create, set, get and
destroy adapter entry points. Its application image is 1,417,088 bytes with
SHA-256
`4eb343c8476949fdf0be66d15eefa9bd66928b1c871990128cc44a8ec770c92f`.
The link-map budget remains 81,152/98,304 bytes IRAM and
121,392/358,144 bytes internal static memory, leaving 236,752 bytes of
headroom.

The production-security gate records the feature as explicitly not set and
finds no `product_agent_set_indicator` or `product_status_indicator_*` symbol
in the final ELF. Its unsigned, Secure-Boot-padded application input is
1,441,792 bytes with SHA-256
`a636234d9c35ac48ebd66e91f33dbb24c546f4589ff466625eabaa1515171884`.
Production-security input verification, ephemeral three-signature bootloader
and one-signature application flow, virtual eFuse rehearsal and synthetic
factory handoff gates pass. These remain untrusted test artifacts and are not
release signatures.

The complete regression passes 27 C host suites, 7 gateway-contract tests, 70
factory tests, 314 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and onboarding gates (25 scenarios), and all Go packages
plus vet. The TLS 1.3 factory tests were run with the pinned Python 3.11.15 /
OpenSSL 3.5.7 environment; the macOS system Python is not a qualifying TLS
runtime.

## Evidence boundary

No physical BOX-3 was connected. No GPIO waveform, display/backlight UX,
current draw, boot glitch, power-cut, prompt-injection soak, signed iOS/Android
App, production identity provider, managed account service, live PostgreSQL or
`MARKET_RELEASE_PASS` was produced. The action therefore remains prohibited in
production-security images.

The next valid step is board-side qualification with the foreground signed App
and live durable authorization stack, followed by independent release evidence.
