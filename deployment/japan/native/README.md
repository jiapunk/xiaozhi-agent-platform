# Low-memory native deployment

This profile is tailored to the current Japan VPS: one x86-64 vCPU, 1 GB RAM,
20 GB storage, and the public endpoint `116-206-93-12.sslip.io`. It runs the
Gateway as a restricted systemd service rather than keeping a Docker daemon in
memory. Caddy terminates HTTPS/WSS and FFmpeg is invoked only for a cloud voice
turn.

The initial public TLS, bootstrap, WebSocket, audio, and ESP-Claw MCP path was
qualified with the known human-voice loopback test. The current MVP profile uses
one owner-only OpenRouter key for transcription, DeepSeek Agent replies, and
speech synthesis. Setting `S3CAM_OPENROUTER_ENABLED=0` restores the built-in
loopback without changing the firmware.

The optional full-duplex profile sets `S3CAM_OPENAI_REALTIME_ENABLED=1` and
reads an OpenAI Platform key from
`/etc/xiaozhi-gateway/secrets/openai_api_key`. It keeps the existing
OpenRouter/DeepSeek pipeline as a fallback for non-Realtime turns and for
capabilities outside the live conversation. The default Realtime model is
`gpt-realtime-2.1-mini`, with low-eagerness semantic VAD so long commands are
not ended at the first short pause. Device-side AEC must be enabled in the
matching watch firmware before using this profile.

Safe Agent v1 adds bounded encrypted profile/preference memory and
confirmation-bound device tools. The systemd `StateDirectory` owns persistent
encrypted state; the encryption key remains in `/etc/xiaozhi-gateway/secrets`.
Voice cloning is an optional direct Model Studio integration because OpenRouter
does not manage voice enrollment. After a Singapore workspace key is installed,
set `S3CAM_VOICE_CLONE_ENABLED=1`; enrollment then requires ESP32 physical
approval plus a one-use six-digit code at `/voice`.

Required server paths:

- `/opt/xiaozhi-gateway/s3camdevgateway`
- `/opt/xiaozhi-glyphs/examples/glyph_push_server.py`
- `/opt/xiaozhi-glyphs/scripts/glyph_provider.py`
- `/opt/xiaozhi-glyphs/full/manifest.json` and its matching CBIN shards
- `/etc/xiaozhi-gateway/gateway.env`
- `/etc/xiaozhi-gateway/secrets/bootstrap_token`
- `/etc/xiaozhi-gateway/secrets/session_token`
- `/etc/xiaozhi-gateway/secrets/openrouter_api_key`
- `/etc/xiaozhi-gateway/secrets/openai_api_key` (only when Realtime is enabled)
- `/etc/xiaozhi-gateway/secrets/memory_key`
- `/var/lib/xiaozhi-gateway/agent-memory.enc` (created on first approved write)
- `/var/lib/xiaozhi-gateway/voice-profile.enc` (created after voice enrollment)
- `/etc/caddy/Caddyfile`
- `/etc/systemd/system/xiaozhi-gateway.service`
- `/etc/systemd/system/xiaozhi-glyph-provider.service`

The default `S3CAM_TEXT_LOCALE=zh-TW` normalizes ASR and Agent text before TTS.
Use `zh-HK` for Hong Kong Traditional Chinese or `zh-CN` for Mainland
Simplified Chinese. The glyph provider binds only to `127.0.0.1:8768` and
serves rare glyphs from the matching `noto-tc-v1` full bundle; the ESP32 keeps
the common 30 px font locally and never downloads the full bundle.

The Gateway listens only on `127.0.0.1:8766`. Caddy exposes the public Gateway
on HTTPS/WSS port `8443` and may use port `80` for certificate issuance and
renewal. Port `443` remains reserved for the separately managed Xray service.
The firmware public URLs must therefore include `:8443`.
