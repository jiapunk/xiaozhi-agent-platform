# Japan cloud Gateway prototype

This profile runs the product-owned ESP32 Gateway behind automatic HTTPS/WSS.
It sends speech recognition and synthesis to Alibaba Cloud Model Studio's
international endpoint and Agent requests to DeepSeek. Provider keys remain on
the server and are never returned to the ESP32.

## Recommended test host

- Japan/Tokyo region
- 2 vCPU, 2 GB RAM, 20 GB or larger SSD
- Ubuntu 24.04 LTS or Debian 12
- Attached static public IPv4 address
- Inbound TCP 22, 80, and 443; UDP 443 is optional for HTTP/3

The Gateway and FFmpeg use little compute because the AI models run at the
providers. A 1 GB host can work for one device, but 2 GB leaves enough room for
container builds, TLS, logs, and short audio conversion bursts.

## Configure

1. Install Docker Engine with the Compose plugin on the server.
2. Attach a static IPv4 address to the server. A dynamic address is unsuitable
   because both the endpoint and certificate validation depend on it remaining
   unchanged.
3. Copy `.env.example` to `.env`, then set the ACME email and device MAC
   address. If there is no purchased domain, convert the static IP to an
   sslip.io name: IP `203.0.113.10` becomes
   `GATEWAY_DOMAIN=203-0-113-10.sslip.io`. sslip.io resolves an embedded IP
   automatically, so no DNS account or record is required. If the Model Studio
   console shows a Singapore Workspace ID, also set its two recommended
   workspace-specific endpoints.
4. Confirm the chosen hostname resolves to the static server IP, then create
   these three files with no trailing spaces:
   - `secrets/deepseek_api_key`
   - `secrets/dashscope_api_key`
   - `secrets/bootstrap_token`
5. Generate the bootstrap token with `openssl rand -hex 32`. Keep the same
   value for the prototype firmware build, and set every secret file to mode
   `0600`.
6. Start the services with `docker compose up -d --build`.
7. Verify `https://your-ip.sslip.io/healthz` returns an OK JSON response.

The firmware must then use
`https://your-ip.sslip.io/xiaozhi/ota/`, disable the insecure Gateway option, and
contain the matching prototype bootstrap token. This compiled shared token is
only a one-device testing bridge; factory devices need unique credentials in
protected provisioning rather than a shared token in firmware.

## Data path

The Tokyo server terminates device TLS/WSS and validates the device. Audio is
then sent to the configured international speech service, and the transcript
is sent to DeepSeek for a short reply. This Gateway does not intentionally
persist transcript or reply content. Container logs record operational errors
and request metadata, not provider keys.

For a commercial launch, add per-device identity, database-backed ownership,
rate limits, usage budgets, monitoring, provider failover, and a separately
qualified mainland-China deployment rather than relying on cross-border access
to the Japan node.

The sslip.io endpoint removes the need to buy or configure a domain and is
appropriate for this physical-device prototype. It introduces dependency on a
public third-party DNS service, so replace it with a product-owned domain before
commercial launch. A literal-IP URL is also possible with a public IP-address
certificate, but those certificates are short-lived and need a separate,
reliable renewal and web-server reload process.
