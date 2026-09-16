#include "agent_bridge.h"
#include "device_voice_runtime.h"
#include "device_voice_client.h"
#include "device_websocket_transport.h"
#include "esp_claw_runtime.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "product_agent_memory.h"
#include "product_agent_observability.h"
#include "product_factory_reset.h"
#include "product_wifi.h"
#include "product_provisioning.h"
#include "product_storage.h"
#include "product_sku.h"
#include "product_ota.h"
#include "product_ota_client.h"
#include "voice_agent_controller.h"
#include "xiaozhi_agent_adapter.h"
#include <stdio.h>
#if CONFIG_PRODUCT_BOARD_BREAD_COMPACT_WIFI_S3CAM
#include "bread_s3cam_bringup.h"
#endif
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3
#include "box3_bringup.h"
#include "agent_control_plane_client.h"
#include "agent_device_identity.h"
#include "box3_agent_credentials_client.h"
#include "box3_agent_supervisor.h"
#include "box3_agent_supervisor_product_wifi.h"
#include "box3_agent_voice.h"
#include "box3_audio.h"
#include "box3_product_runtime.h"
#include "box3_product_runtime_core.h"
#include "box3_voice_audio.h"
#if CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE && \
    CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
#include "product_status_indicator.h"
#endif
#if CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE
#include "esp_mac.h"
#include "esp_random.h"
#endif
#endif
#include "voice_audio_protocol.h"
#include "voice_audio_session.h"

static const char *TAG = "agent_platform";
static product_agent_memory_handle_t s_agent_memory;
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3 && CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE
#ifdef CONFIG_PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH
#define PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH_VALUE true
#else
#define PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH_VALUE false
#endif
static box3_product_runtime_handle_t s_product_runtime;
static product_agent_observability_t s_agent_observability;
#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
static product_status_indicator_handle_t s_status_indicator;
#endif
static char s_device_id[BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES];
static char s_client_id[BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES];

static uint32_t product_agent_capabilities_for_sku(void)
{
    const product_sku_profile_t *profile =
        product_sku_get_compiled_profile();
    uint32_t capabilities = 0;
    if (product_sku_capability_allowed(
            profile, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS, false)) {
        capabilities |= ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS;
    }
#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
    if (product_sku_capability_allowed(
            profile, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, true)) {
        capabilities |= ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR;
    }
#endif
    return capabilities;
}

#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
static esp_err_t product_agent_set_indicator(void *ctx, bool on)
{
    (void)ctx;
    return product_status_indicator_set(s_status_indicator, on);
}
#endif

static esp_err_t product_agent_get_status_json(
    void *ctx,
    char *output,
    size_t output_size)
{
    (void)ctx;
    if (!s_product_runtime || !output || output_size == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    box3_product_runtime_stats_t stats = {0};
    esp_err_t error = box3_product_runtime_get_stats(
        s_product_runtime, &stats);
    if (error != ESP_OK) {
        return error;
    }
    const bool online =
        stats.state == BOX3_PRODUCT_RUNTIME_ONLINE;
    bool indicator_on = false;
#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
    const bool indicator_available = s_status_indicator != NULL;
    if (indicator_available) {
        error = product_status_indicator_get(s_status_indicator,
                                             &indicator_on);
        if (error != ESP_OK) {
            return error;
        }
    }
#else
    const bool indicator_available = false;
#endif
    const int written = snprintf(
        output, output_size,
        "{\"online\":%s,\"state\":%d,\"indicator_available\":%s,"
        "\"indicator_on\":%s}",
        online ? "true" : "false", (int)stats.state,
        indicator_available ? "true" : "false",
        indicator_on ? "true" : "false");
    return written >= 0 && (size_t)written < output_size
               ? ESP_OK
               : ESP_ERR_INVALID_SIZE;
}

static void product_runtime_event(
    void *ctx,
    const box3_product_runtime_event_t *event)
{
    (void)ctx;
    if (!event) {
        return;
    }
    if (event->type == BOX3_PRODUCT_RUNTIME_EVENT_STATE_CHANGED) {
        ESP_LOGI(TAG, "Product runtime state=%d network=%s onboarding=%s",
                 (int)event->state,
                 event->network_available ? "online" : "offline",
                 event->onboarding_required ? "required" : "not-required");
    } else if (event->type == BOX3_PRODUCT_RUNTIME_EVENT_ERROR) {
        ESP_LOGE(TAG, "Product runtime error: %s",
                 esp_err_to_name(event->error));
    } else if (event->type == BOX3_PRODUCT_RUNTIME_EVENT_LOCAL_ACTION) {
        ESP_LOGI(TAG, "Physical input event=%d armed=%s held_ms=%u result=%s",
                 (int)event->local_action_event,
                 event->local_action_armed ? "yes" : "no",
                 (unsigned)event->local_action_held_ms,
                 esp_err_to_name(event->error));
    }
}

static esp_err_t start_product_runtime(void)
{
    esp_err_t error = ESP_OK;
    if (!product_agent_observability_init(&s_agent_observability)) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t base_mac[6] = {0};
    uint8_t boot_random[8] = {0};
    error = esp_read_mac(base_mac, ESP_MAC_BASE);
    if (error != ESP_OK ||
        !box3_product_runtime_format_device_id(base_mac, s_device_id)) {
        return error == ESP_OK ? ESP_ERR_INVALID_STATE : error;
    }
    esp_fill_random(boot_random, sizeof(boot_random));
    if (!box3_product_runtime_format_client_id(boot_random, s_client_id)) {
        return ESP_ERR_INVALID_STATE;
    }
    const char *sntp_servers[PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT] = {
        CONFIG_PRODUCT_SNTP_SERVER_1,
    };
    size_t sntp_server_count = 1;
    if (CONFIG_PRODUCT_SNTP_SERVER_2[0]) {
        sntp_servers[sntp_server_count++] = CONFIG_PRODUCT_SNTP_SERVER_2;
    }
    if (CONFIG_PRODUCT_SNTP_SERVER_3[0]) {
        sntp_servers[sntp_server_count++] = CONFIG_PRODUCT_SNTP_SERVER_3;
    }

#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
    error = product_status_indicator_create(
        product_sku_get_compiled_profile(), &s_status_indicator);
    if (error != ESP_OK) {
        return error;
    }
#endif

    const box3_product_runtime_config_t config = {
        .device_id = s_device_id,
        .client_id = s_client_id,
        .hostname = s_device_id,
        .identity_hmac_key_id = CONFIG_PRODUCT_IDENTITY_HMAC_KEY_ID,
        .control_authority = CONFIG_PRODUCT_CONTROL_AUTHORITY,
        .control_use_crt_bundle = true,
        .control_network_timeout_ms = 10000,
        .action_consent_timeout_ms = 20000,
        .action_consent_poll_interval_ms = 500,
        .agent_proxy_authority = CONFIG_PRODUCT_AGENT_PROXY_AUTHORITY,
        .sntp_servers = {
            sntp_servers[0], sntp_servers[1], sntp_servers[2],
        },
        .sntp_server_count = sntp_server_count,
        .sntp_sync_timeout_ms = 10000,
        .onboarding_button_gpio = CONFIG_PRODUCT_ONBOARDING_BUTTON_GPIO,
        .onboarding_button_active_high =
            PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH_VALUE,
        .onboarding_button_sample_period_ms =
            CONFIG_PRODUCT_ONBOARDING_BUTTON_SAMPLE_PERIOD_MS,
        .onboarding_button_debounce_ms =
            CONFIG_PRODUCT_ONBOARDING_BUTTON_DEBOUNCE_MS,
        .onboarding_button_long_press_ms =
            CONFIG_PRODUCT_ONBOARDING_BUTTON_LONG_PRESS_MS,
        .onboarding_button_factory_reset_press_ms =
            CONFIG_PRODUCT_FACTORY_RESET_PRESS_MS,
        .product = {
            .websocket = {
                .protocol_version = CONFIG_PRODUCT_VOICE_PROTOCOL_VERSION,
                .use_crt_bundle = true,
                .network_timeout_ms = 10000,
                .send_timeout_ms = 1000,
                .ping_interval_seconds = 30,
                .pong_timeout_seconds = 15,
            },
            .agent = {
                .backend_type = "openai-compatible",
                .model = CONFIG_PRODUCT_AGENT_MODEL,
                .auth_type = "bearer",
                .max_tokens_field = "max_completion_tokens",
                .system_prompt = CONFIG_PRODUCT_AGENT_SYSTEM_PROMPT,
                .timeout_ms = 35000,
                .max_tokens = 1024,
                .max_tool_iterations = 4,
                .enabled_capabilities =
                    product_agent_capabilities_for_sku(),
                .device_ops = {
                    .get_status_json = product_agent_get_status_json,
#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
                    .set_indicator = product_agent_set_indicator,
#endif
                },
                /* Never log input/output JSON, memory values, or text. */
                .capability_audit = product_agent_observability_record,
                .capability_audit_ctx = &s_agent_observability,
                .memory = s_agent_memory,
            },
            .output_volume_percent = CONFIG_PRODUCT_OUTPUT_VOLUME_PERCENT,
            .hello_timeout_ms = 5000,
        },
        .event = product_runtime_event,
    };
    error = box3_product_runtime_start(&config, &s_product_runtime);
#if CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE
    if (error != ESP_OK && !s_product_runtime && s_status_indicator) {
        (void)product_status_indicator_destroy(s_status_indicator);
        s_status_indicator = NULL;
    }
#endif
    return error;
}
#endif

static void verify_static_linkage(void)
{
    /*
     * This intentionally invalid call stops at the wrapper's argument guard.
     * It creates no tasks and performs no network I/O, but keeps the complete
     * Agent startup and voice-protocol dependency closures in the image for
     * conservative link/size checks.
     */
    esp_err_t runtime_probe = esp_claw_runtime_start(NULL, NULL);
    agent_bridge_result_t bridge_probe = agent_bridge_init(NULL, NULL, NULL);
    agent_bridge_result_t controller_probe =
        voice_agent_controller_init(NULL, NULL);
    agent_bridge_result_t agent_final_probe =
        voice_agent_controller_on_agent_final(NULL, 1, "probe");
    agent_bridge_result_t agent_error_probe =
        voice_agent_controller_on_agent_error(NULL, 1);
    agent_bridge_result_t interrupt_probe = voice_agent_controller_interrupt(
        NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    agent_bridge_state_t state_probe = voice_agent_controller_state(NULL);
    uint32_t request_id_probe =
        voice_agent_controller_active_request_id(NULL);
    agent_bridge_result_t client_hello_probe =
        xiaozhi_agent_adapter_add_client_hello_feature(NULL);
    agent_bridge_result_t server_hello_probe =
        xiaozhi_agent_adapter_validate_server_hello(NULL);
    agent_bridge_result_t xiaozhi_probe =
        xiaozhi_agent_adapter_handle_json(NULL, NULL, NULL, NULL);
    agent_bridge_result_t device_runtime_init_probe =
        device_voice_runtime_init(NULL, NULL);
    agent_bridge_result_t device_runtime_client_hello_probe =
        device_voice_runtime_add_client_hello(NULL, NULL);
    agent_bridge_result_t device_runtime_server_hello_probe =
        device_voice_runtime_accept_server_hello(NULL, NULL);
    agent_bridge_result_t device_runtime_json_probe =
        device_voice_runtime_on_json(NULL, NULL, NULL);
    agent_bridge_result_t device_runtime_binary_probe =
        device_voice_runtime_on_binary(NULL, NULL, 0);
    agent_bridge_result_t device_runtime_final_probe =
        device_voice_runtime_on_agent_final(NULL, 1, "probe");
    agent_bridge_result_t device_runtime_error_probe =
        device_voice_runtime_on_agent_error(NULL, 1);
    agent_bridge_result_t device_runtime_interrupt_probe =
        device_voice_runtime_interrupt(
            NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    agent_bridge_result_t device_runtime_disconnect_probe =
        device_voice_runtime_on_disconnected(NULL);
    bool device_runtime_ready_probe = device_voice_runtime_ready(NULL);
    const char *device_runtime_session_probe =
        device_voice_runtime_session_id(NULL);
    uint8_t opus_probe[] = {0};
    esp_err_t websocket_create_probe =
        device_websocket_transport_create(NULL, NULL);
    esp_err_t websocket_start_probe =
        device_websocket_transport_start(NULL);
    esp_err_t websocket_close_probe =
        device_websocket_transport_close(NULL, 1);
    bool websocket_connected_probe =
        device_websocket_transport_connected(NULL);
    esp_err_t websocket_text_probe =
        device_websocket_transport_send_text(NULL, "probe", 5);
    esp_err_t websocket_binary_probe =
        device_websocket_transport_send_binary(NULL, opus_probe,
                                               sizeof(opus_probe));
    esp_err_t websocket_stats_probe =
        device_websocket_transport_get_stats(NULL, NULL);
    esp_err_t websocket_destroy_probe =
        device_websocket_transport_destroy(NULL);
    esp_err_t voice_client_create_probe =
        device_voice_client_create(NULL, NULL);
    esp_err_t voice_client_start_probe = device_voice_client_start(NULL);
    esp_err_t voice_client_final_probe =
        device_voice_client_on_agent_final(NULL, 1, "probe");
    esp_err_t voice_client_error_probe =
        device_voice_client_on_agent_error(NULL, 1);
    esp_err_t voice_client_interrupt_probe = device_voice_client_interrupt(
        NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    int voice_client_audio_probe =
        device_voice_client_send_audio(NULL, opus_probe, sizeof(opus_probe));
    bool voice_client_ready_probe = device_voice_client_ready(NULL);
    esp_err_t voice_client_stats_probe =
        device_voice_client_get_stats(NULL, NULL);
    esp_err_t voice_client_destroy_probe = device_voice_client_destroy(NULL);
    uint8_t wire_probe[32];
    size_t wire_size_probe = 0;
    voice_audio_packet_view_t packet_view_probe;
    voice_audio_protocol_result_t audio_encode_probe =
        voice_audio_protocol_encode(1, opus_probe, sizeof(opus_probe), 0,
                                    wire_probe, sizeof(wire_probe),
                                    &wire_size_probe);
    voice_audio_protocol_result_t audio_decode_probe =
        voice_audio_protocol_decode(1, wire_probe, wire_size_probe,
                                    &packet_view_probe);
    voice_audio_session_result_t audio_session_probe =
        voice_audio_session_init(NULL);
    voice_audio_token_t audio_token_probe = {0};
    voice_audio_session_result_t audio_admit_probe =
        voice_audio_session_admit(NULL, &audio_token_probe);
    voice_audio_session_result_t audio_begin_probe =
        voice_audio_session_begin(NULL, 1);
    voice_audio_session_result_t audio_inflight_probe =
        voice_audio_session_set_inflight(NULL, audio_token_probe, false);
    voice_audio_session_result_t audio_drain_probe =
        voice_audio_session_drain(NULL, 1);
    voice_audio_session_result_t audio_flush_probe =
        voice_audio_session_flush(NULL, 1);
    voice_audio_session_result_t audio_finish_probe =
        voice_audio_session_finish_drain(NULL, true, NULL);
    bool audio_current_probe =
        voice_audio_session_is_current(NULL, audio_token_probe);
    product_wifi_handle_t product_wifi_handle_probe = NULL;
    product_wifi_stats_t product_wifi_stats_probe;
    esp_err_t product_wifi_create_probe =
        product_wifi_create(NULL, &product_wifi_handle_probe);
    esp_err_t product_wifi_start_probe = product_wifi_start(NULL);
    esp_err_t product_wifi_onboarding_probe =
        product_wifi_begin_onboarding(NULL);
    esp_err_t product_wifi_softap_probe =
        product_wifi_start_onboarding_softap(NULL, NULL);
    esp_err_t product_wifi_submit_probe =
        product_wifi_submit_credentials(NULL, "probe", "password");
    esp_err_t product_wifi_clear_probe =
        product_wifi_clear_credentials(NULL);
    esp_err_t product_wifi_finish_probe =
        product_wifi_finish_onboarding(NULL);
    esp_err_t product_wifi_stats_result_probe =
        product_wifi_get_stats(NULL, &product_wifi_stats_probe);
    esp_err_t product_wifi_stop_probe = product_wifi_stop(NULL, 100);
    product_provisioning_handle_t provisioning_handle_probe = NULL;
    product_provisioning_stats_t provisioning_stats_probe;
    esp_err_t provisioning_create_probe =
        product_provisioning_create(NULL, &provisioning_handle_probe);
    esp_err_t provisioning_open_probe = product_provisioning_open(NULL);
    esp_err_t provisioning_close_probe = product_provisioning_close(NULL);
    esp_err_t provisioning_stats_result_probe =
        product_provisioning_get_stats(NULL, &provisioning_stats_probe);
    esp_err_t provisioning_destroy_probe =
        product_provisioning_destroy(NULL, 100);
    esp_err_t storage_status_probe = product_storage_get_status(NULL);
    bool storage_invalid_identity_probe =
        product_storage_identity_hmac_key_allowed(6);
    product_agent_memory_stats_t agent_memory_stats_probe;
    esp_err_t agent_memory_stats_result_probe =
        product_agent_memory_get_stats(NULL, &agent_memory_stats_probe);
    esp_err_t agent_memory_clear_probe = product_agent_memory_clear(NULL);
    esp_err_t agent_memory_close_probe = product_agent_memory_close(NULL);
    esp_err_t ota_check_probe =
        product_ota_check_manifest(NULL, NULL, 0, NULL);
    esp_err_t ota_install_probe =
        product_ota_install(NULL, NULL, 0, NULL);
    esp_err_t ota_status_probe = product_ota_get_boot_status(NULL);
    uint32_t ota_health_probe = product_ota_required_health_checks();
    product_ota_client_handle_t ota_client_handle_probe = NULL;
    product_ota_offer_t ota_offer_probe = {0};
    esp_err_t ota_client_create_probe =
        product_ota_client_create(NULL, &ota_client_handle_probe);
    esp_err_t ota_client_fetch_probe =
        product_ota_client_fetch_offer(NULL, NULL, &ota_offer_probe);
    product_ota_client_clear_offer(&ota_offer_probe);
    esp_err_t ota_client_destroy_probe = product_ota_client_destroy(NULL);
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3
    box3_agent_supervisor_product_wifi_event(NULL, NULL);
    esp_err_t board_audio_probe = box3_audio_validate_profile();
    esp_err_t board_audio_create_probe = box3_audio_create(NULL);
    esp_err_t board_audio_input_probe =
        box3_audio_enable_input(NULL, false);
    esp_err_t board_audio_output_probe =
        box3_audio_enable_output(NULL, false);
    esp_err_t board_audio_volume_probe =
        box3_audio_set_output_volume(NULL, 0);
    esp_err_t board_audio_read_probe = box3_audio_read(NULL, NULL, 0, NULL);
    esp_err_t board_audio_write_probe = box3_audio_write(NULL, NULL, 0, NULL);
    box3_audio_destroy(NULL);
    esp_err_t voice_audio_create_probe = box3_voice_audio_create(NULL, NULL);
    esp_err_t voice_audio_capture_probe = box3_voice_audio_start_capture(NULL);
    esp_err_t voice_audio_stop_probe = box3_voice_audio_stop_capture(NULL);
    esp_err_t voice_audio_push_probe =
        box3_voice_audio_push_binary(NULL, NULL, 0);
    esp_err_t voice_audio_stats_probe = box3_voice_audio_get_stats(NULL, NULL);
    box3_voice_audio_playback_event(NULL, VOICE_AGENT_PLAYBACK_FLUSH, 1);
    esp_err_t voice_audio_destroy_probe = box3_voice_audio_destroy(NULL);
    esp_err_t box3_product_create_probe =
        box3_agent_voice_create(NULL, NULL);
    esp_err_t box3_product_start_probe = box3_agent_voice_start(NULL);
    esp_err_t box3_product_interrupt_probe = box3_agent_voice_interrupt(
        NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    bool box3_product_ready_probe = box3_agent_voice_ready(NULL);
    esp_err_t box3_product_stats_probe =
        box3_agent_voice_get_stats(NULL, NULL);
    esp_err_t box3_product_stop_probe = box3_agent_voice_stop(NULL, 100);
    esp_err_t box3_supervisor_create_probe =
        box3_agent_supervisor_create(NULL, NULL);
    esp_err_t box3_supervisor_start_probe =
        box3_agent_supervisor_start(NULL);
    esp_err_t box3_supervisor_network_probe =
        box3_agent_supervisor_set_network_available(NULL, false);
    esp_err_t box3_supervisor_interrupt_probe =
        box3_agent_supervisor_interrupt(
            NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    esp_err_t box3_supervisor_stats_probe =
        box3_agent_supervisor_get_stats(NULL, NULL);
    esp_err_t box3_supervisor_stop_probe =
        box3_agent_supervisor_stop(NULL, 100);
    esp_err_t credentials_client_create_probe =
        box3_agent_credentials_client_create(NULL, NULL);
    esp_err_t credentials_client_refresh_probe =
        box3_agent_credentials_client_refresh(NULL, NULL);
    esp_err_t credentials_client_destroy_probe =
        box3_agent_credentials_client_destroy(NULL);
    esp_err_t identity_create_probe =
        agent_device_identity_create(NULL, NULL);
    uint8_t identity_signature_probe[32];
    esp_err_t identity_sign_probe = agent_device_identity_sign_proof(
        NULL, opus_probe, sizeof(opus_probe), identity_signature_probe);
    esp_err_t identity_agent_sign_probe =
        agent_device_identity_sign_agent_token_proof(
            NULL, opus_probe, sizeof(opus_probe),
            identity_signature_probe);
    esp_err_t identity_ota_sign_probe =
        agent_device_identity_sign_ota_offer_proof(
            NULL, opus_probe, sizeof(opus_probe),
            identity_signature_probe);
    esp_err_t identity_claim_sign_probe =
        agent_device_identity_sign_device_claim_proof(
            NULL, opus_probe, sizeof(opus_probe),
            identity_signature_probe);
    esp_err_t identity_action_challenge_sign_probe =
        agent_device_identity_sign_action_consent_challenge_proof(
            NULL, opus_probe, sizeof(opus_probe),
            identity_signature_probe);
    esp_err_t identity_action_result_sign_probe =
        agent_device_identity_sign_action_consent_result_proof(
            NULL, opus_probe, sizeof(opus_probe),
            identity_signature_probe);
    esp_err_t identity_onboarding_key_probe =
        agent_device_identity_derive_onboarding_ap_key(
            NULL, "XA-000000", identity_signature_probe);
    esp_err_t identity_time_accept_probe =
        agent_device_identity_accept_authenticated_time(NULL, 1800000000);
    esp_err_t identity_time_callback_probe =
        agent_device_identity_accept_authenticated_time_callback(
            NULL, 1800000000);
    int64_t identity_time_probe = 0;
    esp_err_t identity_time_get_probe =
        agent_device_identity_get_unix_time(NULL, &identity_time_probe);
    agent_device_identity_status_t identity_status_probe;
    esp_err_t identity_status_result_probe =
        agent_device_identity_get_status(NULL, &identity_status_probe);
    esp_err_t identity_destroy_probe =
        agent_device_identity_destroy(NULL);
    esp_err_t control_client_create_probe =
        agent_control_plane_client_create(NULL, NULL);
    esp_err_t control_client_sync_probe =
        agent_control_plane_client_sync_time(NULL);
    int64_t control_time_probe = 0;
    esp_err_t control_client_time_probe =
        agent_control_plane_client_get_or_sync_unix_time(
            NULL, &control_time_probe);
    char control_agent_token_probe[32];
    uint32_t control_agent_ttl_probe = 0;
    char control_binding_id_probe[23];
    uint64_t control_binding_revision_probe = 0;
    esp_err_t control_client_agent_probe =
        agent_control_plane_client_refresh_agent_token(
            NULL, control_agent_token_probe,
            sizeof(control_agent_token_probe),
            &control_agent_ttl_probe,
            control_binding_id_probe, sizeof(control_binding_id_probe),
            &control_binding_revision_probe);
    esp_err_t control_client_claim_probe =
        agent_control_plane_client_confirm_device_claim(NULL, NULL);
    agent_control_plane_action_consent_t action_consent_probe = {0};
    agent_control_plane_action_decision_t action_decision_probe =
        AGENT_CONTROL_PLANE_ACTION_PENDING;
    esp_err_t control_client_action_register_probe =
        agent_control_plane_client_register_action_consent(
            NULL, "probe", 1, true, 1800000020,
            &action_consent_probe);
    esp_err_t control_client_action_poll_probe =
        agent_control_plane_client_poll_action_consent(
            NULL, &action_consent_probe, &action_decision_probe);
    esp_err_t control_client_destroy_probe =
        agent_control_plane_client_destroy(NULL);
    box3_product_runtime_handle_t product_runtime_handle_probe = NULL;
    box3_product_runtime_stats_t product_runtime_stats_probe;
    esp_err_t product_runtime_start_probe =
        box3_product_runtime_start(NULL, &product_runtime_handle_probe);
    esp_err_t product_runtime_onboarding_probe =
        box3_product_runtime_open_onboarding(NULL);
    esp_err_t product_runtime_close_probe =
        box3_product_runtime_close_onboarding(NULL);
    esp_err_t product_runtime_interrupt_probe =
        box3_product_runtime_interrupt(
            NULL, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    esp_err_t product_runtime_stats_result_probe =
        box3_product_runtime_get_stats(NULL, &product_runtime_stats_probe);
    esp_err_t product_runtime_stop_probe =
        box3_product_runtime_stop(NULL, 100);
#endif

    if (runtime_probe != ESP_ERR_INVALID_ARG ||
        bridge_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        controller_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        agent_final_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        agent_error_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        interrupt_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        state_probe != AGENT_BRIDGE_STATE_IDLE || request_id_probe != 0 ||
        client_hello_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        server_hello_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        xiaozhi_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_init_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_client_hello_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_server_hello_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_json_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_binary_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_final_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_error_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_interrupt_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_disconnect_probe != AGENT_BRIDGE_ERR_INVALID_ARG ||
        device_runtime_ready_probe || device_runtime_session_probe[0] != '\0' ||
        websocket_create_probe != ESP_ERR_INVALID_ARG ||
        websocket_start_probe != ESP_ERR_INVALID_ARG ||
        websocket_close_probe != ESP_ERR_INVALID_ARG ||
        websocket_connected_probe ||
        websocket_text_probe != ESP_ERR_INVALID_ARG ||
        websocket_binary_probe != ESP_ERR_INVALID_ARG ||
        websocket_stats_probe != ESP_ERR_INVALID_ARG ||
        websocket_destroy_probe != ESP_OK ||
        voice_client_create_probe != ESP_ERR_INVALID_ARG ||
        voice_client_start_probe != ESP_ERR_INVALID_ARG ||
        voice_client_final_probe != ESP_ERR_INVALID_ARG ||
        voice_client_error_probe != ESP_ERR_INVALID_ARG ||
        voice_client_interrupt_probe != ESP_ERR_INVALID_ARG ||
        voice_client_audio_probe != -1 || voice_client_ready_probe ||
        voice_client_stats_probe != ESP_ERR_INVALID_ARG ||
        voice_client_destroy_probe != ESP_OK ||
        audio_encode_probe != VOICE_AUDIO_PROTOCOL_OK ||
        audio_decode_probe != VOICE_AUDIO_PROTOCOL_OK ||
        packet_view_probe.opus_size != sizeof(opus_probe) ||
        audio_session_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_admit_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_begin_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_inflight_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_drain_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_flush_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_finish_probe != VOICE_AUDIO_SESSION_ERR_INVALID_ARG ||
        audio_current_probe ||
        product_wifi_create_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_start_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_onboarding_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_softap_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_submit_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_clear_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_finish_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_stats_result_probe != ESP_ERR_INVALID_ARG ||
        product_wifi_stop_probe != ESP_ERR_INVALID_ARG ||
        provisioning_create_probe != ESP_ERR_INVALID_ARG ||
        provisioning_open_probe != ESP_ERR_INVALID_ARG ||
        provisioning_close_probe != ESP_ERR_INVALID_ARG ||
        provisioning_stats_result_probe != ESP_ERR_INVALID_ARG ||
        provisioning_destroy_probe != ESP_ERR_INVALID_ARG ||
        storage_status_probe != ESP_ERR_INVALID_ARG ||
        storage_invalid_identity_probe ||
        agent_memory_stats_result_probe != ESP_ERR_INVALID_ARG ||
        agent_memory_clear_probe != ESP_ERR_INVALID_ARG ||
        agent_memory_close_probe != ESP_ERR_INVALID_ARG ||
        ota_check_probe != ESP_ERR_INVALID_ARG ||
        ota_install_probe != ESP_ERR_INVALID_ARG ||
        ota_status_probe != ESP_ERR_INVALID_ARG || ota_health_probe == 0 ||
        ota_client_create_probe != ESP_ERR_INVALID_ARG ||
        ota_client_fetch_probe != ESP_ERR_INVALID_ARG ||
        ota_client_destroy_probe != ESP_OK
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3
        || board_audio_probe != ESP_OK ||
        board_audio_create_probe != ESP_ERR_INVALID_ARG ||
        board_audio_input_probe != ESP_ERR_INVALID_ARG ||
        board_audio_output_probe != ESP_ERR_INVALID_ARG ||
        board_audio_volume_probe != ESP_ERR_INVALID_ARG ||
        board_audio_read_probe != ESP_ERR_INVALID_ARG ||
        board_audio_write_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_create_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_capture_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_stop_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_push_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_stats_probe != ESP_ERR_INVALID_ARG ||
        voice_audio_destroy_probe != ESP_OK ||
        box3_product_create_probe != ESP_ERR_INVALID_ARG ||
        box3_product_start_probe != ESP_ERR_INVALID_ARG ||
        box3_product_interrupt_probe != ESP_ERR_INVALID_STATE ||
        box3_product_ready_probe ||
        box3_product_stats_probe != ESP_ERR_INVALID_ARG ||
        box3_product_stop_probe != ESP_OK ||
        box3_supervisor_create_probe != ESP_ERR_INVALID_ARG ||
        box3_supervisor_start_probe != ESP_ERR_INVALID_ARG ||
        box3_supervisor_network_probe != ESP_ERR_INVALID_STATE ||
        box3_supervisor_interrupt_probe != ESP_ERR_INVALID_STATE ||
        box3_supervisor_stats_probe != ESP_ERR_INVALID_ARG ||
        box3_supervisor_stop_probe != ESP_OK ||
        credentials_client_create_probe != ESP_ERR_INVALID_ARG ||
        credentials_client_refresh_probe != ESP_ERR_INVALID_ARG ||
        credentials_client_destroy_probe != ESP_OK ||
        identity_create_probe != ESP_ERR_INVALID_ARG ||
        identity_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_agent_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_ota_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_claim_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_action_challenge_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_action_result_sign_probe != ESP_ERR_INVALID_ARG ||
        identity_onboarding_key_probe != ESP_ERR_INVALID_ARG ||
        identity_time_accept_probe != ESP_ERR_INVALID_ARG ||
        identity_time_callback_probe != ESP_ERR_INVALID_ARG ||
        identity_time_get_probe != ESP_ERR_INVALID_ARG ||
        identity_status_result_probe != ESP_ERR_INVALID_ARG ||
        identity_destroy_probe != ESP_OK ||
        control_client_create_probe != ESP_ERR_INVALID_ARG ||
        control_client_sync_probe != ESP_ERR_INVALID_ARG ||
        control_client_time_probe != ESP_ERR_INVALID_ARG ||
        control_client_agent_probe != ESP_ERR_INVALID_ARG ||
        control_client_claim_probe != ESP_ERR_INVALID_ARG ||
        control_client_action_register_probe != ESP_ERR_INVALID_ARG ||
        control_client_action_poll_probe != ESP_ERR_INVALID_ARG ||
        control_client_destroy_probe != ESP_OK ||
        product_runtime_start_probe != ESP_ERR_INVALID_ARG ||
        product_runtime_onboarding_probe != ESP_ERR_INVALID_STATE ||
        product_runtime_close_probe != ESP_ERR_INVALID_STATE ||
        product_runtime_interrupt_probe != ESP_ERR_INVALID_STATE ||
        product_runtime_stats_result_probe != ESP_ERR_INVALID_ARG ||
        product_runtime_stop_probe != ESP_OK
#endif
    ) {
        ESP_LOGE(TAG, "Static linkage probe failed");
        return;
    }
    ESP_LOGI(TAG,
             "Agent runtime, device voice runtime, XiaoZhi adapter, controller, "
             "bridge, serialized voice client, WSS transport, and audio "
             "protocol plus product storage, signed A/B OTA, Wi-Fi, and "
             "secure provisioning, bounded Agent memory, plus authenticated fleet OTA offer "
             "linkage verified");
}

void app_main(void)
{
    ESP_LOGI(TAG, "Product-owned Agent platform shell booted");
    const product_sku_profile_t *sku = product_sku_get_compiled_profile();
    product_sku_validation_result_t sku_detail =
        PRODUCT_SKU_VALIDATION_INVALID_PROFILE;
    const esp_err_t sku_error = product_sku_validate_hardware(&sku_detail);
    if (!sku || sku_error != ESP_OK) {
        ESP_LOGE(TAG, "Product SKU hardware geometry failed closed: %s (%s)",
                 esp_err_to_name(sku_error),
                 product_sku_validation_result_name(sku_detail));
        return;
    }
    ESP_LOGI(TAG,
             "Product SKU=%s board-contract=%s revision=%u; readable silicon "
             "and memory geometry verified",
             sku->sku, sku->board,
             (unsigned)sku->product_hardware_revision);
    const esp_err_t storage_error = product_storage_initialize();
    if (storage_error != ESP_OK) {
        ESP_LOGE(TAG, "Product storage failed closed: %s",
                 esp_err_to_name(storage_error));
        return;
    }
#if CONFIG_PRODUCT_BOX3_BRINGUP_ENABLE
    ESP_LOGW(TAG,
             "DEVELOPMENT-ONLY BOX-3 bring-up profile: factory identity, "
             "cloud credentials, and production security are intentionally "
             "not asserted");
    const esp_err_t bringup_error = box3_bringup_start();
    if (bringup_error != ESP_OK) {
        ESP_LOGE(TAG, "BOX-3 bring-up failed: %s",
                 esp_err_to_name(bringup_error));
        return;
    }
    ESP_LOGI(TAG,
             "BOX-3 bring-up active: short-press BOOT toggles the display "
             "backlight through ESP-Claw; hold BOOT for 1.5 seconds to "
             "repeat the speaker/microphone test");
    return;
#endif
#if CONFIG_PRODUCT_BREAD_S3CAM_BRINGUP_ENABLE
    ESP_LOGW(TAG,
             "DEVELOPMENT-ONLY Bread S3CAM bring-up: Wi-Fi, cloud tokens, "
             "eFuse writes, and production security are disabled");
    const esp_err_t s3cam_bringup_error = bread_s3cam_bringup_start();
    if (s3cam_bringup_error != ESP_OK) {
        ESP_LOGE(TAG, "Bread S3CAM bring-up failed: %s",
                 esp_err_to_name(s3cam_bringup_error));
        return;
    }
    ESP_LOGI(TAG,
             "Bread S3CAM diagnostic active: short-press BOOT toggles the "
             "LCD backlight through ESP-Claw; hold BOOT for 1.5 seconds to "
             "repeat display/camera/speaker/microphone tests");
    return;
#endif
    product_sku_factory_validation_result_t factory_sku_detail =
        PRODUCT_SKU_FACTORY_VALIDATION_INVALID_ARGUMENT;
    product_sku_factory_manifest_t factory_sku_manifest = {0};
    const esp_err_t factory_sku_error =
        product_sku_validate_factory_identity(
            &factory_sku_detail, &factory_sku_manifest);
    if (factory_sku_error != ESP_OK) {
        ESP_LOGE(TAG,
                 "Factory SKU identity failed closed: %s (%s)",
                 esp_err_to_name(factory_sku_error),
                 product_sku_factory_validation_result_name(
                     factory_sku_detail));
        return;
    }
    if (factory_sku_detail == PRODUCT_SKU_FACTORY_VALIDATION_OK) {
        ESP_LOGI(TAG,
                 "Factory SKU identity authenticated: record=%u "
                 "silicon-revision=%u",
                 (unsigned)factory_sku_manifest.factory_record_version,
                 (unsigned)factory_sku_manifest.chip_revision);
    }
    product_factory_reset_result_t factory_reset = {0};
    const esp_err_t factory_reset_error =
        product_factory_reset_resume(&factory_reset);
    if (factory_reset_error != ESP_OK) {
        ESP_LOGE(TAG, "Factory reset recovery failed closed: %s",
                 esp_err_to_name(factory_reset_error));
        return;
    }
    if (factory_reset.completed) {
        ESP_LOGW(TAG,
                 "Factory reset completed before runtime start; local Wi-Fi "
                 "and Agent memory were cleared");
    }
    const esp_err_t memory_error =
        product_agent_memory_open(&s_agent_memory);
    if (memory_error != ESP_OK) {
        ESP_LOGE(TAG,
                 "Agent memory unavailable and will remain disabled: %s",
                 esp_err_to_name(memory_error));
    } else {
        product_agent_memory_stats_t memory_stats;
        if (product_agent_memory_get_stats(s_agent_memory,
                                           &memory_stats) == ESP_OK) {
            ESP_LOGI(TAG,
                     "Agent memory ready: items=%u generation=%u encrypted=%s",
                     (unsigned)memory_stats.item_count,
                     (unsigned)memory_stats.generation,
                     memory_stats.storage_encrypted ? "yes" : "no");
        }
    }
    product_ota_boot_status_t ota_boot = {0};
    const esp_err_t ota_status_error = product_ota_get_boot_status(&ota_boot);
    if (ota_status_error == ESP_OK && ota_boot.pending_verification) {
        ESP_LOGW(TAG,
                 "OTA image pending health verification; required mask=0x%08x",
                 (unsigned)ota_boot.required_health_checks);
    } else if (ota_status_error != ESP_OK) {
        ESP_LOGE(TAG, "OTA boot state unavailable: %s",
                 esp_err_to_name(ota_status_error));
        return;
    }
    verify_static_linkage();
    ESP_LOGI(TAG, "Free internal heap: %u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    ESP_LOGI(TAG, "Free PSRAM: %u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3 && CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE
    const esp_err_t runtime_error = start_product_runtime();
    if (runtime_error != ESP_OK) {
        ESP_LOGE(TAG, "Live product runtime failed closed: %s",
                 esp_err_to_name(runtime_error));
        return;
    }
    ESP_LOGI(TAG,
             "Live product runtime started; waiting for stored Wi-Fi or a "
             "reviewed physical-presence onboarding action");
#else
    ESP_LOGI(TAG,
             "Live Agent runtime is disabled in this build profile; the "
             "BOX-3 composition root remains fail-closed and opt-in.");
#endif
}
