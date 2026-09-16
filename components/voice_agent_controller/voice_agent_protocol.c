#include "voice_agent_protocol.h"

#include <stdbool.h>
#include <stdio.h>

typedef struct {
    char *output;
    size_t capacity;
    size_t length;
    bool overflow;
} json_writer_t;

static void writer_put(json_writer_t *writer, char value)
{
    if (writer->length == SIZE_MAX) {
        writer->overflow = true;
        return;
    }
    if (writer->capacity > 0 && writer->length + 1 < writer->capacity) {
        writer->output[writer->length] = value;
    }
    writer->length++;
}

static void writer_literal(json_writer_t *writer, const char *value)
{
    while (*value) {
        writer_put(writer, *value++);
    }
}

static void writer_escaped_string(json_writer_t *writer, const char *value)
{
    static const char hex[] = "0123456789abcdef";

    writer_put(writer, '"');
    while (*value) {
        unsigned char byte = (unsigned char)*value++;
        switch (byte) {
        case '"':
            writer_literal(writer, "\\\"");
            break;
        case '\\':
            writer_literal(writer, "\\\\");
            break;
        case '\b':
            writer_literal(writer, "\\b");
            break;
        case '\f':
            writer_literal(writer, "\\f");
            break;
        case '\n':
            writer_literal(writer, "\\n");
            break;
        case '\r':
            writer_literal(writer, "\\r");
            break;
        case '\t':
            writer_literal(writer, "\\t");
            break;
        default:
            if (byte < 0x20) {
                writer_literal(writer, "\\u00");
                writer_put(writer, hex[byte >> 4]);
                writer_put(writer, hex[byte & 0x0f]);
            } else {
                writer_put(writer, (char)byte);
            }
            break;
        }
    }
    writer_put(writer, '"');
}

static void writer_uint32(json_writer_t *writer, uint32_t value)
{
    char digits[11];
    int written = snprintf(digits, sizeof(digits), "%lu", (unsigned long)value);

    if (written <= 0 || (size_t)written >= sizeof(digits)) {
        writer->overflow = true;
        return;
    }
    writer_literal(writer, digits);
}

static voice_agent_protocol_result_t writer_finish(json_writer_t *writer,
                                                    size_t *required_size)
{
    if (writer->overflow || writer->length == SIZE_MAX) {
        if (writer->capacity > 0) {
            writer->output[0] = '\0';
        }
        return VOICE_AGENT_PROTOCOL_ERR_INVALID_ARG;
    }

    *required_size = writer->length + 1;
    if (writer->capacity <= writer->length) {
        if (writer->capacity > 0) {
            writer->output[0] = '\0';
        }
        return VOICE_AGENT_PROTOCOL_ERR_BUFFER_TOO_SMALL;
    }
    writer->output[writer->length] = '\0';
    return VOICE_AGENT_PROTOCOL_OK;
}

static const char *abort_reason_string(voice_agent_abort_reason_t reason)
{
    switch (reason) {
    case VOICE_AGENT_ABORT_BARGE_IN:
        return "barge_in";
    case VOICE_AGENT_ABORT_BUTTON:
        return "button";
    case VOICE_AGENT_ABORT_NETWORK_LOST:
        return "network_lost";
    case VOICE_AGENT_ABORT_SESSION_CLOSED:
        return "session_closed";
    default:
        return NULL;
    }
}

voice_agent_protocol_result_t voice_agent_build_tts_request(
    char *output,
    size_t output_size,
    const char *session_id,
    uint32_t request_id,
    const char *text,
    size_t *required_size)
{
    json_writer_t writer = {
        .output = output,
        .capacity = output_size,
    };

    if (!output || output_size == 0 || !session_id || !session_id[0] ||
        request_id == 0 || !text || !text[0] || !required_size) {
        return VOICE_AGENT_PROTOCOL_ERR_INVALID_ARG;
    }

    writer_literal(&writer, "{\"session_id\":");
    writer_escaped_string(&writer, session_id);
    writer_literal(&writer, ",\"type\":\"tts_request\",\"request_id\":");
    writer_uint32(&writer, request_id);
    writer_literal(&writer, ",\"text\":");
    writer_escaped_string(&writer, text);
    writer_put(&writer, '}');
    return writer_finish(&writer, required_size);
}

voice_agent_protocol_result_t voice_agent_build_tts_abort(
    char *output,
    size_t output_size,
    const char *session_id,
    uint32_t request_id,
    voice_agent_abort_reason_t reason,
    size_t *required_size)
{
    const char *reason_string = abort_reason_string(reason);
    json_writer_t writer = {
        .output = output,
        .capacity = output_size,
    };

    if (!output || output_size == 0 || !session_id || !session_id[0] ||
        request_id == 0 || !reason_string || !required_size) {
        return VOICE_AGENT_PROTOCOL_ERR_INVALID_ARG;
    }

    writer_literal(&writer, "{\"session_id\":");
    writer_escaped_string(&writer, session_id);
    writer_literal(&writer, ",\"type\":\"tts_abort\",\"request_id\":");
    writer_uint32(&writer, request_id);
    writer_literal(&writer, ",\"reason\":");
    writer_escaped_string(&writer, reason_string);
    writer_put(&writer, '}');
    return writer_finish(&writer, required_size);
}
