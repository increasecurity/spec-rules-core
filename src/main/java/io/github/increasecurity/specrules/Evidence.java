package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;

final class Evidence {
    static String safe(JsonNode value, int max) {
        String text = value == null ? "null" : value.toString();
        return text.length() <= max ? text : text.substring(0, max);
    }
}
