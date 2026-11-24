package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

final class JsonSelectors {
    static List<JsonNode> select(JsonNode root, String selector) {
        if (selector == null || !selector.startsWith("$")) throw new RuleEngine.RuleValidationException("Selector must start with $");
        List<JsonNode> current = List.of(root); String path = selector.substring(1);
        if (path.isEmpty()) return current;
        for (String part : path.split("\\.")) {
            if (part.isEmpty()) continue;
            List<JsonNode> next = new ArrayList<>();
            for (JsonNode n : current) { next.add(n.path(part)); }
            current = next;
        }
        return current;
    }
    static String pointer(JsonNode selected, JsonNode root) { return selected == root ? "" : ""; }
}
