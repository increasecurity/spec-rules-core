package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/** Parsed OpenAPI/Swagger document exposed without parser implementation types. */
public record OpenApiDocument(JsonNode json, String version, String source, List<String> diagnostics) {
    public OpenApiDocument {
        diagnostics = List.copyOf(diagnostics);
    }
}
