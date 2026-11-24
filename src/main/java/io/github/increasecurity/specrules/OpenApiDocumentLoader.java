package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Loads local OpenAPI 3.x and Swagger 2.0 YAML or JSON documents. */
public final class OpenApiDocumentLoader {
    private final ObjectMapper mapper = new ObjectMapper();
    private final long maxBytes;

    public OpenApiDocumentLoader() { this(10 * 1024 * 1024); }
    public OpenApiDocumentLoader(long maxBytes) { if (maxBytes <= 0) throw new IllegalArgumentException("maxBytes must be positive"); this.maxBytes = maxBytes; }

    public OpenApiDocument load(Path path) {
        try {
            if (!Files.isRegularFile(path)) throw new OpenApiParseException("OpenAPI source does not exist: " + path);
            if (Files.size(path) > maxBytes) throw new OpenApiParseException("OpenAPI source exceeds maximum size: " + maxBytes);
            try (InputStream input = Files.newInputStream(path)) { return load(input, path.toString()); }
        } catch (IOException e) { throw new OpenApiParseException("Unable to read OpenAPI source '" + path + "': " + e.getMessage(), e); }
    }

    public OpenApiDocument load(byte[] bytes, String source) {
        if (bytes == null || bytes.length > maxBytes) throw new OpenApiParseException("OpenAPI source exceeds maximum size: " + maxBytes);
        try { return parse(bytes, source); }
        catch (OpenApiParseException e) { throw e; }
        catch (RuntimeException | IOException e) { throw new OpenApiParseException("Invalid OpenAPI YAML/JSON in '" + source + "': " + e.getMessage(), e); }
    }

    public OpenApiDocument load(InputStream input, String source) {
        try { return load(input.readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE)), source); }
        catch (IOException e) { throw new OpenApiParseException("Unable to read OpenAPI source '" + source + "': " + e.getMessage(), e); }
    }

    private OpenApiDocument parse(byte[] bytes, String source) throws IOException {
        Object parsed = new Yaml().load(new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
        JsonNode json = mapper.valueToTree(parsed);
        if (json == null || !json.isObject()) throw new OpenApiParseException("OpenAPI source must be an object: " + source);
        JsonNode openapi = json.get("openapi"), swagger = json.get("swagger");
        String version;
        if (openapi != null && openapi.isTextual() && openapi.textValue().matches("3\\..+")) version = openapi.textValue();
        else if (swagger != null && "2.0".equals(swagger.textValue())) version = swagger.textValue();
        else throw new OpenApiParseException("Unsupported API-description format in '" + source + "' (expected openapi 3.x or swagger 2.0)");
        List<String> diagnostics = new ArrayList<>();
        if (json.get("info") == null || !json.get("info").isObject()) diagnostics.add("Missing or invalid info object");
        return new OpenApiDocument(json, version, source, diagnostics);
    }

    public static final class OpenApiParseException extends IllegalArgumentException {
        public OpenApiParseException(String message) { super(message); }
        public OpenApiParseException(String message, Throwable cause) { super(message, cause); }
    }
}
