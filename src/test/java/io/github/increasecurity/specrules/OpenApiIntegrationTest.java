package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OpenApiIntegrationTest {
    private final OpenApiDocumentLoader loader = new OpenApiDocumentLoader();

    @Test
    void parsesFixtureAndRunsBundledRules() {
        OpenApiDocument document = loader.load(Path.of("src/test/resources/specs/outbound_api.yaml"));
        assertEquals("3.0.3", document.version());
        assertEquals("src/test/resources/specs/outbound_api.yaml", document.source());
        assertTrue(document.json().isObject());

        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(getClass().getResourceAsStream("/rules/basic.yaml"));
        RuleEngine.AnalysisResult result = engine.evaluate(document.json(), pack);

        assertTrue(result.findings().isEmpty());
        result.findings().forEach(finding -> {
            assertFalse(finding.ruleId().isBlank());
            assertFalse(finding.ruleVersion().isBlank());
            assertFalse(finding.severity().isBlank());
            assertFalse(finding.message().isBlank());
            assertNotNull(finding.location());
        });
    }

    @Test
    void findingsRetainOpenApiSource() {
        OpenApiDocument document = loader.load(Path.of("src/test/resources/specs/missing-info-title.yaml"));
        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(getClass().getResourceAsStream("/rules/basic.yaml"));

        var findings = engine.evaluate(document, pack).findings();

        assertFalse(findings.isEmpty());
        assertEquals(document.source(), findings.get(0).source());
    }

    @Test
    void reportsMissingInfoTitle() {
        OpenApiDocument document = loader.load(Path.of("src/test/resources/specs/missing-info-title.yaml"));
        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(getClass().getResourceAsStream("/rules/basic.yaml"));

        var findings = engine.evaluate(document.json(), pack).findings();

        assertEquals(2, findings.size());
        assertEquals("INC-GEN-001", findings.get(0).ruleId());
        assertEquals("INC-GEN-002", findings.get(1).ruleId());
        assertEquals("API documents must define info.title.", findings.get(0).message());
    }

    @Test
    void reportsMissingInfoVersion() {
        OpenApiDocument document = loader.load("""
                openapi: 3.0.3
                info:
                  title: Example API
                paths: {}
                """.getBytes(), "missing-info-version.yaml");
        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(getClass().getResourceAsStream("/rules/basic.yaml"));

        var findings = engine.evaluate(document.json(), pack).findings();

        assertEquals(2, findings.size());
        assertEquals("INC-GEN-002", findings.get(0).ruleId());
        assertEquals("INC-GEN-003", findings.get(1).ruleId());
        assertEquals("API documents must define info.version.", findings.get(1).message());
    }

    @Test
    void rejectsMalformedYaml() {
        assertThrows(OpenApiDocumentLoader.OpenApiParseException.class,
                () -> loader.load("openapi: [".getBytes(), "malformed.yaml"));
    }

    @Test
    void rejectsUnsupportedApiDescription() {
        OpenApiDocumentLoader.OpenApiParseException error = assertThrows(OpenApiDocumentLoader.OpenApiParseException.class,
                () -> loader.load("name: ordinary document\n".getBytes(), "ordinary.yaml"));
        assertTrue(error.getMessage().contains("Unsupported API-description format"));
    }

    @Test
    void rejectsMissingSource() {
        OpenApiDocumentLoader.OpenApiParseException error = assertThrows(OpenApiDocumentLoader.OpenApiParseException.class,
                () -> loader.load(Path.of("src/test/resources/specs/missing.yaml")));
        assertTrue(error.getMessage().contains("does not exist"));
    }
}
