package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void loadsBasicRulePackFromClasspath() {
        RuleEngine engine = new RuleEngine();
        assertEquals(3, engine.load(getClass().getResourceAsStream("/rules/basic.yaml")).rules().size());
    }

    @Test
    void existsProducesFindingWhenFieldIsAbsent() throws Exception {
        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(new StringReader(pack("$.info", "exists")));
        RuleEngine.Finding finding = engine.evaluate(JSON.readTree("{}"), pack).findings().get(0);
        assertEquals("TEST-001", finding.ruleId());
        assertEquals("1.0.0", finding.ruleVersion());
        assertEquals("medium", finding.severity());
        assertEquals("documentation", finding.category());
        assertEquals("$.info is required", finding.message());
    }

    @Test
    void existsProducesNoFindingWhenFieldIsPresent() throws Exception {
        RuleEngine engine = new RuleEngine();
        RuleEngine.RulePack pack = engine.load(new StringReader(pack("$.info", "exists")));
        assertTrue(engine.evaluate(JSON.readTree("{\"info\":{\"title\":\"Demo\"}}"), pack).findings().isEmpty());
    }

    @Test
    void rejectsUnknownFunctions() {
        RuleEngine.RuleValidationException error = assertThrows(RuleEngine.RuleValidationException.class,
                () -> new RuleEngine().load(new StringReader(pack("$", "notAllowed"))));
        assertTrue(error.getMessage().contains("Unknown function 'notAllowed'"));
    }

    @Test
    void rejectsDuplicateRuleIds() {
        String yaml = "rules:\n" + rule("TEST-001", "exists") + rule("TEST-001", "exists");
        RuleEngine.RuleValidationException error = assertThrows(RuleEngine.RuleValidationException.class,
                () -> new RuleEngine().load(new StringReader(yaml)));
        assertTrue(error.getMessage().contains("Duplicate rule id"));
    }

    @Test
    void rejectsMalformedRulePacks() {
        RuleEngine.RuleValidationException error = assertThrows(RuleEngine.RuleValidationException.class,
                () -> new RuleEngine().load(new StringReader("rules: nope")));
        assertTrue(error.getMessage().contains("rules list"));
    }

    private static String pack(String given, String function) {
        return "rules:\n" + rule("TEST-001", function).replace("given: $", "given: " + given);
    }

    private static String rule(String id, String function) {
        return "  - id: " + id + "\n" +
                "    version: 1.0.0\n" +
                "    scope: DOCUMENT\n" +
                "    category: documentation\n" +
                "    severity: medium\n" +
                "    given: $\n" +
                "    then:\n" +
                "      function: " + function + "\n" +
                "    message: $.info is required\n";
    }
}
