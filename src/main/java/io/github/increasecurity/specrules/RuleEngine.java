package io.github.increasecurity.specrules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.io.Reader;
import java.util.*;
import java.util.function.BiPredicate;
import java.util.regex.Pattern;

public final class RuleEngine {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final Map<String, RuleFunction> functions;
    private final Limits limits;

    public RuleEngine() { this(Map.of(), Limits.defaults()); }
    public RuleEngine(Map<String, RuleFunction> extensions, Limits limits) {
        Map<String, RuleFunction> all = new LinkedHashMap<>(BuiltInFunctions.all());
        all.putAll(extensions);
        this.functions = Map.copyOf(all); this.limits = limits;
    }

    public RulePack load(InputStream resource) { return RulePackLoader.load(resource, functions, limits); }
    public RulePack load(Reader resource) { return RulePackLoader.load(resource, functions, limits); }
    public AnalysisResult evaluate(JsonNode document, RulePack pack) {
        return evaluate(document, null, pack);
    }
    /** Evaluates a parsed document while retaining the source file in every finding. */
    public AnalysisResult evaluate(OpenApiDocument document, RulePack pack) {
        Objects.requireNonNull(document, "document");
        return evaluate(document.json(), document.source(), pack);
    }
    private AnalysisResult evaluate(JsonNode document, String source, RulePack pack) {
        List<Finding> findings = new ArrayList<>();
        for (Rule rule : pack.rules()) {
            List<JsonNode> selected = JsonSelectors.select(document, rule.given());
            if (selected.size() > limits.maxSelectorResults()) throw new RuleValidationException("Selector result limit exceeded for " + rule.id());
            for (JsonNode value : selected) {
                if (rule.when() != null && functions.get(rule.when().function()).test(value, rule.when().options())) continue;
                if (!functions.get(rule.then().function()).test(value, rule.then().options()))
                    findings.add(new Finding(rule.id(), rule.version(), rule.severity(), rule.category(), rule.message(),
                            JsonSelectors.pointer(value, document), Evidence.safe(value, limits.maxEvidenceSize()), source));
            }
        }
        return new AnalysisResult(findings);
    }

    public record Limits(int maxRules, int maxSelectorResults, int maxMessageSize, int maxEvidenceSize) {
        public static Limits defaults() { return new Limits(500, 1_000, 4_000, 2_000); }
    }
    public interface RuleFunction { boolean test(JsonNode value, Map<String, Object> options); }
    public record RulePack(List<Rule> rules) { public RulePack { rules = List.copyOf(rules); } }
    public record Rule(String id, String version, String title, String scope, String category, String severity,
                       String findingType, String given, Condition when, Condition then, String message, String remediation) {}
    public record Condition(String function, Map<String, Object> options) { public Condition { options = Map.copyOf(options); } }
    public record Finding(String ruleId, String ruleVersion, String severity, String category, String message,
                          String location, String evidence, String source) {
        /** Backward-compatible constructor for callers that evaluate raw JSON. */
        public Finding(String ruleId, String ruleVersion, String severity, String category, String message,
                       String location, String evidence) {
            this(ruleId, ruleVersion, severity, category, message, location, evidence, null);
        }
    }
    public record AnalysisResult(List<Finding> findings) { public AnalysisResult { findings = List.copyOf(findings); } }
    public static final class RuleValidationException extends IllegalArgumentException { public RuleValidationException(String m) { super(m); } }

    private static final class RulePackLoader {
        static RulePack load(Object source, Map<String, RuleFunction> functions, Limits limits) {
            Object data = source instanceof InputStream i ? new Yaml().load(i) : new Yaml().load((Reader) source);
            if (!(data instanceof Map<?, ?> root) || !(root.get("rules") instanceof List<?> list))
                throw new RuleValidationException("Rule pack must contain a rules list");
            if (list.size() > limits.maxRules()) throw new RuleValidationException("Rule count exceeds configured limit");
            Set<String> ids = new HashSet<>(); List<Rule> rules = new ArrayList<>();
            for (Object item : list) {
                if (!(item instanceof Map<?, ?> m)) throw new RuleValidationException("Each rule must be a mapping");
                String id = required(m, "id"), given = required(m, "given"), message = required(m, "message");
                if (!ids.add(id)) throw new RuleValidationException("Duplicate rule id: " + id);
                if (message.length() > limits.maxMessageSize()) throw new RuleValidationException("Message too long: " + id);
                Condition when = condition(m.get("when"), id), then = condition(m.get("then"), id);
                if (then == null) throw new RuleValidationException("Missing then for " + id);
                validateFunction(then, functions, id); if (when != null) validateFunction(when, functions, id);
                rules.add(new Rule(id, required(m,"version"), string(m,"title",""), required(m,"scope"), required(m,"category"),
                        required(m,"severity"), string(m,"findingType","violation"), given, when, then, message, string(m,"remediation","")));
            }
            return new RulePack(rules);
        }
        static String required(Map<?, ?> m, String key) { String v = string(m,key,null); if (v == null || v.isBlank()) throw new RuleValidationException("Missing required field: " + key); return v; }
        static String string(Map<?, ?> m, String k, String d) { return m.get(k) == null ? d : String.valueOf(m.get(k)); }
        static Condition condition(Object o, String id) { if (o == null) return null; if (!(o instanceof Map<?, ?> m)) throw new RuleValidationException("Invalid condition for " + id); String f=required(m,"function"); Map<String,Object> opts=new LinkedHashMap<>(); if(m.get("options") instanceof Map<?,?> om) om.forEach((k,v)->opts.put(String.valueOf(k),v)); return new Condition(f,opts); }
        static void validateFunction(Condition c, Map<String, RuleFunction> fs, String id) { if (!fs.containsKey(c.function())) throw new RuleValidationException("Unknown function '"+c.function()+"' in "+id); }
    }

    private static final class BuiltInFunctions {
        static Map<String,RuleFunction> all() {
            Map<String,RuleFunction> m = new HashMap<>();
            m.put("exists", (v,o) -> !v.isMissingNode() && !v.isNull());
            m.put("truthy", (v,o) -> v.isBoolean() ? v.booleanValue() : v.isTextual() ? !v.textValue().isBlank() : v.isNumber() && v.doubleValue() != 0);
            m.put("falsy", (v,o) -> !m.get("truthy").test(v,o));
            m.put("matches", (v,o) -> v.isTextual() && Pattern.compile(String.valueOf(o.getOrDefault("pattern", ""))).matcher(v.textValue()).find());
            m.put("length", (v,o) -> (v.isArray() || v.isObject() || v.isTextual()) && v.size() == ((Number)o.getOrDefault("value", 0)).intValue());
            m.put("enumeration", (v,o) -> o.get("values") instanceof Collection<?> c && c.stream().map(String::valueOf).anyMatch(x -> x.equals(v.asText())));
            m.put("unique", (v,o) -> { if (!v.isArray()) return false; Set<JsonNode> s = new HashSet<>(); for (JsonNode n : v) if (!s.add(n)) return false; return true; });
            return m;
        }
    }
}
