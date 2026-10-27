package depcheck;

import java.util.List;
import java.util.Map;

public class VulnTests {
    public void testCvss3KnownScores() {
        Assert.eq(9.8, Vuln.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
        Assert.eq(6.1, Vuln.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"));
        Assert.eq(5.3, Vuln.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"));
        Assert.eq(0.0, Vuln.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"));
    }

    public void testCvss3IncompleteVectorIsZero() {
        Assert.eq(0.0, Vuln.cvss3("CVSS:3.1/AV:N"));
        Assert.eq(0.0, Vuln.cvss3("garbage"));
    }

    public void testSeverityFromDeclaredThenFromVector() {
        Dep d = new Dep("npm", "lodash", "4.17.15", "4.17.15", "package.json");
        Map<String, Object> declared = Map.of("database_specific", Map.of("severity", "MODERATE"));
        Assert.eq("MEDIUM", Vuln.from("X", declared, d).severity());
        Map<String, Object> vec = Map.of("severity", List.of(Map.of("score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")));
        Assert.eq("CRITICAL", Vuln.from("X", vec, d).severity());
        Assert.eq("UNKNOWN", Vuln.from("X", Map.of("summary", "s"), d).severity());
        Assert.eq("UNKNOWN", Vuln.from("X", null, d).severity());
    }

    public void testFixedVersionMatchesPackageNameLoosely() {
        Dep d = new Dep("PyPI", "Foo_Bar", "1.0", "==1.0", "requirements.txt");
        Map<String, Object> raw = Map.of("affected", List.of(
                Map.of("package", Map.of("name", "foo-bar"), "ranges", List.of(
                        Map.of("type", "GIT", "events", List.of(Map.of("fixed", "c45d7c49ea75"))),
                        Map.of("type", "ECOSYSTEM", "events", List.of(Map.of("fixed", "1.1"))))),
                Map.of("package", Map.of("name", "other"), "ranges", List.of(Map.of("events", List.of(Map.of("fixed", "9.9")))))));
        Assert.eq(List.of("1.1"), Vuln.from("X", raw, d).fixed());
    }
}
