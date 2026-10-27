package depcheck;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class OsvTests {
    private static final Dep LODASH = new Dep("npm", "lodash", "4.17.15", "4.17.15", "package.json");
    private static final Dep CLEAN = new Dep("npm", "left-pad", "1.3.0", "1.3.0", "package.json");

    public void testRequestShapeAndResponseMapping() throws Exception {
        try (FakeOsv osv = new FakeOsv()) {
            Map<String, List<String>> r = new OsvClient(osv.url()).queryBatch(List.of(LODASH, CLEAN));
            Assert.eq(List.of("GHSA-test-lodash"), r.get(LODASH.key()));
            Assert.eq(List.of(), r.get(CLEAN.key()));

            Map<String, Object> body = Json.asMap(Json.parse(osv.batchBodies.get(0)));
            List<Object> qs = Json.asList(body.get("queries"));
            Assert.eq(2, qs.size());
            Map<String, Object> q0 = Json.asMap(qs.get(0));
            Assert.eq("lodash", Json.asMap(q0.get("package")).get("name"));
            Assert.eq("npm", Json.asMap(q0.get("package")).get("ecosystem"));
            Assert.eq("4.17.15", q0.get("version"));
        }
    }

    public void testVulnDetailsFetch() throws Exception {
        try (FakeOsv osv = new FakeOsv()) {
            Map<String, Object> raw = new OsvClient(osv.url()).vuln("GHSA-test-lodash");
            Vuln v = Vuln.from("GHSA-test-lodash", raw, LODASH);
            Assert.eq("HIGH", v.severity());
            Assert.eq(List.of("4.17.21"), v.fixed());
        }
    }

    public void testHttpErrorIsReported() throws Exception {
        try (FakeOsv osv = new FakeOsv()) {
            osv.batchStatus = 500;
            try {
                new OsvClient(osv.url()).queryBatch(List.of(LODASH));
            } catch (IOException e) {
                Assert.yes(e.getMessage().contains("HTTP 500"), e.getMessage());
                return;
            }
            throw new AssertionError("expected IOException");
        }
    }

    public void testResultCountMismatchIsRejected() throws Exception {
        try (FakeOsv osv = new FakeOsv()) {
            osv.dropLastResult = true;
            try {
                new OsvClient(osv.url()).queryBatch(List.of(LODASH, CLEAN));
            } catch (IOException e) {
                Assert.yes(e.getMessage().contains("1 results for 2 queries"), e.getMessage());
                return;
            }
            throw new AssertionError("expected IOException");
        }
    }

    public void testUnreachableServerFailsCleanly() {
        try {
            new OsvClient("http://127.0.0.1:1").queryBatch(List.of(LODASH));
        } catch (IOException e) {
            return;
        }
        throw new AssertionError("expected IOException");
    }

    public void testSecondRunIsServedFromCache() throws Exception {
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("depcheck-cache");
        try (FakeOsv osv = new FakeOsv()) {
            OsvClient client = new OsvClient(osv.url());
            Cache c1 = new Cache(dir, 3600, () -> 10L);
            Checker.Result first = Checker.check(List.of(LODASH, CLEAN), c1, client);
            c1.save();
            Assert.eq(2, first.queried());
            Assert.eq(1, first.vulns().size());
            int after = osv.requests.get();

            Checker.Result second = Checker.check(List.of(LODASH, CLEAN), new Cache(dir, 3600, () -> 20L), client);
            Assert.eq(0, second.queried());
            Assert.eq(2, second.fromCache());
            Assert.eq(after, osv.requests.get());
            Assert.eq("HIGH", second.vulns().get(LODASH.key()).get(0).severity());
        }
    }
}
