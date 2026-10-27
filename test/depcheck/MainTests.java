package depcheck;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class MainTests {
    private record Run(int code, String out, String err) {
    }

    private static Run run(String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Run(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    private static Path project() throws IOException {
        Path root = Files.createTempDirectory("depcheck-proj");
        Path a = Files.createDirectories(root.resolve("web"));
        Files.writeString(a.resolve("package.json"), "{\"dependencies\":{\"lodash\":\"4.17.15\",\"left-pad\":\"1.3.0\"}}");
        Path b = Files.createDirectories(root.resolve("svc"));
        Files.writeString(b.resolve("requirements.txt"), "requests==2.19.0  # old\nflask>=2\n");
        Path skipped = Files.createDirectories(root.resolve("web").resolve("node_modules").resolve("x"));
        Files.writeString(skipped.resolve("package.json"), "{\"dependencies\":{\"lodash\":\"1.0.0\"}}");
        Files.writeString(root.resolve("go.mod"), "module m\nrequire (\n");
        return root;
    }

    public void testDefaultNeverTouchesNetworkAndListsInventory() throws Exception {
        Path root = project();
        Path cache = Files.createTempDirectory("depcheck-cache");
        try (FakeOsv osv = new FakeOsv()) {
            Run r = run(root.toString(), "--cache-dir", cache.toString(), "--osv-url", osv.url());
            Assert.eq(0, osv.requests.get());
            Assert.eq(0, r.code());
            Assert.yes(r.out().contains("lodash") && r.out().contains("4.17.15"), r.out());
            Assert.yes(r.out().contains("requests") && r.out().contains("(>=2)"), r.out());
            Assert.yes(r.out().contains("offline"), r.out());
            Assert.yes(!r.out().contains("1.0.0"), "node_modules must be skipped");
            Assert.yes(r.err().contains("go.mod: unterminated block"), r.err());
            Assert.yes(!Files.exists(cache.resolve(Cache.FILE_NAME)), "offline run must not write the cache");
        }
    }

    public void testOnlineFindsVulnsSortedAndExitsOne() throws Exception {
        Path root = project();
        Path cache = Files.createTempDirectory("depcheck-cache");
        try (FakeOsv osv = new FakeOsv()) {
            Run r = run(root.toString(), "--online", "--cache-dir", cache.toString(), "--osv-url", osv.url());
            Assert.eq(1, r.code());
            Assert.yes(r.out().contains("GHSA-test-lodash") && r.out().contains("4.17.21"), r.out());
            Assert.yes(r.out().contains("https://osv.dev/vulnerability/GHSA-test-req"), r.out());
            int crit = r.out().indexOf("PYSEC-test-req");
            int high = r.out().indexOf("GHSA-test-lodash");
            Assert.yes(crit >= 0 && crit < high, "CRITICAL (via CVSS vector) must come before HIGH:\n" + r.out());
            Assert.yes(Files.isRegularFile(cache.resolve(Cache.FILE_NAME)), "cache written");

            int seen = osv.requests.get();
            Run offline = run(root.toString(), "--cache-dir", cache.toString(), "--osv-url", osv.url());
            Assert.eq(seen, osv.requests.get());
            Assert.eq(1, offline.code());
            Assert.yes(offline.out().contains("GHSA-test-lodash"), offline.out());
        }
    }

    public void testExpiredCacheIsIgnoredOffline() throws Exception {
        Path root = project();
        Path cache = Files.createTempDirectory("depcheck-cache");
        try (FakeOsv osv = new FakeOsv()) {
            run(root.toString(), "--online", "--cache-dir", cache.toString(), "--osv-url", osv.url());
            Thread.sleep(1100);
            Run r = run(root.toString(), "--ttl-hours", "0", "--cache-dir", cache.toString());
            Assert.eq(0, r.code());
            Assert.yes(r.out().contains("0 packages answered from the cache"), r.out());
        }
    }

    public void testJsonOutput() throws Exception {
        Path root = project();
        try (FakeOsv osv = new FakeOsv()) {
            Run r = run(root.toString(), "--online", "--json", "--cache-dir", Files.createTempDirectory("c").toString(),
                    "--osv-url", osv.url());
            Assert.eq(1, r.code());
            Map<String, Object> doc = Json.asMap(Json.parse(r.out()));
            List<Object> v = Json.asList(doc.get("vulnerabilities"));
            Assert.eq(3, v.size());
            Assert.eq("CRITICAL", Json.asMap(v.get(0)).get("severity"));
            Assert.eq(List.of("web/package.json"), Json.asMap(v.get(1)).get("files"));
            Assert.eq(3L, Json.asMap(doc.get("summary")).get("advisories"));
        }
    }

    public void testCleanProjectExitsZero() throws Exception {
        Path root = Files.createTempDirectory("depcheck-proj");
        Files.writeString(root.resolve("package.json"), "{\"dependencies\":{\"left-pad\":\"1.3.0\"}}");
        try (FakeOsv osv = new FakeOsv()) {
            Run r = run(root.toString(), "--online", "--cache-dir", Files.createTempDirectory("c").toString(), "--osv-url", osv.url());
            Assert.eq(0, r.code());
            Assert.yes(r.out().contains("no known vulnerabilities"), r.out());
        }
    }

    public void testNetworkFailureExitsTwo() throws Exception {
        Path root = project();
        Run r = run(root.toString(), "--online", "--cache-dir", Files.createTempDirectory("c").toString(), "--osv-url", "http://127.0.0.1:1");
        Assert.eq(2, r.code());
        Assert.yes(r.err().startsWith("depcheck:"), r.err());
    }

    public void testBadArguments() throws Exception {
        Assert.eq(2, run("--bogus").code());
        Assert.eq(2, run("--ttl-hours", "x").code());
        Assert.eq(2, run("--cache-dir").code());
        Assert.eq(2, run("a", "b").code());
        Assert.eq(2, run(Files.createTempDirectory("x").resolve("missing").toString()).code());
        Assert.eq(0, run("--help").code());
    }
}
