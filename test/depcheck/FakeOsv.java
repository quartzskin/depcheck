package depcheck;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Stand-in for api.osv.dev: lodash 4.17.15 and requests 2.19.0 are vulnerable, everything else is clean. */
final class FakeOsv implements AutoCloseable {
    final List<String> batchBodies = Collections.synchronizedList(new ArrayList<>());
    final AtomicInteger requests = new AtomicInteger();
    volatile int batchStatus = 200;
    volatile boolean dropLastResult = false;
    private final HttpServer server;

    FakeOsv() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/v1/querybatch", ex -> {
            requests.incrementAndGet();
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            batchBodies.add(body);
            if (batchStatus != 200) {
                reply(ex, batchStatus, "{}");
                return;
            }
            List<Object> results = new ArrayList<>();
            for (Object q : Json.asList(Json.asMap(Json.parse(body)).get("queries"))) {
                Map<String, Object> m = Json.asMap(q);
                String name = Json.asString(Json.asMap(m.get("package")).get("name"));
                String ver = Json.asString(m.get("version"));
                if ("lodash".equals(name) && "4.17.15".equals(ver)) results.add(Map.of("vulns", List.of(Map.of("id", "GHSA-test-lodash"))));
                else if ("requests".equals(name) && "2.19.0".equals(ver))
                    results.add(Map.of("vulns", List.of(Map.of("id", "GHSA-test-req"), Map.of("id", "PYSEC-test-req"))));
                else results.add(Map.of());
            }
            if (dropLastResult && !results.isEmpty()) results.remove(results.size() - 1);
            reply(ex, 200, Json.write(Map.of("results", results)));
        });
        server.createContext("/v1/vulns/", ex -> {
            requests.incrementAndGet();
            String id = ex.getRequestURI().getPath().substring("/v1/vulns/".length());
            reply(ex, 200, Json.write(vuln(id)));
        });
        server.start();
    }

    private static Map<String, Object> vuln(String id) {
        String name = id.contains("lodash") ? "lodash" : "requests";
        String eco = name.equals("lodash") ? "npm" : "PyPI";
        String fixed = name.equals("lodash") ? "4.17.21" : "2.20.0";
        return Map.of("id", id, "summary", "test advisory " + id,
                "database_specific", id.startsWith("GHSA") ? Map.of("severity", "HIGH") : Map.of(),
                "severity", id.startsWith("PYSEC") ? List.of(Map.of("type", "CVSS_V3", "score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) : List.of(),
                "affected", List.of(Map.of("package", Map.of("name", name, "ecosystem", eco),
                        "ranges", List.of(Map.of("type", "ECOSYSTEM", "events", List.of(Map.of("introduced", "0"), Map.of("fixed", fixed)))))));
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
