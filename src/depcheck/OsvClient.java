package depcheck;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OsvClient {
    private static final int BATCH = 500;

    private final String base;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    OsvClient(String baseUrl) {
        this.base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    Map<String, List<String>> queryBatch(List<Dep> deps) throws IOException {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (int from = 0; from < deps.size(); from += BATCH) {
            List<Dep> chunk = deps.subList(from, Math.min(deps.size(), from + BATCH));
            List<Object> queries = new ArrayList<>();
            for (Dep d : chunk) queries.add(query(d, null));
            List<Object> results = Json.asList(post(Map.of("queries", queries)).get("results"));
            if (results.size() != chunk.size())
                throw new IOException("OSV returned " + results.size() + " results for " + chunk.size() + " queries");
            for (int k = 0; k < chunk.size(); k++) {
                Map<String, Object> r = Json.asMap(results.get(k));
                List<String> ids = new ArrayList<>();
                collect(r, ids);
                for (int page = 0; r.get("next_page_token") instanceof String tok && page < 50; page++) {
                    List<Object> one = Json.asList(post(Map.of("queries", List.of(query(chunk.get(k), tok)))).get("results"));
                    r = one.isEmpty() ? Map.of() : Json.asMap(one.get(0));
                    collect(r, ids);
                }
                out.put(chunk.get(k).key(), ids);
            }
        }
        return out;
    }

    private static Map<String, Object> query(Dep d, String pageToken) {
        Map<String, Object> pkg = new LinkedHashMap<>();
        pkg.put("name", d.name());
        pkg.put("ecosystem", d.ecosystem());
        Map<String, Object> q = new LinkedHashMap<>();
        q.put("package", pkg);
        q.put("version", d.version());
        if (pageToken != null) q.put("page_token", pageToken);
        return q;
    }

    private static void collect(Map<String, Object> result, List<String> ids) {
        for (Object o : Json.asList(result.get("vulns"))) {
            String id = Json.asString(Json.asMap(o).get("id"));
            if (id != null && !ids.contains(id)) ids.add(id);
        }
    }

    Map<String, Object> vuln(String id) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/v1/vulns/" + URLEncoder.encode(id, StandardCharsets.UTF_8)))
                .timeout(Duration.ofSeconds(30)).header("User-Agent", "depcheck").GET().build();
        return send(req);
    }

    private Map<String, Object> post(Map<String, Object> body) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/v1/querybatch"))
                .timeout(Duration.ofSeconds(60)).header("User-Agent", "depcheck")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build();
        return send(req);
    }

    private Map<String, Object> send(HttpRequest req) throws IOException {
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
        if (resp.statusCode() != 200) throw new IOException("OSV answered HTTP " + resp.statusCode() + " for " + req.uri().getPath());
        try {
            Object o = Json.parse(resp.body());
            if (!(o instanceof Map)) throw new IOException("OSV response is not a JSON object");
            return Json.asMap(o);
        } catch (ManifestException e) {
            throw new IOException("OSV response is not valid JSON: " + e.getMessage());
        }
    }
}
