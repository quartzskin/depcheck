package depcheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.LongSupplier;

/** One JSON file holding package->advisory ids and advisory bodies, each stamped with the fetch time. */
final class Cache {
    static final String FILE_NAME = "osv-cache.json";

    private final Path file;
    private final long ttlSeconds;
    private final LongSupplier clock;
    private final Map<String, Object> queries = new LinkedHashMap<>();
    private final Map<String, Object> vulns = new LinkedHashMap<>();

    Cache(Path dir, long ttlSeconds, LongSupplier clock) {
        this.file = dir.resolve(FILE_NAME);
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
        load();
    }

    private void load() {
        if (!Files.isRegularFile(file)) return;
        try {
            Map<String, Object> root = Json.asMap(Json.parse(Files.readString(file, StandardCharsets.UTF_8)));
            queries.putAll(Json.asMap(root.get("queries")));
            vulns.putAll(Json.asMap(root.get("vulns")));
        } catch (IOException | ManifestException e) {
            queries.clear();
            vulns.clear();
        }
    }

    private boolean fresh(Map<String, Object> entry) {
        return entry.get("at") instanceof Long at && clock.getAsLong() - at <= ttlSeconds;
    }

    Optional<List<String>> ids(String key) {
        Map<String, Object> e = Json.asMap(queries.get(key));
        if (!fresh(e)) return Optional.empty();
        List<String> out = new ArrayList<>();
        for (Object o : Json.asList(e.get("ids"))) if (o instanceof String s) out.add(s);
        return Optional.of(out);
    }

    Map<String, Object> vuln(String id) {
        Map<String, Object> e = Json.asMap(vulns.get(id));
        return fresh(e) ? Json.asMap(e.get("data")) : null;
    }

    void putIds(String key, List<String> ids) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("at", clock.getAsLong());
        e.put("ids", new ArrayList<>(ids));
        queries.put(key, e);
    }

    void putVuln(String id, Map<String, Object> data) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("at", clock.getAsLong());
        e.put("data", data);
        vulns.put(id, e);
    }

    void save() throws IOException {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("queries", queries);
        root.put("vulns", vulns);
        Files.createDirectories(file.toAbsolutePath().getParent());
        Path tmp = file.resolveSibling(FILE_NAME + ".tmp");
        Files.writeString(tmp, Json.write(root), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
    }
}
