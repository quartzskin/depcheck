package depcheck;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class Checker {
    /** vulns: Dep.key() -> advisories; unchecked: keys with neither a fresh cache entry nor a network answer. */
    record Result(Map<String, List<Vuln>> vulns, Set<String> unchecked, int fromCache, int queried) {
    }

    private Checker() {
    }

    /** client == null means offline: only fresh cache entries are used. */
    static Result check(List<Dep> deps, Cache cache, OsvClient client) throws IOException {
        Map<String, Dep> unique = new LinkedHashMap<>();
        for (Dep d : deps) if (d.version() != null) unique.putIfAbsent(d.key(), d);

        Map<String, List<String>> ids = new HashMap<>();
        List<Dep> misses = new ArrayList<>();
        for (Map.Entry<String, Dep> e : unique.entrySet()) {
            var hit = cache.ids(e.getKey());
            if (hit.isPresent()) ids.put(e.getKey(), hit.get());
            else misses.add(e.getValue());
        }
        int fromCache = ids.size();

        if (client != null && !misses.isEmpty()) {
            Map<String, List<String>> fetched = client.queryBatch(misses);
            for (Map.Entry<String, List<String>> e : fetched.entrySet()) {
                cache.putIds(e.getKey(), e.getValue());
                ids.put(e.getKey(), e.getValue());
            }
        }

        Map<String, List<Vuln>> out = new LinkedHashMap<>();
        for (Map.Entry<String, Dep> e : unique.entrySet()) {
            List<String> found = ids.get(e.getKey());
            if (found == null || found.isEmpty()) continue;
            List<Vuln> list = new ArrayList<>();
            for (String id : found) {
                Map<String, Object> raw = cache.vuln(id);
                if (raw == null && client != null) {
                    raw = client.vuln(id);
                    cache.putVuln(id, raw);
                }
                list.add(Vuln.from(id, raw, e.getValue()));
            }
            out.put(e.getKey(), list);
        }

        Set<String> unchecked = new LinkedHashSet<>(unique.keySet());
        unchecked.removeAll(ids.keySet());
        return new Result(out, unchecked, fromCache, client == null ? 0 : misses.size());
    }
}
