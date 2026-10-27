package depcheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

record Vuln(String id, String severity, double score, String summary, List<String> fixed) {
    static final List<String> ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN");

    static int rank(String severity) {
        int r = ORDER.indexOf(severity);
        return r < 0 ? ORDER.size() : r;
    }

    String link() {
        return "https://osv.dev/vulnerability/" + id;
    }

    /** raw may be null (details not cached); the advisory is then reported by id only. */
    static Vuln from(String id, Map<String, Object> raw, Dep dep) {
        if (raw == null || raw.isEmpty()) return new Vuln(id, "UNKNOWN", 0, "", List.of());
        String summary = Json.asString(raw.get("summary"));
        if (summary == null) summary = "";
        String sev = null;
        double score = 0;
        String declared = Json.asString(Json.asMap(raw.get("database_specific")).get("severity"));
        for (Object o : Json.asList(raw.get("severity"))) {
            String vec = Json.asString(Json.asMap(o).get("score"));
            if (vec != null && vec.startsWith("CVSS:3")) score = Math.max(score, cvss3(vec));
        }
        if (declared != null) sev = normalize(declared);
        if (sev == null && score > 0) sev = rating(score);
        if (sev == null) sev = "UNKNOWN";
        return new Vuln(id, sev, score, summary, fixedVersions(raw, dep));
    }

    private static String normalize(String s) {
        String u = s.trim().toUpperCase();
        if (u.equals("MODERATE")) return "MEDIUM";
        return ORDER.contains(u) && !u.equals("UNKNOWN") ? u : null;
    }

    private static String rating(double score) {
        if (score >= 9) return "CRITICAL";
        if (score >= 7) return "HIGH";
        if (score >= 4) return "MEDIUM";
        return "LOW";
    }

    private static String canon(String name) {
        return name.toLowerCase().replaceAll("[-_.]+", "-");
    }

    private static List<String> fixedVersions(Map<String, Object> raw, Dep dep) {
        List<String> out = new ArrayList<>();
        for (Object a : Json.asList(raw.get("affected"))) {
            Map<String, Object> aff = Json.asMap(a);
            Map<String, Object> pkg = Json.asMap(aff.get("package"));
            String name = Json.asString(pkg.get("name"));
            if (name == null || !canon(name).equals(canon(dep.name()))) continue;
            for (Object r : Json.asList(aff.get("ranges"))) {
                if ("GIT".equals(Json.asMap(r).get("type"))) continue;
                for (Object e : Json.asList(Json.asMap(r).get("events"))) {
                    String fixed = Json.asString(Json.asMap(e).get("fixed"));
                    if (fixed != null && !out.contains(fixed)) out.add(fixed);
                }
            }
        }
        return out;
    }

    static double cvss3(String vector) {
        Map<String, String> m = new java.util.HashMap<>();
        for (String part : vector.split("/")) {
            int c = part.indexOf(':');
            if (c > 0) m.put(part.substring(0, c), part.substring(c + 1));
        }
        boolean changed = "C".equals(m.get("S"));
        Double av = lookup(m.get("AV"), "N", .85, "A", .62, "L", .55, "P", .2);
        Double ac = lookup(m.get("AC"), "L", .77, "H", .44, null, 0, null, 0);
        Double pr = changed ? lookup(m.get("PR"), "N", .85, "L", .68, "H", .5)
                : lookup(m.get("PR"), "N", .85, "L", .62, "H", .27);
        Double ui = lookup(m.get("UI"), "N", .85, "R", .62, null, 0, null, 0);
        Double c = lookup(m.get("C"), "H", .56, "L", .22, "N", 0);
        Double i = lookup(m.get("I"), "H", .56, "L", .22, "N", 0);
        Double a = lookup(m.get("A"), "H", .56, "L", .22, "N", 0);
        if (av == null || ac == null || pr == null || ui == null || c == null || i == null || a == null || m.get("S") == null)
            return 0;
        double iss = 1 - (1 - c) * (1 - i) * (1 - a);
        double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
        if (impact <= 0) return 0;
        double expl = 8.22 * av * ac * pr * ui;
        double raw = changed ? 1.08 * (impact + expl) : impact + expl;
        return Math.ceil(Math.min(raw, 10) * 10 - 1e-9) / 10;
    }

    private static Double lookup(String key, String k1, double v1, String k2, double v2, String k3, double v3) {
        return lookup(key, k1, v1, k2, v2, k3, v3, null, 0);
    }

    private static Double lookup(String key, String k1, double v1, String k2, double v2, String k3, double v3,
            String k4, double v4) {
        if (key == null) return null;
        if (key.equals(k1)) return v1;
        if (key.equals(k2)) return v2;
        if (key.equals(k3)) return v3;
        if (key.equals(k4)) return v4;
        return null;
    }
}
