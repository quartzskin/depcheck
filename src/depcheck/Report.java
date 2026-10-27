package depcheck;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Report {
    private Report() {
    }

    static void print(PrintStream out, Scanner.Scan scan, Checker.Result res, List<Main.Row> rows, boolean online,
            boolean json, boolean inventory) {
        int unresolved = 0;
        for (Dep d : scan.deps()) if (d.version() == null) unresolved++;
        if (json) {
            out.println(Json.write(jsonDoc(scan, res, rows, online, unresolved, inventory)));
            return;
        }

        out.println("scanned " + scan.manifests() + " manifest files, " + scan.deps().size() + " packages ("
                + unresolved + " without an exact version, not checked)");
        if (online) {
            out.println("online: " + res.queried() + " packages queried, " + res.fromCache() + " answered from cache");
        } else {
            out.println("offline: no network used; " + res.fromCache() + " packages answered from the cache, "
                    + res.unchecked().size() + " not checked (pass --online to query OSV)");
        }

        if (inventory) {
            out.println();
            List<List<String>> t = new ArrayList<>();
            t.add(List.of("ECOSYSTEM", "PACKAGE", "VERSION", "FILE"));
            for (Dep d : scan.deps())
                t.add(List.of(d.ecosystem(), d.name(), d.version() != null ? d.version() : "(" + d.spec() + ")", d.file()));
            table(out, t);
        }

        out.println();
        if (rows.isEmpty()) {
            out.println(online || res.fromCache() > 0 ? "no known vulnerabilities in the checked packages" : "no vulnerability data available");
            return;
        }
        List<List<String>> t = new ArrayList<>();
        t.add(List.of("SEVERITY", "ID", "PACKAGE", "VERSION", "FIXED IN", "LINK"));
        for (Main.Row r : rows) {
            t.add(List.of(r.vuln().severity(), r.vuln().id(), r.dep().name(), r.dep().version(),
                    r.vuln().fixed().isEmpty() ? "-" : String.join(", ", r.vuln().fixed()), r.vuln().link()));
        }
        table(out, t);
        out.println();
        out.println(rows.size() + " advisories affecting " + distinctPackages(rows) + " packages");
    }

    private static int distinctPackages(List<Main.Row> rows) {
        return (int) rows.stream().map(r -> r.dep().key()).distinct().count();
    }

    private static void table(PrintStream out, List<List<String>> rows) {
        int cols = rows.get(0).size();
        int[] w = new int[cols];
        for (List<String> r : rows) for (int c = 0; c < cols - 1; c++) w[c] = Math.max(w[c], r.get(c).length());
        for (List<String> r : rows) {
            StringBuilder sb = new StringBuilder();
            for (int c = 0; c < cols; c++) {
                String cell = r.get(c);
                sb.append(cell);
                if (c < cols - 1) sb.append(" ".repeat(w[c] - cell.length() + 2));
            }
            out.println(sb);
        }
    }

    private static Map<String, Object> jsonDoc(Scanner.Scan scan, Checker.Result res, List<Main.Row> rows, boolean online,
            int unresolved, boolean inventory) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("online", online);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("manifests", (long) scan.manifests());
        summary.put("packages", (long) scan.deps().size());
        summary.put("unresolved", (long) unresolved);
        summary.put("notChecked", (long) res.unchecked().size());
        summary.put("advisories", (long) rows.size());
        doc.put("summary", summary);
        List<Object> vulns = new ArrayList<>();
        for (Main.Row r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.vuln().id());
            m.put("severity", r.vuln().severity());
            m.put("ecosystem", r.dep().ecosystem());
            m.put("package", r.dep().name());
            m.put("version", r.dep().version());
            m.put("fixed", r.vuln().fixed());
            m.put("link", r.vuln().link());
            m.put("summary", r.vuln().summary());
            m.put("files", r.files());
            vulns.add(m);
        }
        doc.put("vulnerabilities", vulns);
        if (inventory) {
            List<Object> inv = new ArrayList<>();
            for (Dep d : scan.deps()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ecosystem", d.ecosystem());
                m.put("package", d.name());
                m.put("version", d.version());
                m.put("spec", d.spec());
                m.put("file", d.file());
                inv.add(m);
            }
            doc.put("inventory", inv);
        }
        doc.put("warnings", new ArrayList<>(scan.warnings()));
        return doc;
    }
}
