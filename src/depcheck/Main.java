package depcheck;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Main {
    private static final String USAGE = """
            usage: depcheck [path] [options]
                   depcheck gui [path] [options]    (window; see depcheck gui --help)

            Scans path (default .) for dependency manifests and lock files and lists the packages.
            Nothing leaves the machine unless --online is given.

              --online           query OSV.dev (api.osv.dev) for the exact versions found
              --cache-dir DIR    where OSV answers are cached (default ~/.depcheck-cache)
              --ttl-hours N      cache entry lifetime in hours (default 24)
              --inventory        also list every package found (always on without --online)
              --json             machine-readable output
              --osv-url URL      OSV API base URL (default https://api.osv.dev)

            exit status: 0 nothing known, 1 vulnerable packages found, 2 usage or network error
            """;

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length > 0 && args[0].equals("gui")) {
            int code = Gui.run(Arrays.copyOfRange(args, 1, args.length), System.out, System.err);
            if (code >= 0) System.exit(code);
            return;
        }
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String path = null;
        boolean online = false, json = false, inventory = false;
        Path cacheDir = Path.of(System.getProperty("user.home"), ".depcheck-cache");
        long ttlHours = 24;
        String osvUrl = "https://api.osv.dev";
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--online" -> online = true;
                    case "--json" -> json = true;
                    case "--inventory" -> inventory = true;
                    case "--cache-dir" -> cacheDir = Path.of(value(args, ++i));
                    case "--osv-url" -> osvUrl = value(args, ++i);
                    case "--ttl-hours" -> ttlHours = Long.parseLong(value(args, ++i));
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    default -> {
                        if (args[i].startsWith("-")) throw new IllegalArgumentException("unknown option " + args[i]);
                        if (path != null) throw new IllegalArgumentException("only one path is accepted");
                        path = args[i];
                    }
                }
            }
            if (ttlHours < 0) throw new IllegalArgumentException("--ttl-hours must not be negative");
        } catch (IllegalArgumentException e) {
            err.println("depcheck: " + (e instanceof NumberFormatException ? "bad number for --ttl-hours" : e.getMessage()));
            err.print(USAGE);
            return 2;
        }

        Path root = Path.of(path == null ? "." : path);
        if (!Files.isDirectory(root)) {
            err.println("depcheck: not a directory: " + root);
            return 2;
        }

        try {
            Scanner.Scan scan = Scanner.scan(root);
            Cache cache = new Cache(cacheDir, ttlHours * 3600, () -> System.currentTimeMillis() / 1000);
            Checker.Result res;
            try {
                res = Checker.check(scan.deps(), cache, online ? new OsvClient(osvUrl) : null);
            } finally {
                if (online) saveQuietly(cache, err);
            }
            List<Row> rows = rows(scan.deps(), res);
            Report.print(out, scan, res, rows, online, json, inventory || !online);
            for (String w : scan.warnings()) err.println("warning: " + w);
            return rows.isEmpty() ? 0 : 1;
        } catch (IOException e) {
            err.println("depcheck: " + e.getMessage());
            return 2;
        }
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) throw new IllegalArgumentException(args[i - 1] + " needs a value");
        return args[i];
    }

    private static void saveQuietly(Cache cache, PrintStream err) {
        try {
            cache.save();
        } catch (IOException e) {
            err.println("warning: could not write cache: " + e.getMessage());
        }
    }

    record Row(Vuln vuln, Dep dep, List<String> files) {
    }

    static List<Row> rows(List<Dep> deps, Checker.Result res) {
        Map<String, Row> byKeyAndId = new LinkedHashMap<>();
        for (Dep d : deps) {
            if (d.version() == null) continue;
            for (Vuln v : res.vulns().getOrDefault(d.key(), List.of())) {
                Row r = byKeyAndId.computeIfAbsent(d.key() + "#" + v.id(), k -> new Row(v, d, new ArrayList<>()));
                if (!r.files().contains(d.file())) r.files().add(d.file());
            }
        }
        List<Row> rows = new ArrayList<>(byKeyAndId.values());
        rows.sort(Comparator.<Row>comparingInt(r -> Vuln.rank(r.vuln().severity()))
                .thenComparing(r -> -r.vuln().score())
                .thenComparing(r -> r.dep().name())
                .thenComparing(r -> r.vuln().id()));
        return rows;
    }
}
