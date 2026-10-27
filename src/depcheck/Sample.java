package depcheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Invented projects and advisories for --snapshot and tests. Nothing here comes from a real machine or from OSV. */
final class Sample {
    private final List<Dep> deps = new ArrayList<>();
    private final Map<String, List<Vuln>> vulns = new LinkedHashMap<>();
    private final Set<String> unchecked = new LinkedHashSet<>();

    private Sample() {
    }

    static Sample create() {
        Sample s = new Sample();
        for (String n : List.of("react 18.2.0", "react-dom 18.2.0", "left-pad 1.3.0", "webpack 5.88.0", "typescript 5.3.3",
                "chalk 5.3.0", "dayjs 1.11.10", "zod 3.22.4", "vite 5.0.8", "@types/node 20.10.0", "ms 2.1.3"))
            s.dep("npm", n.split(" ")[0], n.split(" ")[1], "web/package.json");
        s.dep("npm", "lodash", "4.17.15", "web/package.json").add("lodash", "4.17.15", "npm",
                v("GHSA-demo-lod1", "HIGH", 7.4, "Prototype pollution in a deep merge helper lets crafted input change Object.prototype.", "4.17.21"),
                v("GHSA-demo-lod2", "HIGH", 7.2, "Command injection through a template option that reaches Function().", "4.17.21"),
                v("GHSA-demo-lod3", "MEDIUM", 5.3, "Regular expression denial of service in a trimming helper.", "4.17.21"));
        s.dep("npm", "express", "4.17.1", "web/package.json").add("express", "4.17.1", "npm",
                v("GHSA-demo-exp1", "MEDIUM", 6.1, "Open redirect when the redirect target contains encoded characters.", "4.19.2"),
                v("GHSA-demo-exp2", "LOW", 3.7, "Query parser accepts an unbounded number of array entries.", "4.17.3", "4.18.2"));
        s.dep("npm", "axios", "0.21.1", "web/package.json").add("axios", "0.21.1", "npm",
                v("GHSA-demo-axi1", "HIGH", 7.5, "Credentials are forwarded to a different host after a cross-origin redirect.", "0.21.2", "1.6.0"),
                v("GHSA-demo-axi2", "MEDIUM", 5.9, "Inefficient regular expression in URL handling.", "0.21.2"));
        s.dep("npm", "minimist", "1.2.5", "web/package.json").add("minimist", "1.2.5", "npm",
                v("GHSA-demo-min1", "CRITICAL", 9.8, "Prototype pollution through crafted argument names.", "1.2.6"));
        s.dep("npm", "moment", "2.29.1", "web/package.json").add("moment", "2.29.1", "npm",
                v("GHSA-demo-mom1", "HIGH", 7.5, "Path traversal in locale loading.", "2.29.2"),
                v("GHSA-demo-mom2", "HIGH", 7.5, "Slow parsing of very long date strings.", "2.29.4"));
        s.dep("npm", "uuid", "8.3.2", "web/package.json");
        s.dep("npm", "ws", "7.4.5", "web/package.json").add("ws", "7.4.5", "npm",
                v("GHSA-demo-ws01", "HIGH", 7.5, "A request with many headers can crash the server.", "7.5.10"));

        s.dep("npm", "next", "13.4.0", "admin/package.json").add("next", "13.4.0", "npm",
                v("GHSA-demo-nxt1", "CRITICAL", 9.1, "Authorization bypass in middleware for crafted request headers.", "13.5.9", "14.2.25"),
                v("GHSA-demo-nxt2", "MEDIUM", 5.3, "Cache poisoning of a data route.", "13.5.1"));
        s.dep("npm", "jsonwebtoken", "8.5.1", "admin/package.json").add("jsonwebtoken", "8.5.1", "npm",
                v("GHSA-demo-jwt1", "HIGH", 7.6, "Weak key types are accepted when verifying a token.", "9.0.0"),
                v("GHSA-demo-jwt2", "MEDIUM", 6.4, "Algorithm confusion when the key is not typed.", "9.0.0"));
        s.dep("npm", "cookie", "0.4.0", "admin/package.json").add("cookie", "0.4.0", "npm",
                v("GHSA-demo-cok1", "LOW", 3.7, "Cookie names and values may contain out-of-bounds characters.", "0.7.0"));
        s.dep("npm", "bcrypt", "5.1.1", "admin/package.json");
        s.dep("npm", "tailwindcss", "3.4.0", "admin/package.json");
        s.dep("npm", "prettier", "3.1.0", "admin/package.json");
        s.deps.add(new Dep("npm", "eslint", null, "^8.0.0", "admin/package.json"));

        s.dep("PyPI", "requests", "2.19.0", "svc/requirements.txt").add("requests", "2.19.0", "PyPI",
                v("PYSEC-demo-0001", "CRITICAL", 9.8, "Session credentials are sent to an unrelated host after a redirect.", "2.20.0"),
                v("PYSEC-demo-0002", "MEDIUM", 5.6, "Certificate verification is skipped after the first request in a session.", "2.31.0"));
        s.dep("PyPI", "flask", "1.1.2", "svc/requirements.txt").add("flask", "1.1.2", "PyPI",
                v("PYSEC-demo-0003", "HIGH", 7.5, "The session cookie may be cached by a shared proxy.", "2.2.5", "2.3.2"));
        s.dep("PyPI", "jinja2", "2.11.2", "svc/requirements.txt").add("jinja2", "2.11.2", "PyPI",
                v("PYSEC-demo-0004", "MEDIUM", 5.4, "A template attribute filter can reach unsafe functions.", "2.11.3", "3.1.3"));
        s.dep("PyPI", "pyyaml", "5.3.1", "svc/requirements.txt").add("pyyaml", "5.3.1", "PyPI",
                v("PYSEC-demo-0005", "CRITICAL", 9.8, "Arbitrary code execution when loading untrusted documents with the full loader.", "5.4"));
        s.dep("PyPI", "pillow", "8.1.0", "svc/requirements.txt").add("pillow", "8.1.0", "PyPI",
                v("PYSEC-demo-0006", "HIGH", 8.1, "Out-of-bounds read while decoding a malformed image.", "8.1.1", "9.0.0"),
                v("PYSEC-demo-0007", "UNKNOWN", 0, "", "9.0.1"));
        s.dep("PyPI", "urllib3", "1.25.8", "svc/requirements.txt").add("urllib3", "1.25.8", "PyPI",
                v("PYSEC-demo-0008", "HIGH", 7.5, "CRLF injection through the request method.", "1.25.9"),
                v("PYSEC-demo-0009", "LOW", 3.1, "Proxy-Authorization header is kept on cross-host redirects.", "1.26.18"));
        for (String n : List.of("numpy 1.26.2", "click 8.1.7", "pytest 7.4.3"))
            s.dep("PyPI", n.split(" ")[0], n.split(" ")[1], "svc/requirements.txt");
        s.deps.add(new Dep("PyPI", "gunicorn", null, ">=20", "svc/requirements.txt"));

        s.dep("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "billing/pom.xml").add("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven",
                v("GHSA-demo-l4j1", "CRITICAL", 10.0, "Remote code execution through message lookups in logged text.", "2.15.0", "2.12.2"),
                v("GHSA-demo-l4j2", "HIGH", 7.5, "Denial of service from a self-referential lookup.", "2.17.0"));
        s.dep("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8", "billing/pom.xml").add("com.fasterxml.jackson.core:jackson-databind", "2.9.8", "Maven",
                v("GHSA-demo-jak1", "HIGH", 8.1, "Polymorphic deserialization reaches a gadget class.", "2.9.10.8"));
        s.dep("Maven", "org.springframework:spring-core", "5.3.18", "billing/pom.xml").add("org.springframework:spring-core", "5.3.18", "Maven",
                v("GHSA-demo-spr1", "MEDIUM", 5.9, "Denial of service when handling a crafted multipart upload.", "5.3.20"));
        s.dep("Maven", "org.slf4j:slf4j-api", "2.0.9", "billing/pom.xml");
        s.dep("Maven", "com.google.guava:guava", "32.1.3-jre", "billing/pom.xml");

        for (String n : List.of("github.com/gin-gonic/gin 1.9.1", "github.com/gorilla/mux 1.8.1", "google.golang.org/grpc 1.58.0",
                "golang.org/x/net 0.17.0", "github.com/stretchr/testify 1.8.4")) {
            s.dep("Go", n.split(" ")[0], n.split(" ")[1], "gateway/go.mod");
            s.unchecked.add(s.last.key());
        }
        return s;
    }

    private Dep last;

    private Sample dep(String eco, String name, String version, String file) {
        last = new Dep(eco, name, version, version, file);
        deps.add(last);
        return this;
    }

    private Sample add(String name, String version, String eco, Vuln... vs) {
        vulns.put(eco + "|" + name + "|" + version, List.of(vs));
        return this;
    }

    private static Vuln v(String id, String sev, double score, String summary, String... fixed) {
        return new Vuln(id, sev, score, summary, List.of(fixed));
    }

    List<Dep> deps() {
        return deps;
    }

    Checker.Result result() {
        return new Checker.Result(vulns, unchecked, deps.size() - unchecked.size(), 0);
    }
}
