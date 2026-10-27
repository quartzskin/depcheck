package depcheck;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Parsers {
    static final Set<String> FILE_NAMES = Set.of("package.json", "package-lock.json", "requirements.txt",
            "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.lock", "go.mod", "composer.lock");

    private static final Pattern VERSION = Pattern.compile("^\\d+(\\.[0-9A-Za-z]+)*([-+][0-9A-Za-z.+-]+)?$");
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"|'([^']*)'");

    private Parsers() {
    }

    static boolean supports(String fileName) {
        return FILE_NAMES.contains(fileName);
    }

    static List<Dep> parse(String fileName, String text, String file, List<String> warnings) {
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        return switch (fileName) {
            case "package.json" -> packageJson(text, file);
            case "package-lock.json" -> packageLock(text, file);
            case "requirements.txt" -> requirements(text, file, warnings);
            case "pyproject.toml" -> pyproject(text, file, warnings);
            case "pom.xml" -> pom(text, file);
            case "build.gradle", "build.gradle.kts" -> gradle(text, file);
            case "Cargo.lock" -> cargoLock(text, file, warnings);
            case "go.mod" -> goMod(text, file, warnings);
            case "composer.lock" -> composerLock(text, file);
            default -> throw new ManifestException("unsupported file " + fileName);
        };
    }

    static boolean isVersion(String v) {
        return v != null && VERSION.matcher(v).matches();
    }

    private static Dep dep(String eco, String name, String ver, String file) {
        return new Dep(eco, name, isVersion(ver) ? ver : null, ver, file);
    }

    private static Map<String, Object> jsonRoot(String text) {
        Object root = Json.parse(text);
        if (!(root instanceof Map)) throw new ManifestException("expected a JSON object at top level");
        return Json.asMap(root);
    }

    private static List<Dep> packageJson(String text, String file) {
        Map<String, Object> root = jsonRoot(text);
        List<Dep> out = new ArrayList<>();
        for (String section : List.of("dependencies", "devDependencies", "optionalDependencies")) {
            for (Map.Entry<String, Object> e : Json.asMap(root.get(section)).entrySet()) {
                String spec = Json.asString(e.getValue());
                if (spec == null) continue;
                String v = spec.trim();
                if (v.startsWith("=")) v = v.substring(1).trim();
                if (v.startsWith("v")) v = v.substring(1);
                out.add(new Dep("npm", e.getKey(), isVersion(v) ? v : null, spec, file));
            }
        }
        return out;
    }

    private static List<Dep> packageLock(String text, String file) {
        Map<String, Object> root = jsonRoot(text);
        List<Dep> out = new ArrayList<>();
        Map<String, Object> packages = Json.asMap(root.get("packages"));
        if (!packages.isEmpty()) {
            for (Map.Entry<String, Object> e : packages.entrySet()) {
                String path = e.getKey();
                int at = path.lastIndexOf("node_modules/");
                if (at < 0) continue;
                Map<String, Object> p = Json.asMap(e.getValue());
                String name = Json.asString(p.get("name"));
                if (name == null) name = path.substring(at + 13);
                String ver = Json.asString(p.get("version"));
                if (ver != null) out.add(dep("npm", name, ver, file));
            }
        } else {
            lockV1(Json.asMap(root.get("dependencies")), out, file, 0);
        }
        return out;
    }

    private static void lockV1(Map<String, Object> deps, List<Dep> out, String file, int depth) {
        if (depth > 50) return;
        for (Map.Entry<String, Object> e : deps.entrySet()) {
            Map<String, Object> d = Json.asMap(e.getValue());
            String ver = Json.asString(d.get("version"));
            if (ver != null) out.add(dep("npm", e.getKey(), ver, file));
            lockV1(Json.asMap(d.get("dependencies")), out, file, depth + 1);
        }
    }

    private static List<Dep> composerLock(String text, String file) {
        Map<String, Object> root = jsonRoot(text);
        List<Dep> out = new ArrayList<>();
        for (String section : List.of("packages", "packages-dev")) {
            for (Object o : Json.asList(root.get(section))) {
                Map<String, Object> p = Json.asMap(o);
                String name = Json.asString(p.get("name"));
                String ver = Json.asString(p.get("version"));
                if (name == null || ver == null) continue;
                out.add(dep("Packagist", name, ver.startsWith("v") ? ver.substring(1) : ver, file));
            }
        }
        return out;
    }

    private static final Pattern REQ = Pattern.compile("^([A-Za-z0-9][A-Za-z0-9._-]*)\\s*(?:\\[[^\\]]*\\])?\\s*(.*)$");
    private static final Pattern PIN = Pattern.compile("^===?\\s*([^\\s,*]+)$");

    private static Dep requirement(String req, String file) {
        int semi = req.indexOf(';');
        if (semi >= 0) req = req.substring(0, semi);
        req = req.trim();
        Matcher m = REQ.matcher(req);
        if (!m.matches()) return null;
        String rest = m.group(2).trim();
        if (rest.startsWith("(") && rest.endsWith(")")) rest = rest.substring(1, rest.length() - 1).trim();
        Matcher pin = PIN.matcher(rest);
        String ver = pin.matches() ? pin.group(1) : null;
        if (!isVersion(ver)) ver = null;
        return new Dep("PyPI", m.group(1), ver, rest, file);
    }

    private static List<Dep> requirements(String text, String file, List<String> warnings) {
        List<Dep> out = new ArrayList<>();
        int n = 0;
        for (String raw : text.split("\\R")) {
            n++;
            String line = raw;
            Matcher c = Pattern.compile("(^|\\s)#").matcher(line);
            if (c.find()) line = line.substring(0, c.start());
            line = line.trim();
            if (line.endsWith("\\")) line = line.substring(0, line.length() - 1).trim();
            int hash = line.indexOf(" --");
            if (hash >= 0) line = line.substring(0, hash).trim();
            if (line.isEmpty() || line.startsWith("-") || line.contains("://")) continue;
            Dep d = requirement(line, file);
            if (d == null) warnings.add(file + ":" + n + ": cannot parse requirement '" + line + "'");
            else out.add(d);
        }
        return out;
    }

    private static String stripTomlComment(String line) {
        boolean dq = false, sq = false;
        for (int k = 0; k < line.length(); k++) {
            char ch = line.charAt(k);
            if (ch == '"' && !sq) dq = !dq;
            else if (ch == '\'' && !dq) sq = !sq;
            else if (ch == '#' && !dq && !sq) return line.substring(0, k);
        }
        return line;
    }

    private static List<Dep> pyproject(String text, String file, List<String> warnings) {
        List<Dep> out = new ArrayList<>();
        String section = "";
        boolean collecting = false;
        Pattern arrayStart = Pattern.compile("^(?:dependencies|[A-Za-z0-9_.-]+)\\s*=\\s*\\[(.*)$");
        Pattern kv = Pattern.compile("^([A-Za-z0-9_.-]+)\\s*=\\s*(.*)$");
        for (String raw : text.split("\\R")) {
            String line = stripTomlComment(raw).trim();
            if (line.isEmpty()) continue;
            if (!collecting && line.startsWith("[")) {
                if (!line.endsWith("]")) throw new ManifestException("malformed table header '" + line + "'");
                section = line.replaceAll("^\\[+|\\]+$", "").trim();
                continue;
            }
            if (collecting) {
                addQuoted(line, out, file);
                if (QUOTED.matcher(line).replaceAll("").contains("]")) collecting = false;
                continue;
            }
            boolean pep621 = section.equals("project") || section.equals("project.optional-dependencies");
            Matcher a = arrayStart.matcher(line);
            if (pep621 && a.matches() && (section.endsWith("optional-dependencies") || line.startsWith("dependencies"))) {
                String rest = a.group(1);
                addQuoted(rest, out, file);
                collecting = !QUOTED.matcher(rest).replaceAll("").contains("]");
                continue;
            }
            boolean poetry = section.equals("tool.poetry.dependencies") || section.equals("tool.poetry.dev-dependencies")
                    || section.matches("tool\\.poetry\\.group\\.[^.]+\\.dependencies");
            Matcher m = kv.matcher(line);
            if (poetry && m.matches() && !m.group(1).equals("python")) {
                String val = m.group(2).trim();
                String spec = null;
                if (val.startsWith("{")) {
                    Matcher vm = Pattern.compile("version\\s*=\\s*[\"']([^\"']*)[\"']").matcher(val);
                    if (vm.find()) spec = vm.group(1);
                } else {
                    Matcher q = QUOTED.matcher(val);
                    if (q.find()) spec = q.group(1) != null ? q.group(1) : q.group(2);
                }
                if (spec == null) {
                    warnings.add(file + ": no version for poetry dependency " + m.group(1));
                    continue;
                }
                String v = spec.startsWith("==") ? spec.substring(2).trim() : spec;
                out.add(new Dep("PyPI", m.group(1), isVersion(v) ? v : null, spec, file));
            }
        }
        if (collecting) throw new ManifestException("unterminated dependency array");
        return out;
    }

    private static void addQuoted(String line, List<Dep> out, String file) {
        Matcher q = QUOTED.matcher(line);
        while (q.find()) {
            Dep d = requirement(q.group(1) != null ? q.group(1) : q.group(2), file);
            if (d != null) out.add(d);
        }
    }

    private static List<Dep> pom(String text, String file) {
        String xml = text.replaceAll("(?s)<!--.*?-->", "");
        if (!xml.contains("<project")) throw new ManifestException("no <project> element");
        if (count(xml, "<dependency>") != count(xml, "</dependency>"))
            throw new ManifestException("unbalanced <dependency> tags");
        Map<String, String> props = new HashMap<>();
        Matcher pb = Pattern.compile("(?s)<properties>(.*?)</properties>").matcher(xml);
        while (pb.find()) {
            Matcher kv = Pattern.compile("<([\\w.\\-]+)>([^<]*)</\\1>").matcher(pb.group(1));
            while (kv.find()) props.put(kv.group(1), kv.group(2).trim());
        }
        List<Dep> out = new ArrayList<>();
        Matcher d = Pattern.compile("(?s)<dependency>(.*?)</dependency>").matcher(xml);
        while (d.find()) {
            String g = subst(tag(d.group(1), "groupId"), props);
            String a = subst(tag(d.group(1), "artifactId"), props);
            String v = subst(tag(d.group(1), "version"), props);
            if (g == null || a == null) continue;
            String ver = v;
            Matcher exact = v == null ? null : Pattern.compile("^\\[([^,\\]\\[()]+)]$").matcher(v);
            if (exact != null && exact.matches()) ver = exact.group(1).trim();
            out.add(new Dep("Maven", g + ":" + a, isVersion(ver) ? ver : null, v == null ? "" : v, file));
        }
        return out;
    }

    private static int count(String s, String needle) {
        int n = 0;
        for (int k = s.indexOf(needle); k >= 0; k = s.indexOf(needle, k + 1)) n++;
        return n;
    }

    private static String tag(String block, String name) {
        Matcher m = Pattern.compile("<" + name + ">\\s*([^<]*?)\\s*</" + name + ">").matcher(block);
        return m.find() ? m.group(1) : null;
    }

    private static String subst(String v, Map<String, String> props) {
        if (v == null) return null;
        Matcher m = Pattern.compile("\\$\\{([^}]+)}").matcher(v);
        StringBuilder sb = new StringBuilder();
        while (m.find()) m.appendReplacement(sb, Matcher.quoteReplacement(props.getOrDefault(m.group(1), m.group())));
        m.appendTail(sb);
        return sb.toString();
    }

    private static final Pattern GRADLE_NOTATION = Pattern.compile("[\"']([\\w.\\-]+):([\\w.\\-]+):([^\"'\\s:@]+)(?::[\\w.\\-]+)?(?:@\\w+)?[\"']");
    private static final Pattern GRADLE_MAP = Pattern.compile(
            "group\\s*[:=]\\s*[\"']([\\w.\\-]+)[\"']\\s*,\\s*name\\s*[:=]\\s*[\"']([\\w.\\-]+)[\"']\\s*,\\s*version\\s*[:=]\\s*[\"']([^\"']+)[\"']");

    private static List<Dep> gradle(String text, String file) {
        String src = text.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("(?m)//.*$", "");
        List<Dep> out = new ArrayList<>();
        Matcher m = GRADLE_NOTATION.matcher(src);
        while (m.find()) out.add(gradleDep(m.group(1), m.group(2), m.group(3), file));
        m = GRADLE_MAP.matcher(src);
        while (m.find()) out.add(gradleDep(m.group(1), m.group(2), m.group(3), file));
        return out;
    }

    private static Dep gradleDep(String g, String a, String v, String file) {
        return new Dep("Maven", g + ":" + a, isVersion(v) ? v : null, v, file);
    }

    private static String tomlString(String line) {
        Matcher q = QUOTED.matcher(line);
        if (!q.find()) return null;
        return q.group(1) != null ? q.group(1) : q.group(2);
    }

    private static List<Dep> cargoLock(String text, String file, List<String> warnings) {
        List<Dep> out = new ArrayList<>();
        String name = null, ver = null, source = null;
        boolean in = false;
        for (String raw : (text + "\n[[package]]").split("\\R")) {
            String line = stripTomlComment(raw).trim();
            if (line.equals("[[package]]")) {
                if (in && name != null) {
                    if (ver == null) warnings.add(file + ": package " + name + " has no version");
                    else if (source != null) out.add(dep("crates.io", name, ver, file));
                }
                name = ver = source = null;
                in = true;
            } else if (in && line.startsWith("name")) {
                name = tomlString(line);
            } else if (in && line.startsWith("version")) {
                ver = tomlString(line);
            } else if (in && line.startsWith("source")) {
                source = tomlString(line);
            }
        }
        return out;
    }

    private static List<Dep> goMod(String text, String file, List<String> warnings) {
        List<Dep> out = new ArrayList<>();
        boolean inRequire = false, inOther = false;
        int n = 0;
        for (String raw : text.split("\\R")) {
            n++;
            String line = raw;
            int c = line.indexOf("//");
            if (c >= 0) line = line.substring(0, c);
            line = line.trim();
            if (line.isEmpty()) continue;
            if (inRequire || inOther) {
                if (line.equals(")")) {
                    inRequire = inOther = false;
                } else if (inRequire) {
                    goRequire(line, file, n, out, warnings);
                }
                continue;
            }
            if (line.matches("require\\s*\\(")) {
                inRequire = true;
            } else if (line.matches("(replace|exclude|retract)\\s*\\(")) {
                inOther = true;
            } else if (line.startsWith("require ") || line.startsWith("require\t")) {
                goRequire(line.substring(8).trim(), file, n, out, warnings);
            }
        }
        if (inRequire || inOther) throw new ManifestException("unterminated block");
        return out;
    }

    private static void goRequire(String line, String file, int n, List<Dep> out, List<String> warnings) {
        String[] t = line.split("\\s+");
        if (t.length != 2 || !t[1].startsWith("v")) {
            warnings.add(file + ":" + n + ": cannot parse require '" + line + "'");
            return;
        }
        String v = t[1].substring(1).replace("+incompatible", "");
        out.add(new Dep("Go", t[0], isVersion(v) ? v : null, t[1], file));
    }
}
