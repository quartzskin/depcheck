package depcheck;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
    private static final int MAX_DEPTH = 200;

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != text.length()) throw p.err("trailing data");
        return v;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> ? (Map<String, Object>) o : Map.of();
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object o) {
        return o instanceof List<?> ? (List<Object>) o : List.of();
    }

    static String asString(Object o) {
        return o instanceof String str ? str : null;
    }

    private ManifestException err(String msg) {
        return new ManifestException("invalid JSON at offset " + i + ": " + msg);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\uFEFF') i++;
            else break;
        }
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) throw err("nested too deeply");
        if (i >= s.length()) throw err("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': return object(depth);
            case '[': return array(depth);
            case '"': return string();
            case 't': return literal("true", Boolean.TRUE);
            case 'f': return literal("false", Boolean.FALSE);
            case 'n': return literal("null", null);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw err("unexpected '" + c + "'");
        }
    }

    private Object literal(String word, Object v) {
        if (!s.startsWith(word, i)) throw err("bad literal");
        i += word.length();
        return v;
    }

    private Object number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String n = s.substring(start, i);
        try {
            if (n.indexOf('.') < 0 && n.indexOf('e') < 0 && n.indexOf('E') < 0) return Long.parseLong(n);
            return Double.parseDouble(n);
        } catch (NumberFormatException e) {
            throw err("bad number '" + n + "'");
        }
    }

    private String string() {
        i++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw err("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c < 0x20) throw err("control character in string");
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (i >= s.length()) throw err("unterminated escape");
            char e = s.charAt(i++);
            switch (e) {
                case '"', '\\', '/' -> sb.append(e);
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (i + 4 > s.length()) throw err("short \\u escape");
                    try {
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw err("bad \\u escape");
                    }
                    i += 4;
                }
                default -> throw err("bad escape \\" + e);
            }
        }
    }

    private List<Object> array(int depth) {
        i++;
        List<Object> out = new ArrayList<>();
        ws();
        if (i < s.length() && s.charAt(i) == ']') {
            i++;
            return out;
        }
        while (true) {
            ws();
            out.add(value(depth + 1));
            ws();
            if (i >= s.length()) throw err("unterminated array");
            char c = s.charAt(i++);
            if (c == ']') return out;
            if (c != ',') throw err("expected ',' or ']'");
        }
    }

    private Map<String, Object> object(int depth) {
        i++;
        Map<String, Object> out = new LinkedHashMap<>();
        ws();
        if (i < s.length() && s.charAt(i) == '}') {
            i++;
            return out;
        }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') throw err("expected string key");
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
            i++;
            ws();
            out.put(k, value(depth + 1));
            ws();
            if (i >= s.length()) throw err("unterminated object");
            char c = s.charAt(i++);
            if (c == '}') return out;
            if (c != ',') throw err("expected ',' or '}'");
        }
    }

    static String write(Object o) {
        StringBuilder sb = new StringBuilder();
        write(sb, o, 0);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object o, int indent) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String str) {
            quote(sb, str);
        } else if (o instanceof Map<?, ?> m) {
            if (m.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            int n = 0;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                pad(sb, indent + 1);
                quote(sb, String.valueOf(e.getKey()));
                sb.append(": ");
                write(sb, e.getValue(), indent + 1);
                sb.append(++n < m.size() ? ",\n" : "\n");
            }
            pad(sb, indent);
            sb.append('}');
        } else if (o instanceof List<?> l) {
            if (l.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            for (int k = 0; k < l.size(); k++) {
                pad(sb, indent + 1);
                write(sb, l.get(k), indent + 1);
                sb.append(k + 1 < l.size() ? ",\n" : "\n");
            }
            pad(sb, indent);
            sb.append(']');
        } else {
            sb.append(o);
        }
    }

    private static void pad(StringBuilder sb, int n) {
        sb.append("  ".repeat(n));
    }

    private static void quote(StringBuilder sb, String str) {
        sb.append('"');
        for (int k = 0; k < str.length(); k++) {
            char c = str.charAt(k);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
