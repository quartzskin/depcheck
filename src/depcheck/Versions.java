package depcheck;

import java.math.BigInteger;
import java.util.List;

final class Versions {
    private Versions() {
    }

    /** Fix for one package: the version that clears every advisory that has a fix, and how many have none. */
    record Fix(String target, int unfixable) {
    }

    static int compare(String a, String b) {
        String[] x = split(a), y = split(b);
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            if (i >= x.length) return rest(y[i]);
            if (i >= y.length) return -rest(x[i]);
            int c = segment(x[i], y[i]);
            if (c != 0) return c;
        }
        return 0;
    }

    private static String[] split(String v) {
        String s = v.startsWith("v") ? v.substring(1) : v;
        return s.split("[.\\-+_]");
    }

    /** Sign of a version that has an extra trailing segment: 1.0 vs 1.0.1 is older, 1.0 vs 1.0-rc1 is newer. */
    private static int rest(String seg) {
        if (!isNumber(seg)) return 1;
        return new BigInteger(seg).signum() == 0 ? 0 : -1;
    }

    private static int segment(String a, String b) {
        boolean na = isNumber(a), nb = isNumber(b);
        if (na && nb) return new BigInteger(a).compareTo(new BigInteger(b));
        if (na) return 1;
        if (nb) return -1;
        return a.compareToIgnoreCase(b);
    }

    private static boolean isNumber(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) if (!Character.isDigit(s.charAt(i))) return false;
        return true;
    }

    /** Smallest fixed version above current for each advisory; the target is the highest of those. */
    static Fix fixFor(String current, List<Vuln> vulns) {
        String target = null;
        int unfixable = 0;
        for (Vuln v : vulns) {
            String best = null;
            for (String f : v.fixed()) {
                if (compare(f, current) <= 0) continue;
                if (best == null || compare(f, best) < 0) best = f;
            }
            if (best == null) unfixable++;
            else if (target == null || compare(best, target) > 0) target = best;
        }
        return new Fix(target, unfixable);
    }

    /** Length of the prefix two versions share, cut back to a segment boundary so the changed segment is whole. */
    static int sharedPrefix(String a, String b) {
        int n = 0;
        while (n < a.length() && n < b.length() && a.charAt(n) == b.charAt(n)) n++;
        if (n == a.length() && n == b.length()) return n;
        boolean midSegment = n < a.length() && Character.isLetterOrDigit(a.charAt(n))
                || n < b.length() && Character.isLetterOrDigit(b.charAt(n));
        if (midSegment) while (n > 0 && Character.isLetterOrDigit(a.charAt(n - 1))) n--;
        return n;
    }
}
