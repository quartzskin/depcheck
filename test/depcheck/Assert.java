package depcheck;

import java.util.Objects;

final class Assert {
    private Assert() {
    }

    static void eq(Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) throw new AssertionError("expected <" + expected + "> but was <" + actual + ">");
    }

    static void yes(boolean cond, String what) {
        if (!cond) throw new AssertionError(what);
    }

    static void throwsManifest(Runnable r) {
        try {
            r.run();
        } catch (ManifestException e) {
            return;
        }
        throw new AssertionError("expected ManifestException");
    }
}
