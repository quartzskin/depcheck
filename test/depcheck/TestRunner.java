package depcheck;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

public final class TestRunner {
    public static void main(String[] args) throws Exception {
        List<Class<?>> classes = List.of(JsonTests.class, ParserTests.class, VulnTests.class, CacheTests.class,
                OsvTests.class, MainTests.class, VersionTests.class, GuiTests.class);
        int passed = 0;
        int failed = 0;
        for (Class<?> c : classes) {
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().startsWith("test")) continue;
                try {
                    m.invoke(c.getDeclaredConstructor().newInstance());
                    passed++;
                } catch (InvocationTargetException e) {
                    failed++;
                    System.out.println("FAIL " + c.getSimpleName() + "." + m.getName() + ": " + e.getCause());
                }
            }
        }
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0 || passed == 0) System.exit(1);
    }
}
