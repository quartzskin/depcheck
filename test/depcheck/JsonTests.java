package depcheck;

import java.util.List;
import java.util.Map;

public class JsonTests {
    public void testRoundTrip() {
        Object o = Json.parse("{\"a\": [1, 2.5, \"x\\n\\u0041\", true, null], \"b\": {}}");
        Object again = Json.parse(Json.write(o));
        Assert.eq(o, again);
        Assert.eq(List.of(1L, 2.5, "x\nA", true), Json.asList(Json.asMap(o).get("a")).subList(0, 4));
    }

    public void testMalformed() {
        for (String bad : List.of("", "{", "[1,", "{\"a\" 1}", "{\"a\":1,}", "\"abc", "[1] x", "tru", "{1:2}", "[\"\\q\"]", "-")) {
            Assert.throwsManifest(() -> Json.parse(bad));
        }
    }

    public void testDeepNestingIsRejectedNotStackOverflow() {
        Assert.throwsManifest(() -> Json.parse("[".repeat(5000)));
    }

    public void testBomIsIgnored() {
        Assert.eq(Map.of(), Json.parse("\uFEFF{}"));
    }
}
