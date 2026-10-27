package depcheck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class CacheTests {
    public void testEntryExpiresAfterTtl() throws IOException {
        Path dir = Files.createTempDirectory("depcheck-cache");
        AtomicLong now = new AtomicLong(1_000_000);
        Cache c = new Cache(dir, 3600, now::get);
        c.putIds("npm|a|1", List.of("ID-1"));
        c.putVuln("ID-1", Map.of("summary", "s"));
        c.save();

        now.set(1_000_000 + 3600);
        Cache same = new Cache(dir, 3600, now::get);
        Assert.eq(List.of("ID-1"), same.ids("npm|a|1").orElseThrow());
        Assert.eq("s", same.vuln("ID-1").get("summary"));

        now.set(1_000_000 + 3601);
        Assert.yes(same.ids("npm|a|1").isEmpty(), "ids should have expired");
        Assert.eq(null, same.vuln("ID-1"));
    }

    public void testEmptyAnswerIsCachedToo() throws IOException {
        Path dir = Files.createTempDirectory("depcheck-cache");
        Cache c = new Cache(dir, 60, () -> 5L);
        c.putIds("npm|clean|1", List.of());
        c.save();
        Assert.eq(List.of(), new Cache(dir, 60, () -> 5L).ids("npm|clean|1").orElseThrow());
    }

    public void testCorruptFileIsTreatedAsEmpty() throws IOException {
        Path dir = Files.createTempDirectory("depcheck-cache");
        Files.writeString(dir.resolve(Cache.FILE_NAME), "{not json");
        Cache c = new Cache(dir, 60, () -> 5L);
        Assert.yes(c.ids("anything").isEmpty(), "corrupt cache must not yield hits");
        c.putIds("k", List.of("A"));
        c.save();
        Assert.eq(List.of("A"), new Cache(dir, 60, () -> 5L).ids("k").orElseThrow());
    }

    public void testMissingDirIsCreatedOnSave() throws IOException {
        Path dir = Files.createTempDirectory("depcheck-cache").resolve("a").resolve("b");
        Cache c = new Cache(dir, 60, () -> 5L);
        c.save();
        Assert.yes(Files.isRegularFile(dir.resolve(Cache.FILE_NAME)), "cache file written");
    }
}
