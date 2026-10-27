package depcheck;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.imageio.ImageIO;

public class GuiTests {
    private static List<Main.Row> rows() {
        Sample s = Sample.create();
        return Main.rows(s.deps(), s.result());
    }

    private static Main.Row row(String id) {
        for (Main.Row r : rows()) if (r.vuln().id().equals(id)) return r;
        throw new AssertionError("no row " + id);
    }

    public void testSearchMatchesNameIdSeverityAndEcosystem() {
        Main.Row lodash = row("GHSA-demo-lod2");
        Assert.yes(Gui.matches(lodash, ""), "empty matches all");
        Assert.yes(Gui.matches(lodash, "  LODA "), "case and trim");
        Assert.yes(Gui.matches(lodash, "ghsa-demo-lod2"), "advisory id");
        Assert.yes(Gui.matches(lodash, "high"), "severity");
        Assert.yes(Gui.matches(lodash, "npm"), "ecosystem");
        Assert.yes(!Gui.matches(lodash, "pillow"), "other package");
        Assert.yes(!Gui.matches(lodash, "critical"), "other severity");
    }

    public void testDescribeShowsFixAndLink() {
        Main.Row r = row("GHSA-demo-l4j1");
        List<Vuln> all = Sample.create().result().vulns().get(r.dep().key());
        String text = Gui.describe(r, Versions.fixFor(r.dep().version(), all));
        Assert.yes(text.contains("GHSA-demo-l4j1  CRITICAL  CVSS 10.0"), text);
        Assert.yes(text.contains("Fixed in: 2.15.0, 2.12.2"), text);
        Assert.yes(text.contains("clears every advisory with a fix: 2.17.0"), text);
        Assert.yes(text.contains("billing/pom.xml"), text);
        Assert.yes(text.endsWith("https://osv.dev/vulnerability/GHSA-demo-l4j1"), text);
    }

    public void testDescribeWithoutSummaryOrFixedVersion() {
        Dep d = new Dep("PyPI", "pillow", "8.1.0", "8.1.0", "svc/requirements.txt");
        Vuln v = new Vuln("PYSEC-x", "UNKNOWN", 0, "", List.of());
        String text = Gui.describe(new Main.Row(v, d, List.of(d.file())), Versions.fixFor(d.version(), List.of(v)));
        Assert.yes(text.contains("No summary cached"), text);
        Assert.yes(text.contains("Fixed in: not listed"), text);
        Assert.yes(text.contains("No fixed version is listed"), text);
    }

    public void testSummaryForEmptyScans() {
        Checker.Result none = new Checker.Result(Map.of(), Set.of(), 0, 0);
        Assert.yes(Gui.summary("d", List.of(), 0, 0, none, List.of(), false).contains("no dependency manifests"), "no manifests");
        Assert.yes(Gui.summary("d", List.of(), 2, 0, none, List.of(), false).contains("no packages could be read"), "no packages");
    }

    public void testSummaryCountsSampleData() {
        Sample s = Sample.create();
        String text = Gui.summary("x", s.deps(), 4, 1, s.result(), Main.rows(s.deps(), s.result()), false);
        Assert.yes(text.contains("5 not checked"), text);
        Assert.yes(text.contains("2 version ranges skipped"), text);
        Assert.yes(text.endsWith("1 warning"), text);
    }

    public void testSnapshotWritesAPngWithRealContent() throws Exception {
        Path out = Files.createTempDirectory("depcheck-shot").resolve("sub").resolve("shot.png");
        ByteArrayOutputStream o = new ByteArrayOutputStream(), e = new ByteArrayOutputStream();
        int code = Gui.run(new String[] {"--snapshot", out.toString(), "--size", "900x640"},
                new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        Assert.eq(0, code);
        BufferedImage img = ImageIO.read(out.toFile());
        Assert.eq(900, img.getWidth());
        Assert.eq(640, img.getHeight());
        Set<Integer> colors = new HashSet<>();
        for (int y = 0; y < img.getHeight(); y++) for (int x = 0; x < img.getWidth(); x++) colors.add(img.getRGB(x, y));
        Assert.yes(colors.size() > 5, "image looks blank: " + colors.size() + " colours");
    }

    public void testGuiArgumentErrors() throws Exception {
        for (String[] args : new String[][] {{"--bogus"}, {"--snapshot"}, {"--size", "10x10"}, {"--size", "wide"},
                {"a", "b"}, {"--ttl-hours", "x"}, {Files.createTempDirectory("x").resolve("missing").toString()}}) {
            ByteArrayOutputStream e = new ByteArrayOutputStream();
            int code = Gui.run(args, new PrintStream(new ByteArrayOutputStream()), new PrintStream(e, true, StandardCharsets.UTF_8));
            Assert.eq(2, code);
            Assert.yes(e.toString(StandardCharsets.UTF_8).startsWith("depcheck gui:"), String.join(" ", args));
        }
        Assert.eq(0, Gui.run(new String[] {"--help"}, new PrintStream(new ByteArrayOutputStream()), System.err));
    }

    public void testSnapshotToUnwritablePathFails() throws Exception {
        Path dir = Files.createTempDirectory("depcheck-shot");
        Files.writeString(dir.resolve("keep.txt"), "x");
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = Gui.run(new String[] {"--snapshot", dir.toString()}, new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(e, true, StandardCharsets.UTF_8));
        Assert.eq(2, code);
    }
}
