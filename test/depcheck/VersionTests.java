package depcheck;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class VersionTests {
    private static Vuln vuln(String id, String sev, String... fixed) {
        return new Vuln(id, sev, 0, "", List.of(fixed));
    }

    public void testVersionOrdering() {
        Assert.yes(Versions.compare("4.17.15", "4.17.21") < 0, "patch");
        Assert.yes(Versions.compare("1.9", "1.10") < 0, "numeric not lexical");
        Assert.yes(Versions.compare("2.0", "2.0.0") == 0, "trailing zero");
        Assert.yes(Versions.compare("1.0.0-rc1", "1.0.0") < 0, "prerelease is older");
        Assert.yes(Versions.compare("v1.2.3", "1.2.3") == 0, "leading v");
        Assert.yes(Versions.compare("32.1.3-jre", "32.1.2-jre") > 0, "qualifier suffix");
    }

    public void testFixPicksSmallestAboveCurrentThenHighestAcrossAdvisories() {
        List<Vuln> vs = List.of(vuln("A", "HIGH", "1.2.6", "2.0.1"), vuln("B", "LOW", "1.2.9"), vuln("C", "LOW"),
                vuln("D", "LOW", "1.0.0"));
        Versions.Fix fix = Versions.fixFor("1.2.5", vs);
        Assert.eq("1.2.9", fix.target());
        Assert.eq(2, fix.unfixable());
        Assert.eq(null, Versions.fixFor("1.0", List.of(vuln("X", "LOW"))).target());
    }

    public void testSharedPrefixCutsAtSegmentBoundary() {
        Assert.eq(5, Versions.sharedPrefix("4.17.15", "4.17.21"));
        Assert.eq(5, Versions.sharedPrefix("4.17.15", "4.17.151"));
        Assert.eq(0, Versions.sharedPrefix("1.2.3", "2.2.3"));
        Assert.eq(5, Versions.sharedPrefix("1.2.3", "1.2.3"));
    }

    public void testSampleRowsAreSortedWorstFirst() {
        Sample s = Sample.create();
        List<Main.Row> rows = Main.rows(s.deps(), s.result());
        Assert.eq("CRITICAL", rows.get(0).vuln().severity());
        int prev = -1;
        for (Main.Row r : rows) {
            Assert.yes(Vuln.rank(r.vuln().severity()) >= prev, "severity order at " + r.vuln().id());
            prev = Vuln.rank(r.vuln().severity());
        }
        int expected = 0;
        for (List<Vuln> l : s.result().vulns().values()) expected += l.size();
        Assert.eq(expected, rows.size());
    }

    public void testSamePackageInTwoFilesIsOneRowWithBothFiles() {
        Dep a = new Dep("npm", "lodash", "4.17.15", "4.17.15", "web/package.json");
        Dep b = new Dep("npm", "lodash", "4.17.15", "4.17.15", "web/package-lock.json");
        Checker.Result res = new Checker.Result(Map.of(a.key(), List.of(vuln("X-1", "HIGH", "4.17.21"))), Set.of(), 0, 0);
        List<Main.Row> rows = Main.rows(List.of(a, b), res);
        Assert.eq(1, rows.size());
        Assert.eq(List.of("web/package.json", "web/package-lock.json"), rows.get(0).files());
    }
}
