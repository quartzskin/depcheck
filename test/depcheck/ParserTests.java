package depcheck;

import java.util.ArrayList;
import java.util.List;

public class ParserTests {
    private static List<Dep> parse(String name, String text) {
        return Parsers.parse(name, text, name, new ArrayList<>());
    }

    private static String show(List<Dep> deps) {
        StringBuilder sb = new StringBuilder();
        for (Dep d : deps) sb.append(d.name()).append('=').append(d.version()).append(';');
        return sb.toString();
    }

    public void testRequirementsCommentsAndRanges() {
        String txt = """
                # top comment
                requests==2.19.0  # pinned
                Django>=3.0,<4
                flask[async]===1.0.2 ; python_version >= "3.8"
                numpy==1.*
                -r other.txt
                --index-url https://example.invalid/simple
                git+https://example.invalid/x.git#egg=x
                pyyaml==5.1 \\
                    --hash=sha256:abc
                """;
        Assert.eq("requests=2.19.0;Django=null;flask=1.0.2;numpy=null;pyyaml=5.1;", show(parse("requirements.txt", txt)));
    }

    public void testRequirementsGarbageLineWarnsAndContinues() {
        List<String> warnings = new ArrayList<>();
        List<Dep> deps = Parsers.parse("requirements.txt", "==1.0\nrequests==2.0.0\n", "r.txt", warnings);
        Assert.eq(1, deps.size());
        Assert.eq(1, warnings.size());
        Assert.yes(warnings.get(0).startsWith("r.txt:1:"), warnings.get(0));
    }

    public void testPackageJsonRangesAndExact() {
        String txt = "{\"dependencies\":{\"lodash\":\"4.17.15\",\"left-pad\":\"^1.0.0\",\"x\":\"=1.2.3\"},"
                + "\"devDependencies\":{\"y\":\"v2.0.0-beta.1\",\"z\":\"git+https://example.invalid/z.git\",\"w\":5}}";
        Assert.eq("lodash=4.17.15;left-pad=null;x=1.2.3;y=2.0.0-beta.1;z=null;", show(parse("package.json", txt)));
    }

    public void testPackageJsonMalformed() {
        Assert.throwsManifest(() -> parse("package.json", "{\"dependencies\": {"));
        Assert.throwsManifest(() -> parse("package.json", "[]"));
    }

    public void testPackageLockV3AndV1() {
        String v3 = "{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"},"
                + "\"node_modules/a\":{\"version\":\"1.0.0\"},"
                + "\"node_modules/a/node_modules/@s/b\":{\"version\":\"2.0.0\"},"
                + "\"node_modules/alias\":{\"name\":\"real\",\"version\":\"3.0.0\"}}}";
        Assert.eq("a=1.0.0;@s/b=2.0.0;real=3.0.0;", show(parse("package-lock.json", v3)));
        String v1 = "{\"dependencies\":{\"a\":{\"version\":\"1.0.0\",\"dependencies\":{\"b\":{\"version\":\"2.0.0\"}}}}}";
        Assert.eq("a=1.0.0;b=2.0.0;", show(parse("package-lock.json", v1)));
    }

    public void testPyprojectPep621AndPoetry() {
        String txt = """
                [project]
                name = "app"
                dependencies = [
                  "requests==2.19.0",  # old
                  "click>=8",
                ]

                [project.optional-dependencies]
                dev = ["pytest==7.0.0"]

                [tool.poetry.dependencies]
                python = "^3.9"
                flask = "2.0.1"
                jinja2 = { version = "^3.0", optional = true }
                """;
        Assert.eq("requests=2.19.0;click=null;pytest=7.0.0;flask=2.0.1;jinja2=null;", show(parse("pyproject.toml", txt)));
    }

    public void testPyprojectUnterminatedArray() {
        Assert.throwsManifest(() -> parse("pyproject.toml", "[project]\ndependencies = [\n \"a==1\",\n"));
        Assert.throwsManifest(() -> parse("pyproject.toml", "[project\n"));
    }

    public void testPomPropertiesCommentsAndRanges() {
        String txt = """
                <project>
                  <properties><junit.version>4.12</junit.version></properties>
                  <dependencies>
                    <!-- <dependency><groupId>no</groupId><artifactId>no</artifactId><version>9</version></dependency> -->
                    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>${junit.version}</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>[1.0,2.0)</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>b</artifactId><version>[1.5]</version></dependency>
                    <dependency><groupId>g</groupId><artifactId>c</artifactId></dependency>
                    <dependency><groupId>g</groupId><artifactId>d</artifactId><version>${missing}</version></dependency>
                  </dependencies>
                </project>
                """;
        Assert.eq("junit:junit=4.12;g:a=null;g:b=1.5;g:c=null;g:d=null;", show(parse("pom.xml", txt)));
    }

    public void testPomMalformed() {
        Assert.throwsManifest(() -> parse("pom.xml", "not xml"));
        Assert.throwsManifest(() -> parse("pom.xml", "<project><dependency><groupId>a</groupId>"));
    }

    public void testGradle() {
        String txt = """
                dependencies {
                    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
                    testImplementation("junit:junit:4.13.2")
                    api "com.x:y:${xVersion}"
                    runtimeOnly group: 'a.b', name: 'c', version: '1.0'
                    // implementation 'commented:out:1.0'
                    /* implementation 'block:out:1.0' */
                    implementation 'g:h:1.+'
                }
                """;
        Assert.eq("org.apache.logging.log4j:log4j-core=2.14.1;junit:junit=4.13.2;com.x:y=null;g:h=null;a.b:c=1.0;",
                show(parse("build.gradle", txt)));
    }

    public void testCargoLockSkipsPathCrates() {
        String txt = """
                version = 3

                [[package]]
                name = "app"
                version = "0.1.0"

                [[package]]
                name = "smallvec"
                version = "0.6.9"
                source = "registry+https://github.com/rust-lang/crates.io-index"
                checksum = "abc"
                """;
        Assert.eq("smallvec=0.6.9;", show(parse("Cargo.lock", txt)));
    }

    public void testCargoLockMissingVersionWarns() {
        List<String> w = new ArrayList<>();
        List<Dep> deps = Parsers.parse("Cargo.lock", "[[package]]\nname = \"x\"\n", "Cargo.lock", w);
        Assert.eq(0, deps.size());
        Assert.eq(1, w.size());
    }

    public void testGoMod() {
        String txt = """
                module example.invalid/app // comment

                go 1.21

                require golang.org/x/text v0.3.0
                require (
                    github.com/pkg/errors v0.9.1 // indirect
                    // github.com/skip/me v1.0.0
                    gopkg.in/yaml.v2 v2.2.2
                    github.com/bad
                )
                replace (
                    golang.org/x/text => ./text
                )
                """;
        List<String> w = new ArrayList<>();
        List<Dep> deps = Parsers.parse("go.mod", txt, "go.mod", w);
        Assert.eq("golang.org/x/text=0.3.0;github.com/pkg/errors=0.9.1;gopkg.in/yaml.v2=2.2.2;", show(deps));
        Assert.eq(1, w.size());
    }

    public void testGoModUnterminatedBlock() {
        Assert.throwsManifest(() -> parse("go.mod", "require (\n a.b/c v1.0.0\n"));
    }

    public void testComposerLock() {
        String txt = "{\"packages\":[{\"name\":\"monolog/monolog\",\"version\":\"v1.0.0\"},{\"name\":\"x/y\",\"version\":\"dev-master\"},"
                + "{\"name\":\"no/version\"}],\"packages-dev\":[{\"name\":\"p/q\",\"version\":\"2.1.0\"}]}";
        Assert.eq("monolog/monolog=1.0.0;x/y=null;p/q=2.1.0;", show(parse("composer.lock", txt)));
        Assert.throwsManifest(() -> parse("composer.lock", "{\"packages\": ["));
    }

    public void testEmptyFilesGiveNoDeps() {
        for (String n : Parsers.FILE_NAMES) {
            if (n.endsWith(".json") || n.equals("pom.xml") || n.endsWith(".lock") && n.startsWith("composer")) continue;
            Assert.eq(0, parse(n, "").size());
        }
    }
}
