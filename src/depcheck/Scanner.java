package depcheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class Scanner {
    private static final Set<String> SKIP_DIRS = Set.of(".git", "node_modules", "target", "build", ".venv", "venv",
            "__pycache__", ".gradle", ".idea", "vendor");
    private static final long MAX_BYTES = 32L << 20;

    record Scan(List<Dep> deps, int manifests, List<String> warnings) {
    }

    private Scanner() {
    }

    static Scan scan(Path root) throws IOException {
        List<Dep> deps = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int[] manifests = {0};
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes a) {
                if (!dir.equals(root) && SKIP_DIRS.contains(dir.getFileName().toString())) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                String name = f.getFileName().toString();
                if (!a.isRegularFile() || !Parsers.supports(name)) return FileVisitResult.CONTINUE;
                String rel = root.relativize(f).toString().replace('\\', '/');
                manifests[0]++;
                if (a.size() > MAX_BYTES) {
                    warnings.add(rel + ": skipped, file is larger than 32 MB");
                    return FileVisitResult.CONTINUE;
                }
                try {
                    String text = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
                    deps.addAll(Parsers.parse(name, text, rel, warnings));
                } catch (ManifestException e) {
                    warnings.add(rel + ": " + e.getMessage());
                } catch (IOException e) {
                    warnings.add(rel + ": cannot read (" + e.getMessage() + ")");
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path f, IOException e) {
                warnings.add(root.relativize(f).toString().replace('\\', '/') + ": " + e.getMessage());
                return FileVisitResult.CONTINUE;
            }
        });
        return new Scan(deps, manifests[0], warnings);
    }
}
