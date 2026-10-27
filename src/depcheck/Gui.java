package depcheck;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.imageio.ImageIO;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

final class Gui {
    static final String USAGE = """
            usage: depcheck gui [path] [options]
            usage: depcheck gui --snapshot out.png [--size WxH]

            Opens the findings window. Online is off at start; offline, only the cache is used.

              --cache-dir DIR    where OSV answers are cached (default ~/.depcheck-cache)
              --ttl-hours N      cache entry lifetime in hours (default 24)
              --osv-url URL      OSV API base URL (default https://api.osv.dev)
              --snapshot FILE    render the window with invented sample data to a PNG and exit (works headless)
              --size WxH         snapshot size (default 1000x640)
            """;

    private static final String[] COLUMNS = {"Severity", "Package", "Version", "Advisory", "Fixed in"};

    private record Loaded(Scanner.Scan scan, Checker.Result res, List<Main.Row> rows) {
    }

    @SuppressWarnings("serial")
    private static final class FindingsModel extends AbstractTableModel {
        private List<Main.Row> rows = List.of();

        void set(List<Main.Row> r) {
            rows = r;
            fireTableDataChanged();
        }

        Main.Row row(int i) {
            return rows.get(i);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLUMNS[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            Main.Row row = rows.get(r);
            return switch (c) {
                case 0 -> row.vuln().severity();
                case 1 -> row.dep().name();
                case 2 -> row.dep().version();
                case 3 -> row.vuln().id();
                default -> fixedIn(row.vuln());
            };
        }
    }

    private final Path cacheDir;
    private final long ttlHours;
    private final String osvUrl;

    private final JPanel root = new JPanel(new BorderLayout());
    private final FindingsModel model = new FindingsModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<TableModel> sorter = new TableRowSorter<>(model);
    private final JTextArea details = new JTextArea();
    private final JButton openLink = new JButton("Open link");
    private final JTextField search = new JTextField(18);
    private final JCheckBox online = new JCheckBox("Online");
    private final JLabel status = new JLabel("Choose a folder to scan. Online is off, so advisories come from the cache only.");
    private Map<String, List<Vuln>> vulns = Map.of();
    private Path folder;
    private int generation;

    private Gui(Path cacheDir, long ttlHours, String osvUrl) {
        this.cacheDir = cacheDir;
        this.ttlHours = ttlHours;
        this.osvUrl = osvUrl;

        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(300);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setPreferredWidth(160);
        table.getColumnModel().getColumn(4).setPreferredWidth(140);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelected();
        });

        details.setEditable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        details.setBorder(new EmptyBorder(6, 6, 6, 6));
        openLink.setEnabled(false);
        openLink.addActionListener(e -> openSelectedLink());
        JPanel detailPane = new JPanel(new BorderLayout(0, 4));
        detailPane.add(new JScrollPane(details), BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(openLink);
        detailPane.add(buttons, BorderLayout.SOUTH);

        JScrollPane tablePane = new JScrollPane(table);
        tablePane.setColumnHeaderView(table.getTableHeader());
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePane, detailPane);
        split.setResizeWeight(0.7);

        status.setBorder(new EmptyBorder(3, 6, 3, 6));
        root.add(toolbar(), BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyFilter();
            }
        });
        online.setToolTipText("Sends package name, ecosystem and version to api.osv.dev. Off: cache only.");
        online.addActionListener(e -> {
            if (folder != null) scan();
            else status.setText(online.isSelected() ? "Online: packages are sent to OSV once a folder is scanned." : "Offline.");
        });
    }

    private JToolBar toolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        JButton choose = new JButton("Folder...");
        choose.addActionListener(e -> chooseFolder());
        JButton rescan = new JButton("Rescan");
        rescan.addActionListener(e -> {
            if (folder != null) scan();
        });
        bar.add(choose);
        bar.addSeparator();
        bar.add(online);
        bar.add(rescan);
        bar.addSeparator();
        bar.add(new JLabel("Search: "));
        bar.add(search);
        search.setMaximumSize(search.getPreferredSize());
        return bar;
    }

    static String fixedIn(Vuln v) {
        return v.fixed().isEmpty() ? "not listed" : String.join(", ", v.fixed());
    }

    static boolean matches(Main.Row r, String query) {
        String q = query.trim().toLowerCase(Locale.ROOT);
        if (q.isEmpty()) return true;
        return r.dep().name().toLowerCase(Locale.ROOT).contains(q) || r.vuln().id().toLowerCase(Locale.ROOT).contains(q)
                || r.vuln().severity().toLowerCase(Locale.ROOT).equals(q) || r.dep().ecosystem().toLowerCase(Locale.ROOT).contains(q);
    }

    static String describe(Main.Row r, Versions.Fix fix) {
        Vuln v = r.vuln();
        StringBuilder sb = new StringBuilder();
        sb.append(v.id()).append("  ").append(v.severity());
        if (v.score() > 0) sb.append("  CVSS ").append(v.score());
        sb.append('\n').append(r.dep().name()).append(' ').append(r.dep().version()).append(" (").append(r.dep().ecosystem()).append(")\n\n");
        sb.append(v.summary().isEmpty() ? "No summary cached for this advisory." : v.summary()).append("\n\n");
        sb.append("Fixed in: ").append(fixedIn(v)).append('\n');
        if (fix.target() != null) {
            sb.append("Version that clears every advisory with a fix: ").append(fix.target());
            if (fix.unfixable() > 0) sb.append(" (").append(fix.unfixable()).append(" more with no fixed version listed)");
            sb.append('\n');
        } else {
            sb.append("No fixed version is listed for this package's advisories.\n");
        }
        sb.append("Found in: ").append(String.join(", ", r.files())).append('\n').append(v.link());
        return sb.toString();
    }

    private void applyFilter() {
        String q = search.getText();
        sorter.setRowFilter(new RowFilter<TableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends TableModel, ? extends Integer> e) {
                return matches(model.row(e.getIdentifier()), q);
            }
        });
    }

    private Main.Row selected() {
        int v = table.getSelectedRow();
        return v < 0 ? null : model.row(table.convertRowIndexToModel(v));
    }

    private void showSelected() {
        Main.Row r = selected();
        openLink.setEnabled(r != null);
        if (r == null) {
            details.setText("");
            return;
        }
        List<Vuln> all = vulns.getOrDefault(r.dep().key(), List.of());
        details.setText(describe(r, Versions.fixFor(r.dep().version(), all)));
        details.setCaretPosition(0);
    }

    private void openSelectedLink() {
        Main.Row r = selected();
        if (r == null) return;
        try {
            if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))
                throw new UnsupportedOperationException("no default browser available");
            Desktop.getDesktop().browse(URI.create(r.vuln().link()));
        } catch (Exception ex) {
            status.setText("Could not open " + r.vuln().link() + ": " + ex.getMessage());
        }
    }

    private void chooseFolder() {
        JFileChooser fc = new JFileChooser(folder != null ? folder.toFile() : new File(System.getProperty("user.dir")));
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fc.setDialogTitle("Folder with your repos");
        if (fc.showOpenDialog(root) == JFileChooser.APPROVE_OPTION) {
            folder = fc.getSelectedFile().toPath();
            scan();
        }
    }

    private void show(List<Main.Row> rows, Map<String, List<Vuln>> v) {
        vulns = v;
        model.set(rows);
        showSelected();
    }

    private void scan() {
        Path dir = folder;
        boolean useNet = online.isSelected();
        int gen = ++generation;
        status.setText((useNet ? "Querying OSV for " : "Reading cache for ") + dir + "...");
        new SwingWorker<Loaded, Void>() {
            @Override
            protected Loaded doInBackground() throws IOException {
                Scanner.Scan sc = Scanner.scan(dir);
                Cache cache = new Cache(cacheDir, ttlHours * 3600, () -> System.currentTimeMillis() / 1000);
                Checker.Result res;
                try {
                    res = Checker.check(sc.deps(), cache, useNet ? new OsvClient(osvUrl) : null);
                } finally {
                    if (useNet) cache.save();
                }
                return new Loaded(sc, res, Main.rows(sc.deps(), res));
            }

            @Override
            protected void done() {
                if (gen != generation) return;
                try {
                    Loaded l = get();
                    show(l.rows(), l.res().vulns());
                    status.setText(summary(dir.toString(), l.scan().deps(), l.scan().manifests(), l.scan().warnings().size(), l.res(), l.rows(), useNet));
                } catch (Exception e) {
                    Throwable c = e.getCause() != null ? e.getCause() : e;
                    show(List.of(), Map.of());
                    status.setText("Scan failed: " + c.getMessage());
                }
            }
        }.execute();
    }

    static String summary(String where, List<Dep> deps, int manifests, int warnings, Checker.Result res, List<Main.Row> rows, boolean net) {
        if (manifests == 0) return where + ": no dependency manifests found.";
        if (deps.isEmpty()) return where + ": manifests found but no packages could be read from them.";
        int ranges = 0;
        for (Dep d : deps) if (d.version() == null) ranges++;
        int vulnerable = 0;
        for (Dep d : deps) if (d.version() != null && res.vulns().containsKey(d.key())) vulnerable++;
        String s = where + ": " + rows.size() + " advisories in " + vulnerable + " packages, " + res.unchecked().size() + " not checked, "
                + ranges + " version ranges skipped; "
                + (net ? res.queried() + " queried, " + res.fromCache() + " from cache" : "offline, " + res.fromCache() + " from cache");
        return warnings == 0 ? s : s + ", " + warnings + (warnings == 1 ? " warning" : " warnings");
    }

    private void loadSample() {
        Sample s = Sample.create();
        List<Main.Row> rows = Main.rows(s.deps(), s.result());
        show(rows, s.result().vulns());
        status.setText(summary("sample data (invented)", s.deps(), 4, 0, s.result(), rows, false));
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).vuln().id().equals("GHSA-demo-l4j1")) {
                int v = table.convertRowIndexToView(i);
                table.getSelectionModel().setSelectionInterval(v, v);
            }
        }
    }

    private static void layoutTree(Container c) {
        c.doLayout();
        for (java.awt.Component k : c.getComponents()) if (k instanceof Container ch) layoutTree(ch);
    }

    private static void systemLook() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // the cross-platform default is fine
        }
    }

    static void snapshot(Path file, int w, int h) throws IOException {
        systemLook();
        Gui gui = new Gui(Path.of("."), 24, "");
        gui.loadSample();
        gui.root.setSize(w, h);
        layoutTree(gui.root);
        gui.table.scrollRectToVisible(gui.table.getCellRect(gui.table.getSelectedRow(), 0, true));
        layoutTree(gui.root);
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        gui.root.printAll(g);
        g.dispose();
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        try (OutputStream os = Files.newOutputStream(file)) {
            if (!ImageIO.write(img, "png", os)) throw new IOException("no PNG writer available");
        }
    }

    /** Returns an exit code, or -1 when a window was opened and the JVM should keep running. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        String path = null, snapshot = null, osvUrl = "https://api.osv.dev";
        Path cacheDir = Path.of(System.getProperty("user.home"), ".depcheck-cache");
        long ttl = 24;
        int w = 1000, h = 640;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--snapshot" -> snapshot = value(args, ++i);
                    case "--cache-dir" -> cacheDir = Path.of(value(args, ++i));
                    case "--osv-url" -> osvUrl = value(args, ++i);
                    case "--ttl-hours" -> ttl = Long.parseLong(value(args, ++i));
                    case "--size" -> {
                        String[] wh = value(args, ++i).split("x");
                        if (wh.length != 2) throw new IllegalArgumentException("--size wants WIDTHxHEIGHT");
                        w = Integer.parseInt(wh[0]);
                        h = Integer.parseInt(wh[1]);
                        if (w < 640 || h < 400 || w > 4000 || h > 4000) throw new IllegalArgumentException("--size must be between 640x400 and 4000x4000");
                    }
                    case "-h", "--help" -> {
                        out.print(USAGE);
                        return 0;
                    }
                    default -> {
                        if (args[i].startsWith("-")) throw new IllegalArgumentException("unknown option " + args[i]);
                        if (path != null) throw new IllegalArgumentException("only one path is accepted");
                        path = args[i];
                    }
                }
            }
            if (ttl < 0) throw new IllegalArgumentException("--ttl-hours must not be negative");
        } catch (IllegalArgumentException e) {
            err.println("depcheck gui: " + (e instanceof NumberFormatException ? "bad number in options" : e.getMessage()));
            err.print(USAGE);
            return 2;
        }

        if (snapshot != null) {
            System.setProperty("java.awt.headless", "true");
            try {
                snapshot(Path.of(snapshot), w, h);
            } catch (IOException e) {
                err.println("depcheck gui: " + e.getMessage());
                return 2;
            }
            out.println("wrote " + snapshot);
            return 0;
        }

        Path start = path == null ? null : Path.of(path);
        if (start != null && !Files.isDirectory(start)) {
            err.println("depcheck gui: not a directory: " + start);
            return 2;
        }
        if (GraphicsEnvironment.isHeadless()) {
            err.println("depcheck gui: no display available (use --snapshot for a headless render)");
            return 2;
        }
        Path cd = cacheDir;
        long ttlHours = ttl;
        String url = osvUrl;
        SwingUtilities.invokeLater(() -> {
            systemLook();
            Gui gui = new Gui(cd, ttlHours, url);
            JFrame f = new JFrame("depcheck");
            f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            f.setContentPane(gui.root);
            f.setMinimumSize(new Dimension(700, 450));
            f.setSize(1000, 640);
            f.setLocationByPlatform(true);
            f.setVisible(true);
            if (start != null) {
                gui.folder = start;
                gui.scan();
            }
        });
        return -1;
    }

    private static String value(String[] args, int i) {
        if (i >= args.length) throw new IllegalArgumentException(args[i - 1] + " needs a value");
        return args[i];
    }
}
