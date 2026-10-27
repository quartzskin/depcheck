package depcheck;

/** version is null when the manifest only gives a range; spec keeps the raw text. */
record Dep(String ecosystem, String name, String version, String spec, String file) {
    String key() {
        return ecosystem + "|" + name + "|" + version;
    }
}
