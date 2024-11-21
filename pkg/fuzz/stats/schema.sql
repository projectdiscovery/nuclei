CREATE TABLE IF NOT EXISTS sites (
    site_id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT UNIQUE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sites_site_name ON sites(site_name);

CREATE TABLE IF NOT EXISTS components (
    component_id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    component_type TEXT NOT NULL CHECK (component_type IN ('path', 'query', 'header', 'body', 'cookie')),
    component_name TEXT NOT NULL,
    last_fuzzed DATETIME,
    url TEXT NOT NULL,
    total_fuzz_count INTEGER DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(site_id),
    UNIQUE (site_id, component_type, component_name, url)
);
CREATE INDEX IF NOT EXISTS idx_components_site_type_name ON components (site_id, component_type, component_name, url);


CREATE TABLE IF NOT EXISTS templates (
    template_id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT UNIQUE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_templates_template_name ON templates(template_name);

CREATE TABLE IF NOT EXISTS component_templates (
    component_id INTEGER NOT NULL,
    template_id INTEGER NOT NULL,
    times_applied INTEGER DEFAULT 0,
    PRIMARY KEY (component_id, template_id),
    FOREIGN KEY (component_id) REFERENCES components(component_id),
    FOREIGN KEY (template_id) REFERENCES templates(template_id)
);

CREATE TABLE IF NOT EXISTS fuzzing_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    template_id INTEGER NOT NULL,
    payload_sent TEXT NOT NULL,
    status_code_received INTEGER NOT NULL,
    matched BOOLEAN DEFAULT FALSE NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (component_id) REFERENCES components(component_id),
    FOREIGN KEY (template_id) REFERENCES templates(template_id)
);
CREATE INDEX IF NOT EXISTS idx_FuzzingResults_comp_temp_time ON fuzzing_results (component_id, template_id, timestamp);

-- Trigger to update stats when a new fuzzing result is inserted
CREATE TRIGGER IF NOT EXISTS update_component_stats
AFTER INSERT ON fuzzing_results
BEGIN
    UPDATE components
    SET last_fuzzed = NEW.timestamp,
        total_fuzz_count = total_fuzz_count + 1
    WHERE component_id = NEW.component_id;

    INSERT INTO component_templates (component_id, template_id, times_applied)
    VALUES (NEW.component_id, NEW.template_id, 1)
    ON CONFLICT(component_id, template_id) DO UPDATE SET
        times_applied = times_applied + 1;
END;
