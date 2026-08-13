"""Append-only SQLite migrations."""

MIGRATIONS = (
    """
    CREATE TABLE project_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE capture (
        id INTEGER PRIMARY KEY,
        capture_id TEXT NOT NULL UNIQUE,
        source_name TEXT NOT NULL,
        source_path TEXT NOT NULL,
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        sha256 TEXT NOT NULL UNIQUE,
        format TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE tool_run (
        id INTEGER PRIMARY KEY,
        run_id TEXT NOT NULL UNIQUE,
        tool_name TEXT NOT NULL,
        tool_version TEXT,
        argv_json TEXT NOT NULL,
        capability_json TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL,
        exit_code INTEGER,
        stderr_text TEXT,
        stderr_truncated INTEGER NOT NULL DEFAULT 0 CHECK (stderr_truncated IN (0, 1))
    );

    CREATE TABLE capability (
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        capability TEXT NOT NULL,
        available INTEGER NOT NULL CHECK (available IN (0, 1)),
        detail TEXT,
        PRIMARY KEY (tool_run_id, capability)
    ) WITHOUT ROWID;

    CREATE TABLE conversation (
        id INTEGER PRIMARY KEY,
        conversation_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        protocol TEXT NOT NULL,
        stream_index INTEGER,
        endpoint_a TEXT,
        endpoint_b TEXT
    );

    CREATE TABLE frame (
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        frame_number INTEGER NOT NULL CHECK (frame_number > 0),
        time_epoch TEXT,
        captured_length INTEGER CHECK (captured_length >= 0),
        original_length INTEGER CHECK (original_length >= 0),
        PRIMARY KEY (capture_id, frame_number)
    ) WITHOUT ROWID;

    CREATE TABLE protocol_message (
        id INTEGER PRIMARY KEY,
        message_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        conversation_id INTEGER REFERENCES conversation(id) ON DELETE SET NULL,
        representative_frame INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        direction TEXT,
        message_kind TEXT,
        fields_json TEXT NOT NULL,
        FOREIGN KEY (capture_id, representative_frame)
            REFERENCES frame(capture_id, frame_number) ON DELETE CASCADE
    );

    CREATE TABLE transaction_record (
        id INTEGER PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        protocol TEXT NOT NULL,
        request_message_id INTEGER REFERENCES protocol_message(id) ON DELETE SET NULL,
        response_message_id INTEGER REFERENCES protocol_message(id) ON DELETE SET NULL,
        status TEXT NOT NULL
    );

    CREATE TABLE blob (
        id INTEGER PRIMARY KEY,
        sha256 TEXT NOT NULL UNIQUE,
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        relative_path TEXT NOT NULL UNIQUE,
        media_type TEXT,
        magic_description TEXT,
        complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
        created_at TEXT NOT NULL
    );

    CREATE TABLE evidence (
        id INTEGER PRIMARY KEY,
        evidence_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        source_kind TEXT NOT NULL,
        frame_start INTEGER,
        frame_end INTEGER,
        protocol_message_id INTEGER REFERENCES protocol_message(id) ON DELETE SET NULL,
        transaction_id INTEGER REFERENCES transaction_record(id) ON DELETE SET NULL,
        direction TEXT,
        byte_offset INTEGER CHECK (byte_offset IS NULL OR byte_offset >= 0),
        byte_length INTEGER CHECK (byte_length IS NULL OR byte_length >= 0),
        field_name TEXT,
        text_value TEXT,
        blob_id INTEGER REFERENCES blob(id) ON DELETE RESTRICT,
        locator_json TEXT NOT NULL
    );

    CREATE TABLE transform (
        id INTEGER PRIMARY KEY,
        transform_id TEXT NOT NULL UNIQUE,
        parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        output_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        depth INTEGER NOT NULL CHECK (depth >= 0),
        status TEXT NOT NULL,
        truncated INTEGER NOT NULL CHECK (truncated IN (0, 1))
    );

    CREATE TABLE finding (
        id INTEGER PRIMARY KEY,
        finding_id TEXT NOT NULL UNIQUE,
        detector TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        recommended_action TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE finding_evidence (
        finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (finding_id, evidence_id, role)
    ) WITHOUT ROWID;

    CREATE TABLE candidate (
        id INTEGER PRIMARY KEY,
        candidate_id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        rank_score REAL NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE candidate_evidence (
        candidate_id INTEGER NOT NULL REFERENCES candidate(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (candidate_id, evidence_id, role)
    ) WITHOUT ROWID;

    CREATE TABLE artifact (
        id INTEGER PRIMARY KEY,
        artifact_id TEXT NOT NULL UNIQUE,
        blob_id INTEGER NOT NULL REFERENCES blob(id) ON DELETE RESTRICT,
        source_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        suggested_name TEXT,
        declared_media_type TEXT,
        detected_media_type TEXT,
        review_state TEXT NOT NULL DEFAULT 'unreviewed',
        created_at TEXT NOT NULL
    );

    CREATE TABLE review_mark (
        subject_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK (
            state IN ('unreviewed', 'needs_review', 'excluded', 'key_evidence')
        ),
        updated_at TEXT NOT NULL,
        PRIMARY KEY (subject_kind, subject_id)
    ) WITHOUT ROWID;

    CREATE TABLE note (
        id INTEGER PRIMARY KEY,
        subject_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE plugin_run (
        id INTEGER PRIMARY KEY,
        run_id TEXT NOT NULL UNIQUE,
        plugin_id TEXT NOT NULL,
        plugin_version TEXT NOT NULL,
        input_artifact_id INTEGER REFERENCES artifact(id) ON DELETE SET NULL,
        job_directory TEXT NOT NULL,
        status TEXT NOT NULL,
        result_schema TEXT,
        started_at TEXT NOT NULL,
        ended_at TEXT
    );

    CREATE TABLE remote_job (
        id INTEGER PRIMARY KEY,
        job_id TEXT NOT NULL UNIQUE,
        plugin_run_id INTEGER REFERENCES plugin_run(id) ON DELETE SET NULL,
        node_name TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        result_sha256 TEXT,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT
    );

    CREATE INDEX idx_frame_time ON frame(capture_id, time_epoch);
    CREATE INDEX idx_message_frame ON protocol_message(capture_id, representative_frame);
    CREATE INDEX idx_message_protocol ON protocol_message(capture_id, protocol);
    CREATE INDEX idx_evidence_frames ON evidence(capture_id, frame_start, frame_end);
    CREATE INDEX idx_candidate_rank ON candidate(rank_score DESC, confidence DESC);
    """,
    """
    CREATE TABLE http_message (
        protocol_message_id INTEGER PRIMARY KEY
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        method TEXT,
        uri TEXT,
        full_uri TEXT,
        host TEXT,
        response_code INTEGER,
        response_phrase TEXT,
        response_in_frame INTEGER,
        request_in_frame INTEGER,
        content_length INTEGER CHECK (content_length IS NULL OR content_length >= 0),
        content_type TEXT
    );

    CREATE TABLE transaction_message (
        transaction_id INTEGER NOT NULL
            REFERENCES transaction_record(id) ON DELETE CASCADE,
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('request', 'response', 'extra_response')),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (transaction_id, protocol_message_id),
        UNIQUE (transaction_id, role, ordinal)
    ) WITHOUT ROWID;

    CREATE INDEX idx_http_response_in ON http_message(response_in_frame);
    CREATE INDEX idx_http_request_in ON http_message(request_in_frame);
    CREATE INDEX idx_http_uri ON http_message(uri);
    """,
    """
    CREATE TABLE http_body (
        protocol_message_id INTEGER PRIMARY KEY
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        declared_length INTEGER CHECK (declared_length IS NULL OR declared_length >= 0),
        extracted_length INTEGER NOT NULL CHECK (extracted_length >= 0),
        status TEXT NOT NULL CHECK (
            status IN (
                'complete', 'empty', 'absent', 'missing', 'partial',
                'limit-truncated', 'length-mismatch'
            )
        ),
        truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
        error TEXT,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX idx_http_body_status ON http_body(status);
    """,
    """
    CREATE TABLE form_field (
        id INTEGER PRIMARY KEY,
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        name TEXT NOT NULL,
        raw_value_evidence_id INTEGER NOT NULL
            REFERENCES evidence(id) ON DELETE CASCADE,
        decoded_value_evidence_id INTEGER NOT NULL
            REFERENCES evidence(id) ON DELETE CASCADE,
        UNIQUE (protocol_message_id, ordinal)
    );

    CREATE INDEX idx_form_field_name ON form_field(name);
    """,
    """
    CREATE TABLE body_task (
        id INTEGER PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        selection_reason TEXT NOT NULL,
        priority INTEGER NOT NULL,
        max_bytes INTEGER NOT NULL CHECK (max_bytes > 0),
        status TEXT NOT NULL CHECK (
            status IN ('pending', 'running', 'completed', 'skipped-budget', 'failed')
        ),
        extracted_bytes INTEGER CHECK (extracted_bytes IS NULL OR extracted_bytes >= 0),
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX idx_body_task_status ON body_task(status, priority DESC, id);
    """,
    """
    CREATE TABLE artifact_evidence (
        artifact_id INTEGER NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (artifact_id, evidence_id, role)
    ) WITHOUT ROWID;

    CREATE TABLE file_scan (
        id INTEGER PRIMARY KEY,
        scan_id TEXT NOT NULL UNIQUE,
        parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        scanned_bytes INTEGER NOT NULL CHECK (scanned_bytes >= 0),
        parent_bytes INTEGER NOT NULL CHECK (parent_bytes >= 0),
        max_scan_bytes INTEGER NOT NULL CHECK (max_scan_bytes > 0),
        max_artifact_bytes INTEGER NOT NULL CHECK (max_artifact_bytes > 0),
        max_candidates INTEGER NOT NULL CHECK (max_candidates > 0),
        candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
        status TEXT NOT NULL CHECK (
            status IN ('complete', 'scan-truncated', 'candidate-limit')
        ),
        updated_at TEXT NOT NULL
    );

    CREATE TABLE file_carve (
        id INTEGER PRIMARY KEY,
        carve_id TEXT NOT NULL UNIQUE,
        parent_evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        carved_evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        artifact_id INTEGER NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
        prefix_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        trailing_evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        format TEXT NOT NULL,
        start_offset INTEGER NOT NULL CHECK (start_offset >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        structural_status TEXT NOT NULL CHECK (
            structural_status IN (
                'validated', 'signature-only', 'scan-truncated', 'artifact-truncated'
            )
        ),
        validation_detail TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE UNIQUE INDEX idx_file_scan_parent ON file_scan(parent_evidence_id);
    CREATE INDEX idx_file_carve_parent ON file_carve(parent_evidence_id, start_offset);
    """,
)
