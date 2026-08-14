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
    """
    CREATE TABLE tcp_segment (
        id INTEGER PRIMARY KEY,
        segment_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        conversation_id INTEGER NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        frame_number INTEGER NOT NULL,
        stream_index INTEGER NOT NULL CHECK (stream_index >= 0),
        direction TEXT NOT NULL,
        sequence_relative INTEGER NOT NULL CHECK (sequence_relative >= 0),
        sequence_raw INTEGER NOT NULL CHECK (sequence_raw >= 0),
        payload_length INTEGER NOT NULL CHECK (payload_length > 0),
        payload_blob_id INTEGER NOT NULL REFERENCES blob(id) ON DELETE RESTRICT,
        retransmission INTEGER NOT NULL CHECK (retransmission IN (0,1)),
        spurious_retransmission INTEGER NOT NULL CHECK (spurious_retransmission IN (0,1)),
        out_of_order INTEGER NOT NULL CHECK (out_of_order IN (0,1)),
        lost_segment INTEGER NOT NULL CHECK (lost_segment IN (0,1)),
        FOREIGN KEY (capture_id,frame_number)
            REFERENCES frame(capture_id,frame_number) ON DELETE CASCADE
    );

    CREATE TABLE tcp_segment_run (
        segment_id INTEGER NOT NULL REFERENCES tcp_segment(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        PRIMARY KEY (segment_id,tool_run_id)
    ) WITHOUT ROWID;

    CREATE TABLE tcp_segment_skip (
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        frame_number INTEGER NOT NULL,
        stream_index INTEGER NOT NULL CHECK (stream_index >= 0),
        direction TEXT NOT NULL,
        payload_length INTEGER NOT NULL CHECK (payload_length > 0),
        reason TEXT NOT NULL CHECK (reason IN ('segment-limit','payload-budget')),
        PRIMARY KEY (tool_run_id,frame_number),
        FOREIGN KEY (capture_id,frame_number)
            REFERENCES frame(capture_id,frame_number) ON DELETE CASCADE
    ) WITHOUT ROWID;

    CREATE TABLE tcp_reconstruction (
        id INTEGER PRIMARY KEY,
        reconstruction_id TEXT NOT NULL UNIQUE,
        conversation_id INTEGER NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
        direction TEXT NOT NULL,
        evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        status TEXT NOT NULL CHECK (
            status IN ('complete','partial','conflicting','truncated','empty')
        ),
        sequence_start INTEGER,
        sequence_end INTEGER,
        unique_bytes INTEGER NOT NULL CHECK (unique_bytes >= 0),
        output_bytes INTEGER NOT NULL CHECK (output_bytes >= 0),
        duplicate_bytes INTEGER NOT NULL CHECK (duplicate_bytes >= 0),
        conflict_bytes INTEGER NOT NULL CHECK (conflict_bytes >= 0),
        gap_bytes INTEGER NOT NULL CHECK (gap_bytes >= 0),
        capture_midstream INTEGER NOT NULL CHECK (capture_midstream IN (0,1)),
        max_output_bytes INTEGER NOT NULL CHECK (max_output_bytes >= 0),
        updated_at TEXT NOT NULL,
        UNIQUE (conversation_id,direction)
    );

    CREATE TABLE tcp_reconstruction_source (
        reconstruction_id INTEGER NOT NULL
            REFERENCES tcp_reconstruction(id) ON DELETE CASCADE,
        segment_id INTEGER NOT NULL REFERENCES tcp_segment(id) ON DELETE CASCADE,
        sequence_offset INTEGER NOT NULL CHECK (sequence_offset >= 0),
        output_offset INTEGER NOT NULL CHECK (output_offset >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        role TEXT NOT NULL CHECK (role IN ('primary','duplicate')),
        PRIMARY KEY (reconstruction_id,segment_id,sequence_offset,role)
    ) WITHOUT ROWID;

    CREATE TABLE tcp_gap (
        reconstruction_id INTEGER NOT NULL
            REFERENCES tcp_reconstruction(id) ON DELETE CASCADE,
        sequence_start INTEGER NOT NULL CHECK (sequence_start >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        PRIMARY KEY (reconstruction_id,sequence_start)
    ) WITHOUT ROWID;

    CREATE TABLE tcp_overlap_conflict (
        id INTEGER PRIMARY KEY,
        conflict_id TEXT NOT NULL UNIQUE,
        reconstruction_id INTEGER NOT NULL
            REFERENCES tcp_reconstruction(id) ON DELETE CASCADE,
        first_segment_id INTEGER NOT NULL REFERENCES tcp_segment(id) ON DELETE CASCADE,
        conflicting_segment_id INTEGER NOT NULL REFERENCES tcp_segment(id) ON DELETE CASCADE,
        sequence_start INTEGER NOT NULL CHECK (sequence_start >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        first_sha256 TEXT NOT NULL,
        conflicting_sha256 TEXT NOT NULL
    );

    CREATE INDEX idx_tcp_segment_stream
        ON tcp_segment(conversation_id,direction,sequence_relative,frame_number);
    CREATE INDEX idx_tcp_reconstruction_status ON tcp_reconstruction(status);
    """,
    """
    CREATE TABLE triage_scan (
        id INTEGER PRIMARY KEY,
        scan_id TEXT NOT NULL UNIQUE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        detector TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        max_bytes INTEGER NOT NULL CHECK (max_bytes > 0),
        scanned_bytes INTEGER NOT NULL CHECK (scanned_bytes >= 0),
        matches INTEGER NOT NULL CHECK (matches >= 0),
        status TEXT NOT NULL CHECK (
            status IN (
                'complete','input-truncated','candidate-limit',
                'skipped-budget','skipped-limit','failed'
            )
        ),
        error TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE (evidence_id,detector,detector_version,policy_json)
    );

    CREATE TABLE candidate_signal (
        id INTEGER PRIMARY KEY,
        signal_id TEXT NOT NULL UNIQUE,
        candidate_id INTEGER NOT NULL REFERENCES candidate(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        detector TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        signal_name TEXT NOT NULL,
        contribution REAL NOT NULL,
        detail_json TEXT NOT NULL,
        UNIQUE (candidate_id,evidence_id,detector,detector_version,signal_name)
    );

    CREATE INDEX idx_triage_scan_status ON triage_scan(status,evidence_id);
    CREATE INDEX idx_candidate_signal_candidate ON candidate_signal(candidate_id);
    """,
    """
    CREATE TABLE ftp_message (
        protocol_message_id INTEGER PRIMARY KEY
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        request_command TEXT,
        request_argument TEXT,
        response_code INTEGER,
        response_argument TEXT,
        passive_ip TEXT,
        passive_port INTEGER CHECK (
            passive_port IS NULL OR (passive_port > 0 AND passive_port <= 65535)
        )
    );

    CREATE TABLE ftp_data_message (
        protocol_message_id INTEGER PRIMARY KEY
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        setup_frame INTEGER,
        setup_method TEXT,
        command_frame INTEGER,
        command TEXT,
        payload_length INTEGER NOT NULL CHECK (payload_length >= 0)
    );

    CREATE TABLE ftp_message_run (
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        PRIMARY KEY (protocol_message_id,tool_run_id)
    ) WITHOUT ROWID;

    CREATE TABLE ftp_metadata_skip (
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        frame_number INTEGER NOT NULL,
        protocol TEXT NOT NULL CHECK (protocol IN ('ftp','ftp-data')),
        reason TEXT NOT NULL CHECK (reason IN ('message-limit')),
        PRIMARY KEY (tool_run_id,frame_number,protocol),
        FOREIGN KEY (capture_id,frame_number)
            REFERENCES frame(capture_id,frame_number) ON DELETE CASCADE
    ) WITHOUT ROWID;

    CREATE TABLE ftp_transfer (
        id INTEGER PRIMARY KEY,
        transfer_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        setup_message_id INTEGER REFERENCES protocol_message(id) ON DELETE SET NULL,
        command_message_id INTEGER REFERENCES protocol_message(id) ON DELETE SET NULL,
        metadata_tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        reconstruction_id INTEGER REFERENCES tcp_reconstruction(id) ON DELETE SET NULL,
        evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        artifact_id INTEGER REFERENCES artifact(id) ON DELETE SET NULL,
        data_stream_index INTEGER NOT NULL CHECK (data_stream_index >= 0),
        direction TEXT NOT NULL,
        command TEXT,
        argument TEXT,
        suggested_name TEXT,
        output_bytes INTEGER NOT NULL DEFAULT 0 CHECK (output_bytes >= 0),
        max_output_bytes INTEGER NOT NULL CHECK (max_output_bytes > 0),
        status TEXT NOT NULL CHECK (
            status IN (
                'indexed','unresolved','skipped-limit','skipped-budget',
                'complete','partial','conflicting','truncated','empty','failed'
            )
        ),
        error TEXT,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE ftp_transfer_message (
        transfer_id INTEGER NOT NULL REFERENCES ftp_transfer(id) ON DELETE CASCADE,
        data_message_id INTEGER NOT NULL REFERENCES protocol_message(id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        PRIMARY KEY (transfer_id,data_message_id),
        UNIQUE (transfer_id,ordinal)
    ) WITHOUT ROWID;

    CREATE INDEX idx_ftp_message_command ON ftp_message(request_command,response_code);
    CREATE INDEX idx_ftp_data_references
        ON ftp_data_message(setup_frame,command_frame);
    CREATE INDEX idx_ftp_transfer_status ON ftp_transfer(status,data_stream_index);
    """,
    """
    CREATE TABLE telnet_dialogue (
        id INTEGER PRIMARY KEY,
        dialogue_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        conversation_id INTEGER NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
        client_endpoint TEXT,
        server_endpoint TEXT,
        client_reconstruction_id INTEGER
            REFERENCES tcp_reconstruction(id) ON DELETE SET NULL,
        server_reconstruction_id INTEGER
            REFERENCES tcp_reconstruction(id) ON DELETE SET NULL,
        status TEXT NOT NULL CHECK (
            status IN (
                'indexed','complete','partial','conflicting','truncated',
                'unresolved-role','failed'
            )
        ),
        error TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE (conversation_id)
    );

    CREATE TABLE telnet_dialogue_run (
        id INTEGER PRIMARY KEY,
        dialogue_id INTEGER NOT NULL REFERENCES telnet_dialogue(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        policy_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('completed','truncated','failed')),
        record_count INTEGER NOT NULL CHECK (record_count >= 0),
        parsed_bytes INTEGER NOT NULL CHECK (parsed_bytes >= 0),
        skipped_bytes INTEGER NOT NULL CHECK (skipped_bytes >= 0),
        error TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (dialogue_id,tool_run_id)
    );

    CREATE TABLE telnet_metadata_skip (
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        frame_number INTEGER NOT NULL,
        stream_index INTEGER NOT NULL CHECK (stream_index >= 0),
        reason TEXT NOT NULL CHECK (reason IN ('frame-limit')),
        PRIMARY KEY (tool_run_id,frame_number),
        FOREIGN KEY (capture_id,frame_number)
            REFERENCES frame(capture_id,frame_number) ON DELETE CASCADE
    ) WITHOUT ROWID;

    CREATE TABLE telnet_record (
        id INTEGER PRIMARY KEY,
        record_id TEXT NOT NULL UNIQUE,
        dialogue_id INTEGER NOT NULL REFERENCES telnet_dialogue(id) ON DELETE CASCADE,
        reconstruction_id INTEGER NOT NULL
            REFERENCES tcp_reconstruction(id) ON DELETE CASCADE,
        evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
        direction_role TEXT NOT NULL CHECK (direction_role IN ('client','server')),
        record_kind TEXT NOT NULL CHECK (
            record_kind IN (
                'application','negotiation','subnegotiation','command','incomplete-control'
            )
        ),
        stream_offset INTEGER NOT NULL CHECK (stream_offset >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        semantic_label TEXT,
        command INTEGER CHECK (command IS NULL OR (command >= 0 AND command <= 255)),
        option_code INTEGER CHECK (
            option_code IS NULL OR (option_code >= 0 AND option_code <= 255)
        ),
        frame_start INTEGER,
        frame_end INTEGER,
        time_start REAL,
        time_end REAL,
        created_at TEXT NOT NULL,
        UNIQUE (reconstruction_id,stream_offset,byte_length,record_kind)
    );

    CREATE TABLE telnet_record_source (
        record_id INTEGER NOT NULL REFERENCES telnet_record(id) ON DELETE CASCADE,
        segment_id INTEGER NOT NULL REFERENCES tcp_segment(id) ON DELETE CASCADE,
        record_offset INTEGER NOT NULL CHECK (record_offset >= 0),
        stream_offset INTEGER NOT NULL CHECK (stream_offset >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length > 0),
        PRIMARY KEY (record_id,segment_id,record_offset)
    ) WITHOUT ROWID;

    CREATE TABLE telnet_record_relation (
        record_id INTEGER NOT NULL REFERENCES telnet_record(id) ON DELETE CASCADE,
        related_record_id INTEGER NOT NULL REFERENCES telnet_record(id) ON DELETE CASCADE,
        relation TEXT NOT NULL CHECK (relation IN ('responds-to','echo-of')),
        PRIMARY KEY (record_id,related_record_id,relation),
        CHECK (record_id != related_record_id)
    ) WITHOUT ROWID;

    CREATE TABLE telnet_parse_skip (
        id INTEGER PRIMARY KEY,
        dialogue_run_id INTEGER NOT NULL
            REFERENCES telnet_dialogue_run(id) ON DELETE CASCADE,
        reconstruction_id INTEGER REFERENCES tcp_reconstruction(id) ON DELETE CASCADE,
        stream_offset INTEGER NOT NULL CHECK (stream_offset >= 0),
        byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
        reason TEXT NOT NULL CHECK (
            reason IN (
                'stream-limit','metadata-limit','record-limit','direction-byte-budget',
                'total-byte-budget','reconstruction-unavailable'
            )
        ),
        UNIQUE (dialogue_run_id,reconstruction_id,stream_offset,reason)
    );

    CREATE INDEX idx_telnet_dialogue_status ON telnet_dialogue(status,conversation_id);
    CREATE INDEX idx_telnet_record_timeline
        ON telnet_record(dialogue_id,frame_start,time_start,direction_role,stream_offset);
    CREATE INDEX idx_telnet_record_range
        ON telnet_record(reconstruction_id,stream_offset,byte_length);
    """,
    """
    CREATE TABLE capture_inventory_run (
        id INTEGER PRIMARY KEY,
        inventory_run_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        policy_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('completed','partial','failed','budget-limited')),
        processed_frames INTEGER NOT NULL CHECK (processed_frames >= 0),
        skipped_frames INTEGER NOT NULL CHECK (skipped_frames >= 0),
        skipped_conversations INTEGER NOT NULL CHECK (skipped_conversations >= 0),
        skipped_protocol_labels INTEGER NOT NULL CHECK (skipped_protocol_labels >= 0),
        started_at TEXT NOT NULL,
        ended_at TEXT,
        UNIQUE (capture_id, tool_run_id)
    );

    CREATE TABLE protocol_observation (
        id INTEGER PRIMARY KEY,
        observation_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        protocol_label TEXT NOT NULL,
        frame_count INTEGER NOT NULL CHECK (frame_count >= 0),
        first_frame INTEGER,
        last_frame INTEGER,
        inventory_run_id INTEGER NOT NULL REFERENCES capture_inventory_run(id) ON DELETE RESTRICT,
        updated_at TEXT NOT NULL,
        UNIQUE (capture_id, protocol_label)
    );

    CREATE TABLE conversation_profile (
        id INTEGER PRIMARY KEY,
        profile_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
        stream_index INTEGER NOT NULL CHECK (stream_index >= 0),
        endpoint_a TEXT,
        endpoint_b TEXT,
        initiator_endpoint TEXT,
        responder_endpoint TEXT,
        first_frame INTEGER,
        last_frame INTEGER,
        first_time TEXT,
        last_time TEXT,
        frame_count INTEGER NOT NULL CHECK (frame_count >= 0),
        captured_bytes INTEGER NOT NULL CHECK (captured_bytes >= 0),
        wire_bytes INTEGER NOT NULL CHECK (wire_bytes >= 0),
        payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
        protocol_labels_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (capture_id, protocol, stream_index)
    );

    CREATE TABLE conversation_profile_run (
        profile_id INTEGER NOT NULL REFERENCES conversation_profile(id) ON DELETE CASCADE,
        inventory_run_id INTEGER NOT NULL REFERENCES capture_inventory_run(id) ON DELETE CASCADE,
        PRIMARY KEY (profile_id, inventory_run_id)
    ) WITHOUT ROWID;

    CREATE TABLE inventory_skip (
        id INTEGER PRIMARY KEY,
        inventory_run_id INTEGER NOT NULL REFERENCES capture_inventory_run(id) ON DELETE CASCADE,
        scope TEXT NOT NULL CHECK (scope IN ('frame','conversation','protocol-label')),
        frame_number INTEGER,
        protocol TEXT,
        stream_index INTEGER,
        reason TEXT NOT NULL,
        count INTEGER NOT NULL CHECK (count > 0),
        detail_json TEXT NOT NULL,
        UNIQUE (inventory_run_id, scope, frame_number, protocol, stream_index, reason)
    );

    CREATE TABLE analysis_coverage (
        id INTEGER PRIMARY KEY,
        coverage_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        subject_kind TEXT NOT NULL CHECK (subject_kind IN ('protocol','conversation')),
        subject_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN (
                'complete','partial','not-run','unavailable','failed','budget-limited'
            )
        ),
        detail_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (capture_id, subject_kind, subject_id)
    );

    CREATE TABLE multipart_part (
        id INTEGER PRIMARY KEY,
        part_id TEXT NOT NULL UNIQUE,
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        field_name TEXT,
        filename TEXT,
        declared_media_type TEXT,
        status TEXT NOT NULL CHECK (status IN ('indexed','resolved','unresolved')),
        detail_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (protocol_message_id, ordinal)
    );

    CREATE TABLE multipart_part_artifact (
        id INTEGER PRIMARY KEY,
        part_id INTEGER NOT NULL REFERENCES multipart_part(id) ON DELETE CASCADE,
        artifact_id INTEGER REFERENCES artifact(id) ON DELETE CASCADE,
        carve_id INTEGER REFERENCES file_carve(id) ON DELETE SET NULL,
        role TEXT NOT NULL CHECK (role IN ('matched','type-mismatch','unresolved')),
        detail_json TEXT NOT NULL,
        UNIQUE (part_id, artifact_id, role)
    );

    CREATE TABLE finding_run (
        finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        PRIMARY KEY (finding_id, tool_run_id)
    ) WITHOUT ROWID;

    CREATE TABLE manual_queue_run (
        id INTEGER PRIMARY KEY,
        queue_run_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        inventory_run_id INTEGER REFERENCES capture_inventory_run(id) ON DELETE SET NULL,
        rule_version TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('completed','partial','failed','budget-limited')),
        created_count INTEGER NOT NULL CHECK (created_count >= 0),
        updated_count INTEGER NOT NULL CHECK (updated_count >= 0),
        skipped_count INTEGER NOT NULL CHECK (skipped_count >= 0),
        started_at TEXT NOT NULL,
        ended_at TEXT
    );

    CREATE TABLE manual_task (
        id INTEGER PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        subject_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        task_kind TEXT NOT NULL,
        suggested_priority INTEGER NOT NULL CHECK (
            suggested_priority >= 0 AND suggested_priority <= 100
        ),
        state TEXT NOT NULL CHECK (
            state IN ('open','in-progress','resolved','dismissed')
        ),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (capture_id, subject_kind, subject_id, task_kind)
    );

    CREATE TABLE manual_task_signal (
        id INTEGER PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES manual_task(id) ON DELETE CASCADE,
        queue_run_id INTEGER NOT NULL REFERENCES manual_queue_run(id) ON DELETE CASCADE,
        rule_name TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
        detail_json TEXT NOT NULL,
        UNIQUE (task_id, rule_name, rule_version)
    );

    CREATE TABLE manual_task_evidence (
        task_id INTEGER NOT NULL REFERENCES manual_task(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (task_id, evidence_id, role)
    ) WITHOUT ROWID;

    CREATE INDEX idx_inventory_protocol ON protocol_observation(capture_id, protocol_label);
    CREATE INDEX idx_inventory_conversation
        ON conversation_profile(capture_id, protocol, stream_index);
    CREATE INDEX idx_coverage_status ON analysis_coverage(capture_id, status);
    CREATE INDEX idx_multipart_message ON multipart_part(protocol_message_id, ordinal);
    CREATE INDEX idx_manual_task_queue
        ON manual_task(state, suggested_priority DESC, task_id);
    CREATE INDEX idx_manual_task_subject
        ON manual_task(capture_id, subject_kind, subject_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS multipart_part (
        id INTEGER PRIMARY KEY,
        part_id TEXT NOT NULL UNIQUE,
        protocol_message_id INTEGER NOT NULL
            REFERENCES protocol_message(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE RESTRICT,
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        field_name TEXT,
        filename TEXT,
        declared_media_type TEXT,
        status TEXT NOT NULL CHECK (status IN ('indexed','resolved','unresolved')),
        detail_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (protocol_message_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS multipart_part_artifact (
        id INTEGER PRIMARY KEY,
        part_id INTEGER NOT NULL REFERENCES multipart_part(id) ON DELETE CASCADE,
        artifact_id INTEGER REFERENCES artifact(id) ON DELETE CASCADE,
        carve_id INTEGER REFERENCES file_carve(id) ON DELETE SET NULL,
        role TEXT NOT NULL CHECK (role IN ('matched','type-mismatch','unresolved')),
        detail_json TEXT NOT NULL,
        UNIQUE (part_id, artifact_id, role)
    );

    CREATE TABLE IF NOT EXISTS finding_run (
        finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
        tool_run_id INTEGER NOT NULL REFERENCES tool_run(id) ON DELETE CASCADE,
        PRIMARY KEY (finding_id, tool_run_id)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS manual_queue_run (
        id INTEGER PRIMARY KEY,
        queue_run_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        inventory_run_id INTEGER REFERENCES capture_inventory_run(id) ON DELETE SET NULL,
        rule_version TEXT NOT NULL,
        policy_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('completed','partial','failed','budget-limited')
        ),
        created_count INTEGER NOT NULL CHECK (created_count >= 0),
        updated_count INTEGER NOT NULL CHECK (updated_count >= 0),
        skipped_count INTEGER NOT NULL CHECK (skipped_count >= 0),
        started_at TEXT NOT NULL,
        ended_at TEXT
    );

    CREATE TABLE IF NOT EXISTS manual_task (
        id INTEGER PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        capture_id INTEGER NOT NULL REFERENCES capture(id) ON DELETE CASCADE,
        subject_kind TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        task_kind TEXT NOT NULL,
        suggested_priority INTEGER NOT NULL CHECK (
            suggested_priority >= 0 AND suggested_priority <= 100
        ),
        state TEXT NOT NULL CHECK (
            state IN ('open','in-progress','resolved','dismissed')
        ),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (capture_id, subject_kind, subject_id, task_kind)
    );

    CREATE TABLE IF NOT EXISTS manual_task_signal (
        id INTEGER PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES manual_task(id) ON DELETE CASCADE,
        queue_run_id INTEGER NOT NULL REFERENCES manual_queue_run(id) ON DELETE CASCADE,
        rule_name TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
        detail_json TEXT NOT NULL,
        UNIQUE (task_id, rule_name, rule_version)
    );

    CREATE TABLE IF NOT EXISTS manual_task_evidence (
        task_id INTEGER NOT NULL REFERENCES manual_task(id) ON DELETE CASCADE,
        evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        PRIMARY KEY (task_id, evidence_id, role)
    ) WITHOUT ROWID;

    CREATE INDEX IF NOT EXISTS idx_multipart_message
        ON multipart_part(protocol_message_id, ordinal);
    CREATE INDEX IF NOT EXISTS idx_manual_task_queue
        ON manual_task(state, suggested_priority DESC, task_id);
    CREATE INDEX IF NOT EXISTS idx_manual_task_subject
        ON manual_task(capture_id, subject_kind, subject_id);
    """,
)
