# Plugin manifest examples

Copy one of these templates to a machine-local location, replace every
`<...>` placeholder with a real absolute path, and pass it to:

    auto-shark plugin-probe <manifest.json>
    auto-shark plugin-run <project> <manifest.json> --artifact <artifact-id>

Auto-Shark executes only the executable declared in the manifest; artifacts
are passed as inert input bytes. Nothing from the capture is ever executed.

## ctf-stego-toolkit (local, via the working-directory adapter)

`ctf-stego-toolkit` currently prints human-readable terminal output and does
not declare an output directory. The bundled `src/auto_shark/assets/cwd_adapter.py` adapter (shipped inside the wheel)
bridges that without parsing terminal prose: it runs the tool with the job's
isolated output directory as the working directory, so every file the tool
writes is discovered and hashed by Auto-Shark. The tool's terminal output is
preserved verbatim as hashed `stdout.txt`/`stderr.txt` evidence files; it is
never parsed into structured conclusions.

Replace `<python>` with the interpreter that has the toolkit dependencies
installed and `<solve.py>` with the absolute path to the toolkit's
`solve.py`:

```json
{
  "schema_version": "auto-shark.plugin/v1",
  "name": "ctf-stego-toolkit",
  "version": "1.0",
  "executable": "<python>",
  "capabilities": ["image-analysis"],
  "arguments": [
    "<site-packages>/auto_shark/assets/cwd_adapter.py",
    "120",
    "<python>",
    "<solve.py>",
    "{input}",
    "--no-color",
    "{output_dir}"
  ],
  "timeout_seconds": 300,
  "stdout_limit_bytes": 65536,
  "stderr_limit_bytes": 65536,
  "max_output_files": 32,
  "max_output_file_bytes": 33554432,
  "max_output_total_bytes": 134217728,
  "result_file": null
}
```

The same adapter works for any external tool that writes results into its
current working directory.

## Remote analyzer (Linux node)

Remote manifests use the same schema, but the executable must be an absolute
POSIX path on the node and every substituted argument token must be
shell-safe. First probe the node, then run:

    auto-shark remote-probe --host <user@host> --path /usr/bin/python3
    auto-shark remote-run <project> <manifest.json> --artifact <artifact-id> \
        --host <user@host>
