# Activity 4.b: Forensics Integration (5 of 10 methods)

## Status
Complete for this half: 5 methods are instrumented, and the logging runs end to end on sample manifests. The scan results are identical to the original, uninstrumented code (checked by comparing `runScanner` output before and after the change).

## What forensics means here
Every instrumented method writes to one append-only log, `forensics.log`, through a shared logger (`forensics_logger.py`). Each line records the time, the level, `module.method:line`, and an event tag (`START`, `END`, `REJECT`, `SECRET_FOUND`, `PARSE_ERROR`, ...). After a bad scan, you can use the log to reconstruct which files were read, why each one was accepted or skipped, what was found, and where it failed.

**Secrets never reach the log.** SLI-KUBE's job is to find hard-coded passwords, so a naive log would become a second copy of them. `scanForSecrets` logs only the key name and counts (`key='db_password' passwords=1`), never the value. The demo manifest contains the password `SuperS3cretValue`, and `grep` finds it 0 times in `forensics.log`.

## The 5 methods

| # | File | Method | What it logs |
|---|------|--------|--------------|
| 1 | `parser.py` | `loadMultiYAML` | file opened, missing-file check, number of YAML documents loaded and their types, **parse/YAML/Unicode errors with line and column** (originally the code only printed `skipping`) |
| 2 | `parser.py` | `checkIfValidK8SYaml` | the accept/reject decision **and the reason** (forbidden `kind`, or missing `apiVersion`/`kind`) |
| 3 | `scanner.py` | `scanForSecrets` | keys scanned, each key flagged as a username/password/key secret (counts only, values withheld) |
| 4 | `scanner.py` | `scanSingleManifest` | which branch ran (valid K8s / Helm), secret and taint counts at exit, and any failure in the `yq` line-number lookup, logged before it is re-raised |
| 5 | `scanner.py` | `runScanner` | target folder, YAML files found, each file scanned/skipped (invalid or "weird"), totals, SARIF result count, elapsed time |

## How to identify the implementation
- New file: `forensics_logger.py`
- Every added line ends with the comment `# FORENSICS (4.b)`. To find them all, run `grep -n "FORENSICS (4.b)" parser.py scanner.py` (12 in parser.py, 18 in scanner.py).
- Evidence: `forensics.log`, `run_output.txt`, `screenshots/forensics_run.png`
- Demo inputs: `FORENSICS_DEMO/` (a privileged pod with plain HTTP, a Secret with a hard-coded username and password, a malformed YAML file, and a non-Kubernetes Ansible file)

## How to replicate
```bash
pip install ruamel.yaml==0.17.21 sarif-om jschema-to-python numpy pandas
# SLI-KUBE shells out to mikefarah yq v4 (NOT the Python "yq" wrapper)
curl -sSL -o yq https://github.com/mikefarah/yq/releases/download/v4.44.3/yq_linux_amd64 && chmod +x yq && export PATH=$PWD:$PATH
./run_forensics_demo.sh       # writes forensics.log and prints the key events
```

## Problems the forensics log exposed
1. **Undeclared `yq` dependency.** `parser.show_line_for_paths` runs `yq` through `subprocess`, but `yq` isn't in `requirements.txt`, `environment.yml`, or the Dockerfile. With the wrong `yq` installed, the scan dies with `CalledProcessError`. The last `forensics.log` line before the crash pins down the file being scanned.
2. **Empty folder crashes `runScanner`.** `sarif_json` is only assigned inside the file loop, so a folder with no YAML files raises `UnboundLocalError`. `runScanner` now logs a `NO_YAML_FILES` warning first.
3. **`main.py` cannot start.** It uses `typer` and `Path` without importing them (`NameError: name 'typer' is not defined`).
4. **Silent parse failures.** Malformed YAML used to print only `skipping`. The log now records the exact line and column (e.g. `broken.yaml line 5, column 11`).

## Lessons learned (draft, edit into your own words)
Forensics logging is only useful if it answers "why", not just "what": a line saying a file was rejected helped much less than one saying it was rejected because it had no `apiVersion`. When the tool under test is a secret scanner, the logging itself can become a vulnerability, so deciding what *not* to log was as important as deciding what to log. Running the instrumented tool on deliberately bad inputs exposed real defects (an undeclared `yq` dependency and a crash on empty folders) that the existing unit tests never exercised.
