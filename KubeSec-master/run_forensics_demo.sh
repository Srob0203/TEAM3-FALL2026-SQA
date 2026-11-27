#!/usr/bin/env bash
# Activity 4.b demo: runs the instrumented SLI-KUBE scanner on FORENSICS_DEMO/
# and writes forensics.log. Needs mikefarah yq v4 on PATH (SLI-KUBE shells out to it).
set -e
cd "$(dirname "$0")"
rm -f forensics.log
python3 -W ignore -c "import scanner; scanner.runScanner('FORENSICS_DEMO')" > run_output.txt 2>&1
echo "forensics.log: $(wc -l < forensics.log) lines"
grep -E "SECRET_FOUND|PARSE_ERROR|REJECT|runScanner (START|END)" forensics.log
