1. Have we completed all tasks?
    Yes. Both the fuzzer and the forensics integration are complete.

2. How to identify our implementation:
    For the fuzzer:
    All fuzzer and most of the supporting code are located in the directory fuzzer/ to ensure it doesn't attempt to scan itself. fuzzer.py drives the fuzzing execution. fuzz_targets.json are the functions I specifically selected from KubeSec. requirements.txt has all dependencies listed for GitHub Actions, and fuzzer_overview is documentation. 

    Other supporting code/documentation:
    The saved_crashes/ directory documents a few Atheris-generated outputs that caused crashes/slowdowns. Unfortunately, I forgot to track the origin (which function took in the input). There are also a few screenshots from when it was simply raw Atheris scanning. (The program intentionally catches errors so Atheris gets through all rather than stopping once an error is found).

    The testing_materials/ directory contains test scripts for functions that take in paths for scripts (e.g. KubeSec-master/graphtaint.py 's getSHFiles()).

3. How to replicate our work:
    1. Prerequisites - Clone this repo using git clone [link to repo]. All Python code runs on version 3.11. This project has its own dependencies in requirements.txt.

    2. Setup - Configuration: This projects works best with a Python virtual environment. Verify that the environment is working on Python version 3.11. Ensure all dependencies are installed by running: pip install -r requirements.txt.

    NOTE: If you are using this project on Windows, you will need to use Windows Subsystem for Linux 2 and run the project there, as Atheris is currently not compatible for native Windows. Although development was performed using VS Code on Windows, execution and testing were performed within Ubuntu.

    3. Input files - No input files are needed for the fuzzer.

    4. Execution - To run the file, use the command ' python fuzzer/fuzzer.py -max_total_time=30'. Estimated execeution time is a few minutes.

    5. Expected Results/Verification	- After execution terminates, a fuzzing_stats.json file is created. This file should have the following output pattern:

    '[
    '{
        '"file": "path",
        '"function": "functionName",
        '"line": 23
    '},
    '...]


    6. Troubleshooting - Please check your directory variables for fuzzer.py. They are setup to adjust to your own personal directory, but may not work if items are moved around.

4. What we learned:
    a. How to find functions suitable for Atheris (as the tool has its own ways of determining suitability for fuzzing).
    b. How to make a repo compatible for GitHub Actions and how to make a GitHub Actions config file (.yml). Directory problems were the largest issue.
    c. How to properly document statistics/generate meaningful fuzzing output for analysis/integration.