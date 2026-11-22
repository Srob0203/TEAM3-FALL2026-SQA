import ast
import os
import json
import random
import inspect
import importlib.util
import sys
from pathlib import Path
import atheris
#remove import

from typing import get_origin, get_args

#configurations/selection (output file, functions, source, random seed)
TARGET_FILE = "fuzz_targets.json"
MAX_FUNCTIONS = 10
RANDOM_SEED = 42
SOURCE_DIRECTORY = "KubeSec-master"
#these don't have anything worth testing
EXCLUDED_DIRS = {
    ".venv",
    "venv",
    "fuzz-env",
    "__pycache__",
    ".git",
    "node_modules",
    "TEST_ARTIFACTS"
}


def discover_functions(directory):

    """
    Search for eligible function definitions in a directory using AST parsing.

    Returns a list of dictionaries containing file paths, function names, and line numbers.

    """

    discovered = []

    for root, dirs, files in os.walk(directory):

        #keep out excluded directories
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDED_DIRS
        ]

        for filename in files:

            if not filename.endswith(".py"): #check python only
                continue

            filepath = os.path.join(root, filename)

            try: #read
                with open(filepath, "r", encoding="utf-8") as file:

                    source = file.read()

                tree = ast.parse(source)

            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            for node in tree.body:

                if isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef)
                ):

                    #ignore private functions
                    if node.name.startswith("_"):
                        continue

                    discovered.append({
                        "file": filepath,
                        "function": node.name,
                        "line": node.lineno
                    })

    return discovered


def select_targets(directory):

    """

    Randomly select 10 functions and save them.

    Uses a fixed seed for reproducibility.

    (Still working on trying to ensure all 10 actually scan with Atheris)

    """

    discovered = discover_functions(directory)

    #must find 10 functions to continue, otherwise raise an error
    if len(discovered) < MAX_FUNCTIONS:

        raise ValueError(
            f"Found only {len(discovered)} functions. "
            f"At least {MAX_FUNCTIONS} are required."
        )

    #generate seed for reproducibility

    rng = random.Random(RANDOM_SEED)

    selected = rng.sample(discovered, MAX_FUNCTIONS)

    with open(TARGET_FILE, "w", encoding="utf-8") as file:

        json.dump(selected, file, indent=4)

    print(f"Selected {len(selected)} functions.")

    return selected


def load_targets():

    """

    Load previously selected functions from a JSON file.
    Returns None if the file does not exist or cannot be read.

    """

    if not os.path.exists(TARGET_FILE):

        return None

    try:

        with open(TARGET_FILE, "r", encoding="utf-8") as file:
            targets = json.load(file)

        return targets

    except (json.JSONDecodeError, OSError) as error:

        print(f"Could not load targets: {error}")

        return None


def initialize_targets(directory):

    """

load existing targets or generate a new selection.

    """

    targets = load_targets()

    if targets is not None:

        if len(targets) != MAX_FUNCTIONS:
            raise ValueError(
                f"{TARGET_FILE} contains {len(targets)} targets; "
                f"exactly {MAX_FUNCTIONS} are required. Delete the file "
                "to generate a new selection."
            )

        print(f"Loaded {len(targets)} existing targets.")
        return targets

    print("No existing targets found. Discovering functions...")

    return select_targets(directory)





#prep for fuzzing with Atheris
def generate_argument(annotation, fdp):

    """Generate an argument based on type"""

    #THESE ARE NOT NEEDED AS NO FUNCTIONS IN THE PROJECT USE THESE TYPES

    if annotation in (int, "int"):

        return fdp.ConsumeInt(4)

    elif annotation in (float, "float"):

        return fdp.ConsumeFloat()

    elif annotation in (str, "str"):

        return fdp.ConsumeUnicodeNoSurrogates(64)

    elif annotation in (bool, "bool"):

        return fdp.ConsumeBool()

    #THESE ARE NOT NEEDED AS NO FUNCTIONS IN THE PROJECT USE THESE TYPES

    elif annotation in (bytes, "bytes"):

        return fdp.ConsumeBytes(64)



    elif annotation == Path:

        #generate a filesystem path from fuzzed text

        path_string = fdp.ConsumeUnicodeNoSurrogates(100)

        return Path(path_string)

    elif annotation == list:

        #generate a list containing fuzzed strings

        count = fdp.ConsumeIntInRange(0, 10)

        return [

            fdp.ConsumeUnicodeNoSurrogates(50)

            for _ in range(count)

        ]

    raise TypeError(f"Unsupported parameter type: {annotation}") #check for unexpected params

def generate_by_name(param_name, fdp):
    name = param_name.lower()
    """ Generates an argument based on the parameter name. 

This is a heuristic approach and may not always be accurate. """

    #string-like parameters

    if any(word in name for word in

           ["key", "password", "username", "name", "secret", "val"]):

        return fdp.ConsumeUnicodeNoSurrogates(100)

    #list-like parameters

    elif any(word in name for word in

             ["list", "lis", "items", "values"]):

        count = fdp.ConsumeIntInRange(0, 10)

        return [

            fdp.ConsumeUnicodeNoSurrogates(50)

            for _ in range(count)

        ]

    #path-like parameters

    elif any(word in name for word in

             ["path", "file", "dir", "folder", "script"]):

        return Path(fdp.ConsumeUnicodeNoSurrogates(100))

    #dictionary-like parameters

    elif any(word in name for word in

             ["dict", "config", "mapping", "settings"]):

        count = fdp.ConsumeIntInRange(0, 10)

        return {

            fdp.ConsumeUnicodeNoSurrogates(20):

            fdp.ConsumeUnicodeNoSurrogates(50)

            for _ in range(count)

        }

    #integer-like parameters

    elif any(word in name for word in

             ["pos", "index", "count", "size", "length", "num"]):

        return fdp.ConsumeInt(4)

    #default fallback

    return fdp.ConsumeUnicodeNoSurrogates(100)


def prepare_arguments(function, fdp):

    signature = inspect.signature(function)

    """Prepare arguments for a function based on its signature and fuzzed data"""

    args = []

    kwargs = {}

    for name, param in signature.parameters.items():

        #skip parameters that Python supplies automatically

        if param.kind in (

            inspect.Parameter.VAR_POSITIONAL,

            inspect.Parameter.VAR_KEYWORD

        ):

            continue

        #use annotations when available

        if param.annotation != inspect.Parameter.empty:

            value = generate_argument(param.annotation, fdp)

        #otherwise, infer from the parameter name

        else:

            value = generate_by_name(name, fdp)

        if param.kind == inspect.Parameter.KEYWORD_ONLY:

            kwargs[name] = value

        else:

            args.append(value)

    return args, kwargs


def load_target_functions(targets):

    """Import and instrument the saved target functions."""

    loaded = []
    modules = {}

    for target in targets:

        filepath = Path(target["file"]).resolve()

        if filepath not in modules:

            #import the source file as a Python module.

            module_name = f"fuzz_target_{len(modules)}"

            sys.path.insert(0, str(filepath.parent)) #CHANGE MADE (it's fine)

            spec = importlib.util.spec_from_file_location(

                module_name, filepath

            )

            if spec is None or spec.loader is None:

                print(f"Could not load: {filepath}")

                continue

            module = importlib.util.module_from_spec(spec)

            sys.modules[module_name] = module

            try:
                spec.loader.exec_module(module)
            except Exception as error:
                raise RuntimeError(
                    f"Could not import target module {filepath}: {error}"
                ) from error

            modules[filepath] = module

        module = modules[filepath]

        function = getattr(module, target["function"], None)

        if not inspect.isfunction(function):
            raise RuntimeError(
                f"Target not found: {target['function']} in {filepath}"
            )



        try:
            #check whether the function has supported parameters.
            print(f"\nChecking: {function.__name__}")

            for name, param in inspect.signature(function).parameters.items():

                print(f"  Parameter: {name}")

                print(f"  Annotation: {param.annotation}")

            signature = inspect.signature(function)







            #enable coverage instrumentation.

            atheris.instrument_func(function)

            loaded.append(function)

            print(f"Loaded target: {function.__name__}")

        except TypeError as error:
            raise RuntimeError(
                f"Could not instrument {function.__name__}: {error}"
            ) from error

    if len(loaded) != len(targets):
        raise RuntimeError(
            f"Loaded {len(loaded)} of {len(targets)} selected targets."
        )

    return loaded

def TestOneInput(data):

    """Atheris entry point."""

    if not target_functions:
        return

    # Run every selected function for each input instead of choosing one.
    # A fresh provider gives each function its own read position.
    for function in target_functions:
        fdp = atheris.FuzzedDataProvider(data)
        args, kwargs = prepare_arguments(function, fdp)
        print(f"Fuzzing function: {function.__name__}") #print for double checking
        # Unexpected exceptions are intentionally not caught for reporting.
        function(*args, **kwargs)


if __name__ == "__main__":

    targets = initialize_targets(SOURCE_DIRECTORY)

    print("\nFuzzing targets:")
    for index, target in enumerate(targets, start=1):
        print(
            f"{index}. {target['function']} "
            f"({target['file']}, line {target['line']})"
        )

    with atheris.instrument_imports():

        target_functions = load_target_functions(targets)



    if len(target_functions) != MAX_FUNCTIONS:
        raise RuntimeError(
            f"Expected {MAX_FUNCTIONS} loaded targets, "
            f"but got {len(target_functions)}."
        )

    print(f"\nFuzzing all {len(target_functions)} selected functions per input.")

    atheris.Setup(sys.argv, TestOneInput)

    atheris.Fuzz() #begin fuzzing