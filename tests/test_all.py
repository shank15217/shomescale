"""shomescale test runner - minimal pytest-compatible runner."""

import os
import sys
import importlib
import unittest


def discover_and_run(test_dir="tests"):
    """Discover and run all test files in the tests/ directory."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for fname in sorted(os.listdir(test_dir)):
        if fname.endswith(".py") and fname.startswith("test_"):
            module_name = os.path.splitext(fname)[0]
            # Use importlib to load the module
            spec = importlib.util.find_spec(f"tests.{module_name}")
            if spec:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module_suite = loader.loadTestsFromModule(module)
                suite.addTests(module_suite)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, failfast=False)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    result = discover_and_run()
    sys.exit(0 if result.wasSuccessful() else 1)
