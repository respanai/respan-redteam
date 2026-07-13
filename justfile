# List available recipes
default:
    @just --list

# Install the engine + dev dependencies
install:
    uv sync

# Run the test suite (plain-python asserts; no pytest needed)
test:
    uv run python tests/test_session_waist.py
    uv run python tests/test_cli.py
    uv run python tests/test_user_config.py
