# List available developer commands.
default:
    @just --list

# Run the normal locked test suite.
test:
    cargo test --locked

# Run ignored Redis integration tests against REDIS_URL, defaulting to localhost.
redis-test:
    REDIS_URL="${REDIS_URL:-redis://127.0.0.1/}" cargo test --locked --features redis --test redis_store -- --ignored --nocapture
