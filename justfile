# Lists available recipes.
default:
    @just --list

# Runs tests.
test:
    cargo test

# Builds release artifacts.
[linux]
build:
    cargo build --release --target=x86_64-unknown-linux-musl

# Builds release artifacts.
[macos]
build:
    cargo build --release --target=aarch64-apple-darwin

# Builds release artifacts.
[windows]
build:
    cargo build --release --target=x86_64-pc-windows-msvc

# Publishes the application to the Armory registry.
[linux]
publish: build
    armory publish --triple x86_64_linux

# Publishes the application to the Armory registry.
[macos]
publish: build
    armory publish --triple aarch64_darwin

# Publishes the application to the Armory registry.
[windows]
publish: build
    armory publish --triple x86_64_windows
