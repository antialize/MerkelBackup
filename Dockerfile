FROM rust:latest as builder
WORKDIR /mbackup
# Note: "cargo install" ignores Cargo.lock, so there's no point in copying it in.
COPY Cargo.toml ./
RUN \
mkdir src && \
mkdir src/client && \
mkdir src/server && \
echo "fn main() {panic!(\"OH NO\")}" > src/client/main.rs && \
echo "fn main() {panic!(\"OH NO\")}" > src/server/main.rs
RUN CARGO_TARGET_DIR=target cargo install --root /usr --path .
RUN rm -f target/release/deps/mbackup*
COPY src/ src/
RUN CARGO_TARGET_DIR=target cargo install --offline --root /usr --path .

FROM rust
COPY --from=builder /usr/bin/mbackupd /usr/bin/mbackupd
COPY --from=builder /usr/bin/mbackup /usr/bin/mbackup
CMD ["sh", "-c", "echo Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N; while sleep 100000; do  : ; done"]
