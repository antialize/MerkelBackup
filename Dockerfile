FROM rust:latest as builder
WORKDIR /mbackup
COPY Cargo.toml Cargo.lock ./
RUN \
mkdir src && \\
mkdir src/client && \
mkdir src/server && \
echo "fn main() {}" > src/client/main.rs && \
echo "fn main() {}" > src/server/main.rs
RUN cargo build --release
COPY src/ src/
RUN cargo build --release && cargo install --path . --root /usr

FROM rust:slim
COPY --from=builder /usr/bin/mbackupd /usr/bin/mbackupd
COPY --from=builder /usr/bin/mbackup /usr/bin/mbackup


