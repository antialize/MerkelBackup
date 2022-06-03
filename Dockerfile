FROM docker.io/rust:latest as builder
WORKDIR /mbackup
# Note: "cargo install" ignores Cargo.lock, so there's no point in copying it in.
COPY Cargo.toml ./
RUN \
mkdir src && \
mkdir src/client && \
mkdir src/server && \
echo "fn main() {panic!(\"OH NO\")}" > src/client/main.rs && \
echo "fn main() {panic!(\"OH NO\")}" > src/server/main.rs && \
echo "fn main() {panic!(\"OH NO\")}" > src/dummy_server.rs
RUN CARGO_TARGET_DIR=target cargo install --root /usr --path .
RUN rm -f target/release/deps/mbackup*
COPY src/ src/
RUN CARGO_TARGET_DIR=target cargo install --offline --root /usr --path .

FROM rust
ARG GIT_COMMIT
ARG GIT_COMMIT_FULL
ARG GIT_BRANCH
ARG BUILD_USER
ARG BUILD_HOST
COPY --from=builder /usr/bin/mbackupd /usr/bin/mbackupd
COPY --from=builder /usr/bin/mbackup /usr/bin/mbackup
COPY --from=builder /usr/bin/dummy_server /usr/bin/dummy_server
ENV GIT_COMMIT=$GIT_COMMIT GIT_COMMIT_FULL=$GIT_COMMIT_FULL GIT_BRANCH=$GIT_BRANCH BUILD_USER=$BUILD_USER BUILD_HOST=$BUILD_HOST
LABEL GIT_COMMIT=$GIT_COMMIT GIT_COMMIT_FULL=$GIT_COMMIT_FULL GIT_BRANCH=$GIT_BRANCH BUILD_USER=$BUILD_USER BUILD_HOST=$BUILD_HOST
CMD ["dummy_server"]
