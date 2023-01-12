FROM docker.io/rust:latest AS chef
RUN cargo install cargo-chef 
WORKDIR /mbackup

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /mbackup/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo install --offline --root /usr --path .

FROM debian:stable-slim
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
