FROM debian:12.11-slim


WORKDIR /rusthole
COPY rusthole .

RUN apt-get update && apt-get upgrade && apt-get install -y curl build-essential
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN . "$HOME/.cargo/env" && cargo build --release && mv ./target/release/rusthole . && rm -rf ./target ./src ./Cargo.lock ./Cargo.toml

EXPOSE 53
CMD ["./rusthole"]