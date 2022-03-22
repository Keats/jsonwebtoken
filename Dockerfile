FROM rust
COPY . /home/
WORKDIR /home/
RUN cargo install cargo-fuzz
RUN cargo build
RUN rustup toolchain install nightly
RUN cargo +nightly fuzz build
CMD cargo +nightly fuzz run target