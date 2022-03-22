FROM rust
COPY . /home/
WORKDIR /home/
RUN cargo install cargo-fuzz
RUN cargo build
RUN rustup toolchain install nightly
RUN rustup override set nightly
RUN cargo fuzz build
RUN cargo fuzz list

CMD cargo fuzz run target