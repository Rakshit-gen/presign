FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p presign-server -p presign-cli

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/target/release/presign-server /src/target/release/presign /usr/local/bin/
USER 65534:65534
EXPOSE 8080
ENV PRESIGN_ADDR=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/presign-server"]
