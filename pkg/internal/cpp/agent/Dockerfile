# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
#
# OBI C++ Agent - Reproducible build environment
#

FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    linux-headers \
    file \
    binutils

WORKDIR /build
COPY . .

RUN make clean && make all

# Verify the output
RUN file embedded/obi-cpp-agent.so && \
    nm -D embedded/obi-cpp-agent.so | head -20

# --- Output stage ---
FROM scratch
COPY --from=builder /build/embedded/obi-cpp-agent.so /obi-cpp-agent.so
