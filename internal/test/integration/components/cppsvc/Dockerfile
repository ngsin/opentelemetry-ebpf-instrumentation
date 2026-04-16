# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.19

RUN apk add --no-cache \
    gcc \
    musl-dev \
    curl-dev

WORKDIR /app
COPY main.c .

RUN gcc -Wall -O2 -o cppsvc main.c -lcurl && \
    cp cppsvc cppsvctls

# Default: make requests to testserver every 2 seconds, up to 100 requests
ENTRYPOINT ["/app/cppsvc"]
CMD ["http://testserver:8080/greeting", "2", "100"]
