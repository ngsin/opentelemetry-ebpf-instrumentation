// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cpp // import "go.opentelemetry.io/obi/pkg/internal/cpp"

import (
	_ "embed"
)

const ObiCppAgentFileName = "obi-cpp-agent.so"

// embeddedCppAgentRaw contains the compiled agent.so binary.
// During development, a placeholder file is used. The real binary is
// produced by `make cpp-agent-docker-build` and placed in the embedded/ directory.
//
//go:embed agent/embedded/obi-cpp-agent.so
var embeddedCppAgentRaw []byte

// EmbeddedCppAgentBytes returns the embedded agent binary.
// Using a function allows test code to override the bytes if needed.
var EmbeddedCppAgentBytes = embeddedCppAgentRaw
