// Intentional: go.mod with typosquatted and hallucinated Go modules.
//
// When developers ask an LLM to "set up a Go project with common dependencies",
// the model may suggest modules that don't exist or are typosquats of popular
// packages. Go's module system fetches from the internet by default, so a
// malicious module could execute arbitrary code via init() functions.
//
// Scanner should flag: known typosquats, suspicious module paths, modules
// that mimic popular packages but from different namespaces.

module github.com/example/ai-suggested-service

go 1.21

require (
	// Legitimate dependencies
	github.com/gin-gonic/gin v1.9.1
	github.com/go-sql-driver/mysql v1.7.1
	google.golang.org/grpc v1.59.0

	// Intentional: typosquat of github.com/sirupsen/logrus (capital S)
	github.com/Sirupsen/logrus v1.9.3

	// Intentional: typosquat of github.com/stretchr/testify (extra 'r')
	github.com/stretchrr/testify v1.8.4

	// Intentional: hallucinated module — plausible name, doesn't exist
	github.com/go-crypto-utils/aes256 v1.0.0

	// Intentional: typosquat of github.com/gorilla/mux (different org)
	github.com/gorila/mux v1.8.0

	// Intentional: hallucinated "official" Go security module
	golang.org/x/security v0.15.0

	// Intentional: namespace confusion — looks like an official pkg
	github.com/golang/protobuf-gen v1.5.3

	// Intentional: typosquat of github.com/lib/pq (different org)
	github.com/libs/pq v1.10.9

	// Intentional: hallucinated AI/ML Go module
	github.com/go-ai/inference v0.3.0

	// Intentional: typosquat of github.com/spf13/cobra
	github.com/spf13/corba v1.7.0

	// Intentional: hallucinated — looks like official gRPC middleware
	google.golang.org/grpc/middleware/auth v1.0.0
)
