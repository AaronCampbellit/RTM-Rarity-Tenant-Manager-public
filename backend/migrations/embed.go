// Package migrations embeds the Goose SQL migrations so the API/worker can
// apply them at startup (goose library) in addition to the `goose` CLI
// (make migrate-up). Keeping the .sql files here means one source of truth.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
