package ui

import (
	"fmt"

	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/wagoodman/go-partybus"
)

// handleExit is a UI function for processing the CatalogerFinished bus event, displaying the catalog
// via the given presenter to stdout.
func handleExit(event partybus.Event) error {
	// show the report to stdout
	callback, err := syftEventParsers.ParseExit(event)
	if err != nil {
		return fmt.Errorf("bad exit event: %w", err)
	}

	if callback == nil {
		return nil
	}

	return callback()
}
