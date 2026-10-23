package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/anaconda/envscout/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal cancels ctx, restore default handling so a second interrupt terminates.
	go func() {
		<-ctx.Done()
		stop()
	}()

	err := cli.New().ExecuteContext(ctx)
	stop()

	if err != nil {
		if cli.ShouldPrintError(err) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(cli.ExitCode(err))
	}
}
