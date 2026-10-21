package main

import (
	"fmt"
	"os"

	"github.com/anaconda/envscout/internal/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		if cli.ShouldPrintError(err) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(cli.ExitCode(err))
	}
}
