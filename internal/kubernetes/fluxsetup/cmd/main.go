// Command fluxsetup transforms a pinned Flux install --export YAML stream into
// a bounded JSON List for the isolated local fixture. It never contacts a cluster.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes/fluxsetup"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: fluxsetup < pinned-flux-export.yaml")
		os.Exit(2)
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, fluxsetup.MaxInputBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read Flux export")
		os.Exit(1)
	}
	output, err := fluxsetup.Transform(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(output, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write prepared Flux export")
		os.Exit(1)
	}
}
