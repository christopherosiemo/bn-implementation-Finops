// Command gitfixture is a local-only, read-only smart-HTTP fixture for Flux.
// Run in the lab's private Docker network with a read-only synthetic repo mount;
// do not publish its port or mount credentials, source repositories, or sockets.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes/gitfixture"
)

func main() {
	flags := flag.NewFlagSet("gitfixture", flag.ContinueOnError)
	repository := flags.String("repository", "", "absolute read-only synthetic bare repository ending in repository.git")
	check := flags.Bool("check", false, "validate the synthetic repository and fixed Git executables, then exit without listening")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 || *repository == "" {
		log.Fatal("usage: gitfixture -repository /fixture/repository.git")
	}
	handler, err := gitfixture.New(gitfixture.Config{RepositoryDir: *repository})
	if err != nil {
		log.Fatalf("fixture initialization failed: %v", err)
	}
	if *check {
		return
	}
	server := &http.Server{
		Addr:              gitfixture.ListenAddress,
		Handler:           http.TimeoutHandler(handler, 30*time.Second, "fixture request timed out"),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("synthetic Git fixture listening on %s", gitfixture.ListenAddress)
	log.Fatal(server.ListenAndServe())
}
