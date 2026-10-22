This package is a synthetic Git fixture for the local Kubernetes/Flux lab.
It serves one approved bare repository, named `repository.git`, through actual
Git smart HTTP. It does not connect to GitHub or use the checkout's remotes.

Build in the pinned Linux Go image:

```sh
go build -o /out/gitfixture ./internal/kubernetes/gitfixture/cmd
```

Run `/out/gitfixture -repository /fixture/repository.git` in the lab's private
Docker network. The process listens on port 8080. Mount only the synthetic bare
repository, read-only. Do not publish ports or mount credentials, the source
checkout, home directories, or the Docker socket. The fixture producer may
update that bare repository locally to publish another synthetic revision.
Initialize the repository inside the pinned Linux Go image with
`git init --bare --initial-branch=main /fixture/repository.git`, then write the
fresh synthetic repository's exact minimal core config. Filesystem detection
can still add `core.ignorecase` on a Windows-shared mount; existing repositories
must never be adopted or rewritten. The config
allowlist accepts only `core.repositoryformatversion=0`, `core.bare=true`, and
boolean `core.filemode`/`core.logallrefupdates`. Do not persist remotes, includes,
custom hooks/configuration, symlinks, or alternate object stores. A local
producer may use invocation-only `git -c safe.directory=<owned-path> ...`
settings when publishing a synthetic commit to the bare repository.
`gitfixture -check -repository /fixture/repository.git` validates startup without
opening a listener. The lab runs this with no network before creating nodes.

The only accepted endpoints are:

* `GET /repository.git/info/refs?service=git-upload-pack`
* `POST /repository.git/git-upload-pack` with the Git upload-pack content type

Other paths, query spellings, methods, receive-pack, and dumb HTTP are rejected.
Bodies are buffered up to 1 MiB, responses are limited to 32 MiB, repository
contents to 64 MiB/20,000 entries, and two requests may execute concurrently.
The command also applies HTTP read/write and handler timeouts. Git runs through
the standard library CGI handler using fixed Linux Git binaries and a bounded,
explicit environment. It receives no request authorization/cookie headers or
host Git configuration. Git diagnostics are discarded.

`go test ./internal/kubernetes/gitfixture/...` performs real local Git clone and
fetch operations through the HTTP handler, along with rejection tests. Real
Git tests skip when the Linux fixture binaries are unavailable. No external
Git service or cluster is involved.
