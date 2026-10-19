# Git-owned 5.1 artifact component

Run `node scripts/fleet-group-git-lab.mjs` with no arguments. It creates a new
unprivileged, network-disabled local Docker fixture using the digest-pinned
tooling in this directory. It has no application API/database, host ports,
cloud credentials, AWS provider or emulator. The original V5 artifact lab and
its evidence remain unchanged.

The new, explicitly versioned 5.1 parent signs a manifest of real local Git
commits. Every tree contains exactly `main.tf.json` and
`desired.auto.tfvars.json`: the former stays byte-for-byte fixed, while the
latter commits each stage's desired model values. The preparation stage uses
the approved base; the 25 changed forward stages create new commits before
approval. The proposal ref retains this history. There is no remote Git fetch
or remote-HEAD authenticity claim.

A fresh linked execution worktree starts at the approved base. Before each
transition the producer checks its ref, index, exact two files and workspace
closure. It uses native `git update-ref <ref> <target> <expected-predecessor>`
and a two-tree `read-tree -u -m` update that refuses dirty changed files. It
never force-resets or force-checks out over manual work. Any Git-only or
unknown-apply interruption fails closed; this lab supplies no durable intent
or uncertainty reconciler.

Each stage creates a fresh real saved plan against current local state with
no CLI variable flags, `TF_VAR_*`, `TF_CLI_ARGS*`, implicit variable files or
inherited environment. The pinned Terraform CLI reads the committed automatic
variable file. Native Terraform 1.16 saved-plan configuration snapshots omit
values files; the independent semantic review instead binds their exact Git
blob/tree/commit and native plan variables. The reviewed binary is applied
unchanged and the actual state lineage, serial and model are checked.

The final extra (27th) apply is the exact inverse of **one owned final child**
using a new commit whose parent is the current controlled head. It does not
rewind history and is **not whole-program rollback**. Current ownership is an
explicit local component model derived from the observed fixture apply; it
does not claim a durable or independently authenticated ownership service.
No health windows are waited, no ownership is consumed, and no fixture
signature or declared/point-history IDs grant native execution or savings.

Negative cases cover a manual ref move (CAS must reject without overwriting),
an edited configuration, an untracked variable input, manually changed state
bytes, uncommitted desired bytes and a CLI variable override. Test actors undo
only their own unissued edits; that cleanup is not program recovery. A separate
owned state clone also receives a real pinned Terraform plan and then a manual
serial change: applying that exact stale binary must produce Terraform's native
stale-plan refusal without changing the cloned state or the forward model. The
probe is discarded afterward and does not relax the main attestor's fixed
state path or invocation contract.

Raw Git/Terraform artifacts stay in tmpfs or AES-256-GCM ciphertext in the
restricted run directory. A private local key and append-only hash/context
index permit authenticated readback after the producer exits. The runner
decrypts only in memory, verifies every retained object, validates exact owned
Docker cleanup, then writes `acceptance.json`. It does not validate hosted KMS,
S3 Object Lock, real 025/027 source resolution, pipeline OIDC, real-clock
member/SLO/demand windows, complete program recovery or financial outcomes.
Artifacts remain under `work/private/fleet-group-git/<run-id>/`.
