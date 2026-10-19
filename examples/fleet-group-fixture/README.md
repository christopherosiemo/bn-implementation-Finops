# Isolated group Terraform artifact component

Run `node scripts/fleet-group-terraform-lab.mjs` from the repository root.
The runner accepts no arguments or alternate targets. It uses only a local
Docker daemon, the two digest-pinned public images in this directory, a new
unprivileged container, no network, no host ports and no host credentials.
It does not inspect or connect to the application Compose stack.

The fixture creates and commits one generated `main.tf.json` in a fresh local
Git repository. Only the built-in Terraform provider and three
`terraform_data` resources are present. ASG names and template metadata are
explicit model labels; no AWS provider, emulator or native resource is used.
The 025/027 selection and evidence IDs are visibly synthetic component inputs;
they do not demonstrate database resolution or historical ownership.

After initial local state creation, all 26 bounded model transitions receive
a fresh binary saved plan, actual `terraform show -json`, exact before state,
signed V5 child and semantic artifact review. The inspected saved binary is
then applied unchanged. Actual lineage, serial and resulting input values
are checked. Native Git commit/tree objects and the committed configuration
bytes bind the local object graph; this does not authenticate a remote HEAD.
The 9,600 seconds of declared observation windows are **not
waited or accepted** by this component lab. It provides no real-clock health,
pipeline identity, durable ownership, budget-reservation store, economic
verification or customer execution acceptance.

Raw state, plans and private fixture signing keys stay in container tmpfs.
Only AES-256-GCM encrypted artifacts leave the container. Each immutable local
object binds run, child, kind and plaintext hash as authenticated data and is
read back, decrypted and compared before success. The random local-only key
is retained separately in the private run directory. A private append-only
metadata index preserves the authenticated context, sizes and hashes needed
to decrypt retained objects, including a failed capture; it contains no raw
plan/state values or key. This is not hosted KMS
commissioning or S3 Object Lock acceptance. Public result metadata and a
source/image-bound acceptance manifest identify the component boundary.
On Windows the private directory ACL excludes inherited access; on Linux the
directory and key use modes 0700 and 0600.

Artifacts remain under `work/private/fleet-group-terraform/<run-id>/`.
No raw plans/state are printed. Owned Docker objects are validated and removed
before a PASS manifest is written. Failure diagnostics remain private and do
not produce a PASS record. Do not reuse the local encryption key or synthetic
approvals as production credentials or evidence.
