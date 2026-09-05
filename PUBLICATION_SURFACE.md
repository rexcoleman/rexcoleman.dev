# Publication surface — rexcoleman.dev

This repository is a **publication surface**. It is the live public site:
a Hugo build whose `content/posts` are published under the author's own
byline, with a cross-post path and a publish script that push finished
posts to other channels. It runs no research cycle and carries no
`RESEARCH_SEED.md`.

It also hosts the signed-release convergence engine under
`.github/write-enforcement/`. That machinery is enforcement authority for
other repositories and is not itself a publication surface; the surfaces
declared below are the reader-facing ones.

This file is the classification record the registered enrollment transition
`existing-nonempty-project-initial-enrollment` reads. Enforcement classification
is derived from tracked published bytes, never from a caller-supplied flag, so
this file is frozen once tracked and any change to it changes what this
repository is declared to be.

## Surfaces this repository owns

- `blog` — `content/posts`, long-form prose under the author's own byline.
- `publication` — the built site as served, the reader-facing object itself.
- `distribution` — `cross-post.py`, `cross-posts/` and `publish.sh`, the
  channel push that puts a finished post in front of readers.

`report` is **not** claimed: this repository publishes finished prose and does
not generate the analysis behind it.

## Classification

<!-- BEGIN_PUBLICATION_CLASSIFICATION -->
```json
{
  "research_type": "write_publish",
  "profile": "write-publish",
  "publication_surfaces": ["blog", "distribution", "publication"]
}
```
<!-- END_PUBLICATION_CLASSIFICATION -->

The block above is machine-read. Exactly one BEGIN/END pair may exist, the JSON
must carry exactly those three keys, and `publication_surfaces` must be a
non-empty duplicate-free subset of `blog`, `distribution`, `publication`,
`report`. Anything else refuses rather than defaulting.

Declaring a surface this repository does not own would be a false claim about
where enforcement has to hold, so the set below is deliberately the measured
set and not the full four.
