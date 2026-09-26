# s253 T3 prompt-assets refusal evidence

Session: s253
Date: 2026-09-26 UTC
Repository under evaluation: research_enforcement_activation
Branch/locus: `/data/s253_rea`, `s253/gate-minus-one`

## Failure class

Signed T3 scorer omits its prompt assets.

## Measured refusal

Standalone T3 was run from `/data/s253_rea` under Rex's 2026-09-25 API authorization. Credentials were loaded into the child process and recorded only as SET or UNSET.

The command exited with raw exit `1` before scoring:

`Error: Sonnet prompt not found at /data/s253_rea/.governance/research/artifacts/t3_sonnet_scoring_prompt.md`

Fresh Moonshots source at `/data/s253_moo` also had no tracked `research/artifacts/t3_*prompt.md` files, so the installed signed scorer can verify while its prompt dependencies are absent.

## Evidence digests

- REA handback: `coaching/s253/HANDBACK_KC100.md`, sha256 `26337e512c8a953446978ac65364f853f48f6a69678230e14db6172bdd5ab365`
- T3 stdout: `coaching/s253/raw/t3_score_stdout.txt`, sha256 `7d086e4d172b536becbd893647815f8bf5fcdd88c4af639d8256efbb99b5ac7c`
- T3 rc: `coaching/s253/raw/t3_score_rc.txt`, sha256 `4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865`
- T3 credential status: `coaching/s253/raw/credential_status_t3.txt`, sha256 `7994574df2a6865e36d009ee1f46c7d743f3e280f2ec27fb6c957c6a1c06e260`

## Status

Open. This evidence row records the observed refusal; it does not claim a repaired mechanism. The repair must enroll the prompt assets as signed managed members or change the scorer to resolve an authenticated prompt source.
