# SS-AID Formal Verification Artifact

This directory contains the Tamarin Prover model for the SS-AID delegation
protocol. The model encodes credential issuance, delegation with scope
narrowing, revocation, and Policy Enforcement Point verification, and
states the lemmas referenced in the paper's Formal Verification subsection.

## Files

| File | Description |
|------|-------------|
| `ssaid.spthy` | Tamarin theory file (multiset-rewriting model + lemmas) |
| `README.md`   | This file |

## Lemmas

| Lemma | Property | Expected Tamarin status | Closure path |
|-------|----------|------------------------|--------------|
| `executable`        | Sanity: rules admit a non-vacuous trace               | verified | Witness trace from `Issued` → `Delegated` → `Verified` events. |
| `monotonicity`      | Single-step delegation narrows scope                  | verified | Direct rewrite via `equations: subscope(narrow(p, w), p) = true`. |
| `chain_monotone`    | Multi-step delegation chain preserves narrowing       | verified (with `reuse` annotation on `monotonicity`) | Induction on the `Delegated` event chain; each step composes with the rewrite. |
| `revocation_sound`  | A revoked credential cannot be verified after revocation | verified | Trace ordering imposed by the `RevocationCheck` restriction; closure does not depend on adversary capability. |

The "expected" column reflects the authors' analysis of the rule system, not a measured Tamarin run on the submission machine; reviewers running `--prove` are the intended primary verifiers (see Verification Status below).

## Reproduction

Install Tamarin Prover (1.12.0 or later) following the upstream instructions
(<https://tamarin-prover.com/>). Then run:

```sh
tamarin-prover --prove ssaid.spthy
```

Each lemma is reported as `verified`, `falsified`, or `analysis incomplete`.
The expected outcome on the model as written is that all four lemmas
verify; `monotonicity` reduces to the equational rewrite
`subscope(narrow(p, w), p) = true`, and `chain_monotone` follows by
induction on the number of `Delegated` events. `revocation_sound` is
established by the `RevocationCheck` restriction.

### Platform Notes

Tamarin Prover is supported on Linux and macOS natively. On Windows the
route we recommend is WSL2 with the upstream Linux build. There is no
official Tamarin Docker image; community images exist but we have not
verified any of them, so we do not name one here.

### Known limitations of this model

Anyone running `--prove` should read this section first, because closing the
lemmas would mean less than it appears.

1. **The adversary has no channel into the protocol.** The theory contains no
   `In()` facts, and `Out()` appears only for public keys. Credentials move
   between rules as persistent `!Cred` facts and never travel over the network,
   so the Dolev-Yao adversary Tamarin provides cannot read, modify or inject
   them.
2. **`Verify_Action` does not check a signature.** The rule binds the
   credential term and then ignores it. No `verify(...)` equation is evaluated,
   so the model establishes nothing about authentication.
3. **Scope is a fresh name.** Scopes are drawn with `Fr(~scope)`, so the
   adversary cannot construct or manipulate a scope term.
4. **`monotonicity` restates the construction.** The `Delegate` rule builds the
   child scope as `narrow(pscope, ~w)`, and the equational theory makes
   `subscope(narrow(p, w), p)` true by definition, so the lemma follows from
   how the rule is written rather than from any protocol property.
5. **`revocation_sound` relies on the `RevocationCheck` restriction**, which
   already forbids the ordering the lemma rules out.

Taken together, closing these lemmas would show that the rule system is
internally consistent. It would not show that the protocol resists an active
adversary. Making the model meaningful requires at minimum putting credentials
on the network, checking signatures in `Verify_Action`, allowing the adversary
to construct scopes, and adding a key-compromise rule. The article does not
claim these lemmas are machine-checked and does not describe the delegation
rules as formally verified.

### Verification Status

This theory file is provided as a reproducible artifact. The authors
modeled the rules and lemmas as described and rely on Tamarin's
documented semantics for the equational theory and trace restrictions;
the file has not been independently verified by the authors on a
Tamarin installation prior to submission, and reviewers running
`tamarin-prover --prove` are encouraged to report any analysis-incomplete
or falsified outcomes. The paper's Formal Verification subsection
deliberately uses the language "lemmas are stated" rather than
"lemmas are proved" to reflect this status.

## Scope

The model abstracts over BBS+ unforgeability and Groth16 soundness,
treating signatures and proofs as Tamarin's built-in `signing` primitive.
EUF-CMA security of BBS+ and the soundness of Groth16 are taken as
literature assumptions and not re-proven here. Side-channel timing leaks
are likewise out of scope; the constant-time mitigation discussed in the
paper closes the channel at the protocol implementation layer rather
than in the symbolic model.

## License

MIT (see repository root).
