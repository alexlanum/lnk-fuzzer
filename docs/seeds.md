# Seed corpus

Coverage-guided structure-aware fuzzing explores outward from seeds, and most subsystem operators
are gated on their structure already being present (`op_precondition` in [`mutate.c`](../mutate.c) —
the propstore operators need a parsed property store, the Darwin operators need a Darwin block, etc.;
see [architecture.md](architecture.md)). So the breadth of subsystem *depth* the fuzzer can reach is
bounded by the structural variety of the corpus: a group with no satisfying seed never gets a live
candidate, no matter how good its operators are.

## Axes

The structural axes are exactly the `LNKLayout` flags the precondition filter consults, plus the
enum varieties in [`model.h`](../model.h):

- **sections** — LinkTargetIDList, LinkInfo (VolumeID / local *vs* CommonNetworkRelativeLink / UNC),
  StringData (Unicode *vs* ANSI), ExtraData.
- **PIDL item types** — CLSID, Volume, FilesystemDir/File, Network Resource/Server/Share. *(Delegate
  and Extension items are not classifiable from `abID[0]` — deserialize.c leaves them `UNKNOWN`; see
  its TODO. They are a deserializer gap, not a seed gap.)*
- **ExtraData blocks** — the 11 signatures (Environment, Console, Console-FE, Tracker, SpecialFolder,
  Darwin, IconEnvironment, PropertyStore, KnownFolder, VistaIDList, Shim) + unknown-signature.
- **PropertyStore depth** — Integer-Named *vs* String-Named scheme; ≥2 storages; ≥2 values in a
  storage (the preconditions for `DUPLICATE_FORMAT_ID` / `EARLY_TERMINATOR` / `DUPLICATE_PID`).

## Classifier

[`tools/classify.c`](../tools/classify.c) runs the project's own `deserialize_lnk` over each seed and
emits the axes above as flat tags, so the corpus-wide union is the set of operator groups with live
candidates somewhere. Build offline (the Makefile's `cc` path) and run:

```
cc -I. tools/classify.c deserialize.c serialize.c mutate.c gen.c lnk_prng.c -lm -lpthread -o /tmp/classify
/tmp/classify seeds/*.lnk | grep -oE 'block:[a-z_]+|pidl:[a-z]+|ps:[a-z0-9+]+|linkinfo:[a-z]+|ansi' | sort | uniq -c
```

## Generators

- [`generate_seeds.py`](../tools/generate_seeds.py) — pylnk3 + struct hybrid, writes the broad
  baseline set to `corpus/seeds/`.
- [`generate_coverage_seeds.py`](../tools/generate_coverage_seeds.py) — struct-only (no pylnk3),
  writes gap-fillers (`cov_*`) straight into `seeds/`. Each emitted seed is validated to (a) parse
  and (b) round-trip deserialize→serialize→deserialize.

> Note: `generate_seeds.py` targets `corpus/seeds/` while the live corpus is `seeds/`. The
> `cov_*` set was authored against `seeds/`, the directory the run commands in
> [running.md](running.md) actually consume. Consolidating the two locations is a loose end worth
> closing.

## Gaps closed in `seeds/`

The collected corpus (~50 real-world `.lnk`) is filesystem/CLSID-heavy — every seed Unicode, almost
all Integer-Named single-storage property stores, only Tracker/PropertyStore ExtraData blocks, no
network PIDLs, one UNC, no String-Named store. `generate_coverage_seeds.py` adds one well-formed
seed per missing variety: Darwin, KnownFolder, SpecialFolder, Console/Console-FE, Shim,
Environment/IconEnvironment, VistaIDList, unknown-signature; String-Named and multi-storage/value
property stores; network PIDL items; a UNC CommonNetworkRelativeLink; and an ANSI seed. After this,
every operator group with a producible precondition has at least one satisfying seed.
