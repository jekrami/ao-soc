use codegraph for indexing and grepping , discovering the files and logic

## Architecture diagrams — keep both languages in sync

`docs/AI-SOC-architecture-en.svg` and `docs/AI-SOC-architecture-fa.svg` are the same
diagram in English and Persian. **They are a pair. Never update one without the other,
in the same commit.**

`docs/AI-SOC-dataflow-en.svg` and `docs/AI-SOC-dataflow-fa.svg` are a **second** such
pair and follow every rule in this section. They answer a different question: the
architecture pair says *what is built*, layer by layer; the data-flow pair traces *one
alert in order* — intake, correlation, the queue split, the analysis job, the verdict,
the human, dispatch, the outcome — and, just as importantly, every branch that refuses
(401, 422/400, the 202s, the 502 that still stores the detection, dead letters, the
rules fallback, the autopilot gates, `BLOCKED`, `SIMULATED`). Their footers carry the
`VERSION` of the app rather than the plan version, because they describe the running
pipeline. Update them when the *order of steps or the set of refusals* changes — a new
adapter or connector does not change either drawing.

Update them after every progress that changes what the picture claims:

- a milestone changes status (the coloured dots: green built / amber partial / red not
  built / dashed grey out of scope)
- a component crosses the system boundary in either direction
- a layer, contract or external tool category is added, removed or renamed
- `docs/AI-SOC-PLAN.md` gets a version bump — the footers say "matches plan v<X>" and
  must be corrected to the new number

### Conventions

- **English** is LTR: detection tools on the left, execution on the right, flow enters
  left and leaves right. Gregorian season+year (`Summer 2026`).
- **Persian** is RTL and mirrored: detection tools on the right, execution on the left.
  Solar Hijri season+year (`تابستان ۱۴۰۵`) and Persian digits. Vendor names stay in
  Latin script.
- Persian text is written in **logical order** with `direction: rtl` — the renderer
  shapes it. Never run it through arabic_reshaper or python-bidi.
- **`text-anchor` is logical, not physical.** For RTL text, right-aligning is
  `text-anchor="start"`; `end` puts the anchor on the left. This is inverted from the
  English file and is the easiest thing to get wrong.
- Both carry the authorship footer: writer, co-writing model **with its version**,
  copyright, date, and the plan version they match.

Verify a change by opening the SVG in the browser pane at ~1700px wide and checking for
collisions before committing — text has no automatic wrapping or overflow protection.
