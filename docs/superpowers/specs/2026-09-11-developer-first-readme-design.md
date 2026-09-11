# Developer-First README Redesign

## Objective

Redesign the English and Chinese GitHub landing pages so an ordinary developer can understand SentinelFlow, see that it is a working product, and run it locally within a few minutes. The README should improve discovery and star conversion without presenting the repository as a production-certified SOAR.

## Audience

The primary reader is a general software developer browsing GitHub. They may be interested in AI agents, security automation, FastAPI, React, or Docker, but should not need prior SOC or SOAR knowledge.

Secondary readers are security engineers evaluating the architecture and contributors deciding whether the project is credible enough to extend.

## Success Criteria

- The first viewport answers what SentinelFlow is, why it is interesting, and how to try it.
- A reader can identify the complete product flow without learning internal terminology first.
- The default quickstart remains accurate, offline, and free of API-key requirements.
- Product claims are backed by repository facts such as test coverage, browser tests, PostgreSQL tests, CI, and the default mock execution boundary.
- English and Chinese README files have equivalent structure and claims.
- Existing security limitations remain prominent and unambiguous.
- No badge, benchmark, screenshot, demo URL, integration status, or production claim is invented.

## Recommended Positioning

Lead with SentinelFlow as a runnable, open-source security-response workflow rather than an abstract alert-orchestration platform:

> Turn a raw security alert into a scored incident, an AI-assisted response recommendation, a human-approved action, and an auditable outcome — locally, with no API key required.

The Chinese version will carry the same meaning in natural Chinese rather than translating word for word.

The differentiation is the governed execution chain, not AI alone. The page should make these points easy to scan:

- deterministic and explainable risk scoring;
- AI recommendations constrained by a fixed protocol;
- approval and execution are separate facts;
- durable dispatch records survive ambiguous failures;
- external effects are confirmed independently from request delivery;
- the default demo is offline and produces no outbound action.

## Information Architecture

The two README files will use the following order.

### 1. Hero

- Product name and one-sentence value proposition.
- Short supporting sentence describing FastAPI, React, PostgreSQL, and the offline demo.
- A small, factual badge row using only existing repository and CI information.
- A concise call to action linking to Quickstart, Architecture, Demo Flow, and Contributing.

The hero will avoid broad phrases such as enterprise-ready, autonomous SOC, production-grade, or AI-powered everything.

### 2. Product Preview

Use an existing repository image if it accurately represents the current console. If no suitable current screenshot exists, use a compact text flow instead of creating a misleading mockup.

The preview must show the product journey:

```text
Alert -> Normalize -> Deduplicate -> Risk -> Incident
      -> AI Recommendation -> Human Approval -> Execute -> Audit
```

### 3. Why Developers Try It

Present four to six short benefits:

- complete end-to-end workflow rather than a chat-only AI demo;
- no external security platform or model key required for the default run;
- explicit safety controls around side effects;
- adapters and provider interfaces that can be extended;
- repeatable Docker startup and meaningful automated tests;
- readable architecture and audit trail for learning purposes.

### 4. Three-Minute Quickstart

Keep Docker as the primary path. The section will:

- state the exact prerequisite;
- show clone, directory change, and quickstart commands;
- list the frontend, API, and API-doc URLs;
- explain what successful startup proves;
- link to native setup and troubleshooting instead of placing every alternative above the fold.

Commands and URLs must remain byte-for-byte compatible with the current scripts and Compose configuration.

### 5. Demo Journey

Explain one concrete scenario in numbered steps, from alert ingestion through the final audit record. This section should translate security terminology for general developers and show where deterministic logic, AI, and human input each participate.

### 6. Feature Groups

Group features by user-visible capability instead of listing implementation objects:

- Alert pipeline
- Explainable risk and incidents
- AI assistance
- Governed response execution
- Audit and observability
- Local-first integrations

Each group will contain at most three concise bullets and link to deeper documentation where useful.

### 7. Architecture

Retain a compact architecture diagram and a short technology table. Detailed state machines, database constraints, compensation semantics, and adapter contracts should link to `docs/architecture.md` instead of dominating the landing page.

### 8. Engineering Evidence

Present release evidence with a timestamp or release label so the numbers are not mistaken for permanently live values:

- backend default tests;
- frontend tests and typecheck;
- PostgreSQL durable tests;
- browser end-to-end tests;
- measured backend coverage;
- nine CI jobs and branch protection.

Link the numbers to the final readiness report and CI rather than repeating long methodology notes.

### 9. Safety Model and Limitations

Use two adjacent subsections:

- Safety by design: deterministic risk, advisory AI, one-shot approval, authenticated execution, durable attempts, redaction, and default mock adapters.
- Current limits: no edge/session layer, no production certification, unverified real-adapter outcome closure, SQLite development limitations, and incomplete Wazuh normalization/read adapters.

The limitations must stay visible on the main README. They must not be moved exclusively into another document.

### 10. Roadmap and Contribution

Use a short roadmap tied to real production-readiness gaps:

- production identity/session boundary;
- one fully verified external integration loop;
- scalable audit and approval read models;
- stronger supply-chain pinning.

Contributing instructions should offer approachable entry points for general developers and link to `CONTRIBUTING.md` and `SECURITY.md`.

### 11. Closing Call to Action

End with one restrained request:

> If the project gives you a useful reference for building safer AI-assisted automation, consider starring it so other developers can find it.

Avoid repeated star requests, fake social proof, urgency, or decorative counters with no repository source.

## Content Rules

- Prefer short paragraphs, descriptive headings, and concrete verbs.
- Define SOC and SOAR the first time they are used or avoid them.
- Keep the main README useful on mobile and skimmable in under two minutes.
- Keep code blocks limited to commands a reader can execute.
- Do not expose `.env` secrets or show insecure production defaults.
- Do not claim an integration works in production when only its adapter contract or mock tests are verified.
- Do not call the project autonomous; every external action requires an explicit execution request and production authentication.
- Preserve links to detailed operational and security documentation.

## Assets

The existing `frontend/src/assets/hero.png` may be used only after checking that it reflects the current interface. If it is stale or is a decorative asset rather than a useful product preview, the first implementation will omit it and retain the text flow. Generating a new screenshot or GIF is outside this initial README rewrite because it requires running and visually verifying the application.

## Files in Scope

- `README.md` — English landing page rewrite.
- `README.zh-CN.md` — structurally equivalent Chinese landing page rewrite.
- Existing documentation may be linked but will not be broadly rewritten.
- No application code, API behavior, deployment configuration, or external adapter will change.

## Validation

- Compare every command, port, feature claim, limitation, test count, and release number against the repository at the implementation commit.
- Check every relative Markdown link resolves to a tracked path.
- Confirm the English and Chinese section structures match.
- Scan both files for unsupported production claims and stale internal process language.
- Run the repository's whitespace and Markdown-oriented quality checks that do not require external services.
- Review the rendered first two viewports for hierarchy, wrapping, and scanability before completion.

## Out of Scope

- Changing the GitHub repository description, topics, social preview, or release notes.
- Producing or publishing a hosted demo.
- Creating screenshots or videos without running the current UI.
- Changing implementation behavior to make a README claim true.
- Hiding known limitations to improve conversion.

