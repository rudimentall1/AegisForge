# AegisForge Model Research Blueprint

AegisForge adopts the useful public research methodology visible in dealignai artifacts without copying refusal-removal objectives.

## Research loop

DISCOVER -> HYPOTHESIS -> EXPERIMENT -> BENCHMARK -> CALIBRATE -> REGRESSION -> KEEP/REJECT

## Principles

1. Define measurable behavior before changing a model.
2. Always compare against a reproducible baseline.
3. Prefer the smallest intervention that produces measurable improvement.
4. Test general capability and security capability separately.
5. Treat runtime configuration as part of the model system.
6. Test reasoning modes, context handling, repetition behavior and tool reliability.
7. Reject candidates that improve one metric while causing unacceptable regression elsewhere.
8. Keep every experiment reproducible.

## Initial AegisForge scorecard

- general capability: 30%
- secure code reasoning: 25%
- repository analysis: 20%
- tool/agent reliability: 15%
- runtime efficiency: 10%

## Hard regression gates

- no severe reasoning-loop regression
- no material coding regression
- no material tool-call reliability regression
- no benchmark accepted without a recorded baseline
- no experiment accepted from a single metric

## Research targets

AegisForge should eventually compare:

- base model
- quantized model
- runtime configuration
- reasoning configuration
- candidate weight intervention
- candidate fine-tune/adaptation
- combinations of the above

The objective is not "uncensored at any cost".

The objective is:

security reasoning + coding + repository analysis + agent reliability + efficiency

while preserving general capability.
