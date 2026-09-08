# Self-improvement

Status: **in progress**, 2026-09-08. The proposal is
[proposals/self-improvement.md](proposals/self-improvement.md); the implementation plan, with
the ten places the source corrected the proposal, is
[proposals/self-improvement-plan.md](proposals/self-improvement-plan.md). This document is
what is built: each section below is written by the slice that built it and claims only what
its tests prove.

## 1. The claim

Ouroboros self-improves when a session running inside it produces a change to its own
behaviour that the model authored, that passed gates the model cannot pass for itself, that
measured better than before on one fixed benchmark, and that is running afterwards without a
human editing code. Humans stay at signing, merging, and promotion.

## 2. The `self` posture

<!-- S4-posture -->

## 3. Slices

### S0. The measure: `bench/self`

<!-- S0 -->

### S1. The `forge` tool

<!-- S1 -->

### S2. Policy promotion by replay

<!-- S2 -->

### S3. The outer loop

<!-- S3 -->

### S4. Ship what it forged

<!-- S4 -->

## 4. Decisions

Numbered `S-D<n>`; each slice appends its own under its marker and never renumbers another's.

<!-- S0-decisions -->

<!-- S1-decisions -->

<!-- S2-decisions -->

<!-- S3-decisions -->

<!-- S4-decisions -->

## 5. Open

<!-- open -->
