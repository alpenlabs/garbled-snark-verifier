# Privacy-Free Garbled Circuit Implementation Guide

This guide provides a comprehensive technical reference for implementing privacy-free garbled circuits using the `garbled-snark-verifier` crate, with focus on authentication and proof-of-computation applications.

## Overview

Privacy-free garbling is a variant where both the garbler and evaluator know the input values. This model is particularly useful for:
- **Authentication protocols**: Proving computation integrity
- **Verification systems**: Confirming correct execution
- **Benchmarking**: Analyzing circuit performance without privacy overhead

The protocol involves a **Garbler** that creates the garbled circuit and an **Evaluator** that verifies the computation using garbled wire labels.

## Core Architecture

### Type System

The implementation relies on several key types:

- **`GarbledWire`**: Wire labels in garbling mode
- **`EvaluatedWire`**: Wire labels in evaluation mode
- **`S`**: Underlying label type used in outputs
- **`WireId`**: Circuit wire identifiers

### Circuit Modes

Each mode has a different `WireValue` type:

```rust
// Garbling: WireValue = GarbledWire
GarbleMode<H: GateHasher>

// Evaluation: WireValue = EvaluatedWire
EvaluateMode<H: GateHasher>

// Execution: WireValue = bool (for comparison)
ExecuteMode
```

This difference is **critical** - trait implementations must match the correct `WireValue` type.

## Implementation Requirements

### 1. Essential Imports

```rust
use std::{env, thread};
use garbled_snark_verifier::{
    AesNiHasher, EvaluatedWire, GarbledWire, S,
    circuit::{
        streaming::{
            CircuitBuilder, StreamingResult, EncodeInput,
            modes::{CircuitMode, EvaluateMode, GarbleMode}
        },
        CircuitInput
    },
    CircuitContext, Gate, WireId
};
use rand::Rng;
```

### 2. Input Type Structure

You need **two separate input types** - one for each mode:

#### Garbler Input Type
```rust
#[derive(Clone)]
struct GarblerInput {
    values: [bool; N], // Your input values
}

impl CircuitInput for GarblerInput {
    type WireRepr = [WireId; N];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        // Create N wire IDs
        [(); N].map(|_| issue())
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.to_vec()
    }
}

impl<H: garbled_snark_verifier::GateHasher> EncodeInput<GarbleMode<H>> for GarblerInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H>) {
        for (i, &value) in self.values.iter().enumerate() {
            let garbled_value = if value {
                cache.true_value()  // NOT cache.true_wire - that's private!
            } else {
                cache.false_value()
            };
            cache.feed_wire(repr[i], garbled_value);
        }
    }
}
```

#### Evaluator Input Type
```rust
#[derive(Clone)]
struct EvaluatorInput {
    wire_labels: Vec<GarbledWire>, // From garbler
    values: [bool; N],             // Known values (privacy-free)
}

impl CircuitInput for EvaluatorInput {
    type WireRepr = Vec<WireId>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.wire_labels.len()).map(|_| issue()).collect()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.clone()
    }
}

impl<H: garbled_snark_verifier::GateHasher> EncodeInput<EvaluateMode<H>> for EvaluatorInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H>) {
        for (i, &wire_id) in repr.iter().enumerate() {
            // Privacy-free: we know both the garbled wire and its boolean value
            let evaluated_value = EvaluatedWire::new_from_garbled(&self.wire_labels[i], self.values[i]);
            cache.feed_wire(wire_id, evaluated_value);
        }
    }
}
```

### 3. Circuit Definition

Define your circuit logic using basic gates:

```rust
fn your_circuit_function(
    ctx: &mut impl CircuitContext,
    wires: &[WireId; N] // Match your input count
) -> WireId {
    // Example: 4-input AND circuit
    let ab = ctx.issue_wire();
    let cd = ctx.issue_wire();
    let result = ctx.issue_wire();

    ctx.add_gate(Gate::and(wires[0], wires[1], ab));
    ctx.add_gate(Gate::and(wires[2], wires[3], cd));
    ctx.add_gate(Gate::and(ab, cd, result));

    result
}
```

### 4. Thread Communication

Set up message passing between garbler and evaluator:

```rust
struct GarblerMessage {
    output_labels: (S, S),                  // Note: S type, not GarbledWire!
    input_values: [bool; N],               // Privacy-free: share values
    garbled_input_labels: Vec<GarbledWire>, // Wire labels for inputs
    true_wire: u128,
    false_wire: u128,
}
```

### 5. Complete Implementation

```rust
fn main() {
    let garbling_seed: u64 = rand::thread_rng().r#gen(); // Note: r#gen due to keyword

    let input = GarblerInput {
        values: [true, true, false, true], // Your input
    };
    let input_values = input.values; // Save before moving

    // Channel setup
    let (garbler_sender, garbler_receiver) = crossbeam::channel::unbounded();
    let (ciphertext_sender, ciphertext_receiver) = crossbeam::channel::unbounded();

    // Garbler thread
    let garbler_input = input.clone();
    let garbler = thread::spawn(move || {
        let garbling_result: StreamingResult<GarbleMode<AesNiHasher>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(
                garbler_input,
                1_000, // Circuit capacity
                garbling_seed,
                ciphertext_sender,
                your_circuit_function,
            );

        // CRITICAL: Get borrowed data BEFORE moving owned data
        let (label0, label1) = garbling_result.output_labels();
        let output_labels = (*label0, *label1); // Copy S values

        // Now safe to move owned data
        let input_wire_labels = garbling_result.input_wire_values;
        let true_wire = garbling_result.true_wire_constant.select(true).to_u128();
        let false_wire = garbling_result.false_wire_constant.select(false).to_u128();

        let msg = GarblerMessage {
            output_labels,
            input_values,
            garbled_input_labels: input_wire_labels,
            true_wire,
            false_wire,
        };

        garbler_sender.send(msg).unwrap();
    });

    // Evaluator thread
    let evaluator = thread::spawn(move || {
        let msg = garbler_receiver.recv().unwrap();

        let evaluator_input = EvaluatorInput {
            wire_labels: msg.garbled_input_labels,
            values: msg.input_values,
        };

        let evaluator_result: StreamingResult<EvaluateMode<AesNiHasher>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                evaluator_input,
                1_000,
                msg.true_wire,
                msg.false_wire,
                ciphertext_receiver,
                |ctx, wires| {
                    // Adapt Vec<WireId> to your circuit's expected array type
                    let wire_array: [WireId; N] = [wires[0], wires[1], /* ... */];
                    your_circuit_function(ctx, &wire_array)
                },
            );

        let result = evaluator_result.output_value.value; // Extract boolean result
        (result, evaluator_result.gate_count)
    });

    // Wait and collect results
    garbler.join().unwrap();
    let (result, gate_count) = evaluator.join().unwrap();

    println!("Result: {}", result);
    println!("Gates: {}", gate_count.total_gate_count());
}
```

## Critical Implementation Issues & Solutions

### 1. Type System Errors

**Error**: `expected GarbledWire, found bool`
```rust
// WRONG
cache.feed_wire(wire_id, true);

// CORRECT
let garbled_value = if value { cache.true_value() } else { cache.false_value() };
cache.feed_wire(wire_id, garbled_value);
```

**Error**: `expected S, found GarbledWire`
```rust
// WRONG
output_labels: (garbled_wire1, garbled_wire2),

// CORRECT - output_labels() returns (&S, &S)
let (label0, label1) = result.output_labels();
output_labels: (*label0, *label1),
```

### 2. Borrowing Issues

**Error**: `cannot borrow after partial move`
```rust
// WRONG - moving before borrowing
let input_labels = result.input_wire_values; // MOVE
let (l0, l1) = result.output_labels(); // BORROW - fails!

// CORRECT - borrow first
let (l0, l1) = result.output_labels(); // BORROW
let output_labels = (*l0, *l1); // COPY
let input_labels = result.input_wire_values; // MOVE
```

### 3. Private Field Access

**Error**: `field 'true_wire' is private`
```rust
// WRONG
cache.true_wire.clone()

// CORRECT
cache.true_value()
```

### 4. Import Path Issues

```rust
// OLD/WRONG
use garbled_snark_verifier::circuit::{streaming::StreamingResult, CircuitBuilder};

// CORRECT
use garbled_snark_verifier::circuit::streaming::{CircuitBuilder, StreamingResult};
```

### 5. Circuit Function Signatures

Different contexts require different signatures:

```rust
// For streaming_garbling/evaluation with closure:
|ctx, wires| your_function(ctx, wires)

// Direct function (if compatible):
your_function

// Type adaptation:
|ctx, wires| {
    let wire_array: [WireId; N] = [wires[0], wires[1], /* ... */];
    your_function(ctx, &wire_array)
}
```

## Gate Types & Performance

### Gate Cost Analysis
- **AND gates**: Non-free (cryptographic operations required)
- **XOR gates**: Free (no ciphertext needed)
- **NOT gates**: Free (label manipulation only)

Example output:
```
gate count: [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
and variants:            3
xor variants:            0
not:                     0
total:                   3
```

### Optimization Strategies
- Minimize AND gates where possible
- Use XOR/NOT combinations when equivalent
- Monitor `nonfree_gate_count()` vs `total_gate_count()`

## Extension Patterns

### Different Boolean Circuits

**OR Gate Example**:
```rust
fn or_circuit(ctx: &mut impl CircuitContext, wires: &[WireId; 2]) -> WireId {
    let result = ctx.issue_wire();
    ctx.add_gate(Gate::or(wires[0], wires[1], result));
    result
}
```

**XOR Chain Example**:
```rust
fn xor_chain(ctx: &mut impl CircuitContext, wires: &[WireId; N]) -> WireId {
    let mut current = wires[0];
    for &wire in &wires[1..] {
        let next = ctx.issue_wire();
        ctx.add_gate(Gate::xor(current, wire, next));
        current = next;
    }
    current
}
```

### Scaling to Larger Circuits

1. **Increase capacity**: Adjust the capacity parameter in `streaming_garbling`
2. **Batch processing**: Process circuits in chunks for memory efficiency
3. **Gate counting**: Monitor performance with `gate_count.total_gate_count()`

## Authentication Applications

Privacy-free garbling enables:
- **Proof-of-computation**: Demonstrate correct execution without revealing computation details
- **Integrity verification**: Verify results match expected computations
- **Benchmarking**: Measure circuit performance and optimization effectiveness

The shared knowledge model allows both parties to verify the computation while maintaining the garbled circuit's tamper-evident properties.