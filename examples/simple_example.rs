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


#[derive(Clone)]
struct SimpleInput {
    values: [bool; 4],
}

impl CircuitInput for SimpleInput {
    type WireRepr = [WireId; 4];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        [issue(), issue(), issue(), issue()]
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.to_vec()
    }
}

impl<H: garbled_snark_verifier::GateHasher> EncodeInput<GarbleMode<H>> for SimpleInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H>) {
        for (i, &value) in self.values.iter().enumerate() {
            // Convert boolean to GarbledWire using the cache's wire constant
            let garbled_value = if value {
                cache.true_value()
            } else {
                cache.false_value()
            };
            cache.feed_wire(repr[i], garbled_value);
        }
    }
}

// Evaluator input type that holds garbled wire labels
#[derive(Clone)]
struct SimpleEvaluatorInput {
    wire_labels: Vec<GarbledWire>, // The garbled wire labels from garbler
    values: [bool; 4], // The boolean values that correspond to these labels (privacy-free)
}

impl CircuitInput for SimpleEvaluatorInput {
    type WireRepr = Vec<WireId>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.wire_labels.len()).map(|_| issue()).collect()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.clone()
    }
}

impl<H: garbled_snark_verifier::GateHasher> EncodeInput<EvaluateMode<H>> for SimpleEvaluatorInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H>) {
        for (i, &wire_id) in repr.iter().enumerate() {
            // Privacy-free garbling: evaluator knows the boolean values
            let evaluated_value = EvaluatedWire::new_from_garbled(&self.wire_labels[i], self.values[i]);
            cache.feed_wire(wire_id, evaluated_value);
        }
    }
}

// Simple message to pass data from garbler to evaluator
struct GarblerMessage {
    output_labels: (S, S),
    input_values: [bool; 4], // The actual boolean values (needed for evaluation)
    garbled_input_labels: Vec<GarbledWire>, // The garbled wire labels for inputs
    true_wire: u128,
    false_wire: u128,
}

fn four_input_and_circuit(
    ctx: &mut impl CircuitContext,
    wires: &[WireId; 4]
) -> WireId {
    // Perform 4-input AND: (a AND b) AND (c AND d)
    let ab = ctx.issue_wire();
    let cd = ctx.issue_wire();
    let result = ctx.issue_wire();

    ctx.add_gate(Gate::and(wires[0], wires[1], ab));
    ctx.add_gate(Gate::and(wires[2], wires[3], cd));
    ctx.add_gate(Gate::and(ab, cd, result));

    result
}

fn main() {
    let _args: Vec<String> = env::args().collect();
    let garbling_seed: u64 = rand::thread_rng().r#gen();

    let input = SimpleInput {
        values: [true, true, false, true], // Example input values
    };

    println!("Starting garbled circuit demonstration...");
    println!("Input: {:?}", input.values);

    // Create channel for garbled tables (simplified - no ciphertext accumulation)
    let (garbler_sender, garbler_receiver) = crossbeam::channel::unbounded();
    let (ciphertext_sender, ciphertext_receiver) = crossbeam::channel::unbounded();

    // Garbler thread
    let garbler_input = input.clone();
    let input_values = input.values; // Save the values before moving input
    let garbler = thread::spawn(move || {
        println!("[GARBLER] Starting garbling...");

        let garbling_result: StreamingResult<GarbleMode<AesNiHasher>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(
                garbler_input,
                1_000,
                garbling_seed,
                ciphertext_sender,
                four_input_and_circuit,
            );

        // Get borrowed data first (copies the S values)
        let (label0, label1) = garbling_result.output_labels();
        let output_labels = (*label0, *label1);

        // Then extract owned values (moves them)
        let input_wire_labels = garbling_result.input_wire_values;
        let true_wire = garbling_result.true_wire_constant.select(true).to_u128();
        let false_wire = garbling_result.false_wire_constant.select(false).to_u128();
        let gate_count = garbling_result.gate_count.total_gate_count();

        println!("[GARBLER] Garbling complete. Gates: {}", gate_count);
        println!("[GARBLER] Produced {} input wire labels", input_wire_labels.len());

        let msg = GarblerMessage {
            output_labels,
            input_values, // Use the saved values
            garbled_input_labels: input_wire_labels,
            true_wire,
            false_wire,
        };

        garbler_sender.send(msg).unwrap();
    });

    // Evaluator thread
    let evaluator = thread::spawn(move || {
        let msg = garbler_receiver.recv().unwrap();

        println!("[EVALUATOR] Starting evaluation...");
        println!("[EVALUATOR] Received {} garbled wire labels", msg.garbled_input_labels.len());

        let evaluator_input = SimpleEvaluatorInput {
            wire_labels: msg.garbled_input_labels,
            values: msg.input_values, // Privacy-free: evaluator knows the values
        };

        let evaluator_result: StreamingResult<EvaluateMode<AesNiHasher>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                evaluator_input,
                1_000,
                msg.true_wire,
                msg.false_wire,
                ciphertext_receiver,
                |ctx, wires| {
                    // Convert Vec<WireId> back to [WireId; 4] for our circuit function
                    let wire_array: [WireId; 4] = [wires[0], wires[1], wires[2], wires[3]];
                    four_input_and_circuit(ctx, &wire_array)
                },
            );

        let EvaluatedWire { active_label: _, value: result } = evaluator_result.output_value;

        println!("[EVALUATOR] Evaluation complete. Result: {}", result);
        println!("[EVALUATOR] Gates: {}", evaluator_result.gate_count.total_gate_count());

        (result, evaluator_result.gate_count)
    });

    // Wait for both threads and collect results
    garbler.join().unwrap();
    let (result, gate_count) = evaluator.join().unwrap();

    // Display final results
    let total_gates = gate_count.total_gate_count();
    let nonfree_gates = gate_count.nonfree_gate_count();
    let free_gates = total_gates.saturating_sub(nonfree_gates);

    println!("\n=== FINAL RESULTS ===");
    println!("Input: {:?}", input.values);
    println!("Result: {}", result);
    println!("\n=== GATE COUNT ===");
    println!("non-free: {}", nonfree_gates);
    println!("free:     {}", free_gates);
    println!("total:    {}", total_gates);
}
