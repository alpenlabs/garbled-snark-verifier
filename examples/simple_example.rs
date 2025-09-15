// Groth16-based gate-count example emitting the JSON schema used by CI badges.
// Modeled after examples/groth16_mpc.rs, but focused on counting and JSON output.

use std::env;

use garbled_snark_verifier::{circuit::{streaming::{CircuitBuilder, StreamingResult, EncodeInput, modes::CircuitMode}, CircuitInput}, CircuitContext, Gate, WireId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;


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

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for SimpleInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        for (i, &value) in self.values.iter().enumerate() {
            cache.feed_wire(repr[i], value);
        }
    }
}

fn main() {
    let _args: Vec<String> = env::args().collect();

    // Deterministic RNG for reproducibility
    let _rng = ChaCha20Rng::seed_from_u64(12345);

    let input = SimpleInput {
        values: [true, true, false, true], // Example input values
    };

    let (result, gate_count) = {
        let result: StreamingResult<_, _, bool> = CircuitBuilder::streaming_execute(
            input,
            1_000,
            |ctx, wires| {
                // Perform 4-input AND: (a AND b) AND (c AND d)
                let ab = ctx.issue_wire();
                let cd = ctx.issue_wire();
                let result = ctx.issue_wire();

                ctx.add_gate(Gate::and(wires[0], wires[1], ab));
                ctx.add_gate(Gate::and(wires[2], wires[3], cd));
                ctx.add_gate(Gate::and(ab, cd, result));

                result
            },
        );

        (result.output_value, result.gate_count)
    }; 

    let total_gates = gate_count.total_gate_count();
    let nonfree_gates = gate_count.nonfree_gate_count();
    let free_gates = total_gates.saturating_sub(nonfree_gates);

    println!("\n=== GATE COUNT ===");
    println!("non-free: {}", nonfree_gates);
    println!("free:     {}", free_gates);
    println!("total:    {}", total_gates);
    println!("result:   {}", result);
}
