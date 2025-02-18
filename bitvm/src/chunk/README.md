To test Full Execution:
RUST_MIN_STACK=104857600 cargo test --package bitvm --lib -- chunk::api::test::full_e2e_execution --exact --nocapture

The following show tests for step wise execution.
The module groth16::g16::test have been commented out for the time being as these tests depend upon sequential exection and as such is not supported by CI.
Use the test abov for single full execution if applicable. Uncomment g16 from module groth16/mod.rs and run the following if step wise flow is necessary.
1. Generate Partial Scripts
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_compile --exact --nocapture
2. Generate Assertions
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_generate_assertions --exact --nocapture 
3. Validate generated Assertions
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_validate_assertions --exact --nocapture
4. Manually Corrupt each Assertion one at a time and Disprove invalid assertion
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_disprove_invalid_assertions --exact --nocapture  

-------
Directory:

api - interface between verifier and external module (like bridge)
api_compiletime_utils - interfacing methods used during bitvm compile time i.e. presigning
api_runtime_utils - interfacing methods used during bitvm runtime i.e. assertion and disprove
assigner - interface to assign Assertions [to support legacy code]
elements - data structure to represent inputs and outputs of each chunk

g16_runner_core - function to generate execute chunked groth16 verifier and collect necessary information
g16_runner_utils - set of functions that wrap tapscripts and is required by g16_runner_core

primitives - utility functions [will likely refactor]
taps_msm - tapscripts for MSM
taps_mul - tapscripts for Fp12 multiplications
taps_point_ops - tapscripts for point operations
taps_premiller - miscellaneous tapscripts external to Miller Loop

wrap_hasher - wrapper to blake3_u4 hasher
wrap_wots - wrapper to winternitz methods

------

Info on tapscripts:

chunk_dense_dense_mul

When implementing multiplication between two elements in $F_{q^{12}}$, 

say $f = 1 + c \cdot J$ and 

$g = 1 + d \cdot J$, 

we can compute 

$f \times g \rightarrow (1+c \cdot J) \times (1+d \cdot J) \rightarrow 1 + c \cdot d \cdot J^2 + (c+d) \cdot J \rightarrow (1+c \cdot d \cdot V) + (c+d) \cdot J \rightarrow  1 + [(c+d)/ (1+c \cdot d \cdot V) \cdot J]$.
$h = f \times g  = 1 + e.J $


Instead of computing, you now verify whether $h == f \times g$ by verifying the following equation:


$e == [(c+d)/ (1+c \cdot d \cdot V) \cdot J]$


$e. (1+c \cdot d \cdot V) == (c+d).J$


In the last equation, $c \cdot d$ requires 1 Fq6 mul, cost of $\cdot V$ is negligible, and $e. (1+c \cdot d \cdot V)$ requires 1 more Fq6 multiplication by c. Therefore 2 Fq6 muls, 1 negligible mul by Fp12Config::NON_RESIDUE (V), but you need to pass c as hint to the tapscript.

------
Multiplying three Fq12 elements in the form: $(1 + a J), (1 + b J), (1 + d J)$

First Segment:

$(1 + c J) = (1 + a J) \times (1 + b J)$

$c = (a + b) / (1 + ab V)$

Second Segment:

$(1 + e J) = (1 + a J) \times (1 + b J) \times (1 + d J) = ( 1 + c J) \times (1 + d J)$

$e = (c + d) / (1 + cd V)$

$e = [(a + b) + d (1 + ab V)] / [(1 + ab V) + (a + b)dV]$


Point Operation Inside Miller Loop:
Given $T_4, Q_4, P_2, P_3, P_4$, calculate product of line evaluations and new T4 i.e.

$T_4 \leftarrow T_4 + Q_4$

$le \leftarrow l_2(P_2). l_3(P_3). l_4(P_4)$

The above equation doesn't fit inside a single tapscript and has been broken into two fragments.
tap_point_ops::chunk_point_ops_and_multiply_line_evals_step_1 & tap_point_ops::chunk_point_ops_and_multiply_line_evals_step_2

-----
chunk_point_ops_and_multiply_line_evals_step_1 does the following in order:

- $T_4 \leftarrow T_4 + Q_4$

- $le_4 \leftarrow l_4(P_4) $

- $le_3 \leftarrow l_3(P_3) $

- $le_2 \leftarrow l_2(P_2) $

Based on the same set of equations in First Segment of Multiplying three Fq12 elements, where a is $le_4$ and b is $le_3$, this chunk outputs (a + b) and (1 + ab V) as outputs of partial multiplication of a and b.

Alongside, updated $T_4$ and $le_2$, the total output becomes $T_4, a+b, ab, le_2 $

---------
chunk_point_ops_and_multiply_line_evals_step_2 does the following in order

This chunk receives the output from previous step and completes the multiplication between line evaluations.

The expected computation is $lev = le_2 \times le_3 \times le_4$.

Based on the same set of equations in Second Segment of Multiplying three Fq12 elements, where d is $le_2$, e is $le$ and a and b are outputs of partial multiplication mentioned above between $le_4$ and $le_3$, we execute validity check in the form given below.

$e \times [(1 + ab V) + (a + b) dV] =?= [(a + b) + d (1 + ab V)] $

Output of this chunk is $lev$

---------

Optimization on product of Fp_12 accumulator $f$ and line evaluation $le$

line evaluations are always in the form $le = (1, le.c1) $ where $le.c1 = (le.c1.c0, le.c1.c1, 0)$

Because le.c1 has zero as the third coefficient, you get some necessary saving in terms of script and stack use (especially during intialization where a lot of tmul hints have to be loaded).

Fp6-Sparse-Sparse Mul when we have to multiply two line evaluations. Output is a dense Fp6 element.
Fp6-Sparse-Dense Mul when we have to multiply a line evaluation with $f$
Fp6-Dense-Dense Mul when we have to multiply a $f$ and $g$ where neither of them is known in advance to have zero coefficient

Fp6-Sparse-Sparse Mul requires 6 tmul hints and around 680K Script. Lesser number of tmul hints here because it internally uses LC4. utils_fq6_ss_mul
Fp6-Sparse-Dense Mul requires 6 tmul hints and around 850K Script. Lesser number of tmul hints here because it internally uses LC4. utils_fq6_sd_mul
Fp6-Dense-Dense Mul requires 20 tmul hints and around 950K Script. Large number of tmul hints here because it internally uses LC2. bn254::Fq6::hinted_mul

Here LC4 is a term used to refer to linear combination of multiplicands and multipliers, with which we get prominent savings in terms of necessary tmul hints.

---------

Merkelize Bitcommitments:

The output of chunk_point_ops_and_multiply_line_evals_step_1 is $A \leftarrow T_4$ and $B \leftarrow$ {$a+b, ab, le_2$ }.
A and B are used separately in two different places for different purposes. 
- It is used in "chunk_point_ops_and_multiply_line_evals_step_2" to complete line evaluation multiplication (i.e. to obtain $lev$ mentioned above).
- It is used in "chunk_point_ops_and_multiply_line_evals_step_1" again in the next iteration to update $T_4$.
We could bitcommit to hash of A and hash of B separately and use them as input where needed, but that would incur 2 bitcommitments per instance of chunk_point_ops_and_multiply_line_evals_step_1. If we bitcommit to hash of concat(A, B), we have larger (avoidable) hashing cost.

What we resort to is akin to Merkle Tree Commitment. We treat A and B as separate merkle leaves and the root of the tree as the value to bitcommit. This way you only provide as input to a tapscript the merkle path i.e. preimage (A or B) in the relevant tapscript, alongside hash of the other value (HashB or HashA) respectively. This proves that the correct values were loaded as input to a tapscript.

In implementation, this means the sibling hash also needs to be passed as a hint alongside the preimage itself to compute the merkle root.

------------

Disprove Logic
``` rust
// parameters are obtained after wots signature verification
fn disprove_core(input, Option<output>, operator_claimed_input_hash, operator_claimed_output_hash) {

    // Computation Layer
    // Stack: [input, output] 
    // Altstack: [operator_claimed_output_hash, operator_claimed_input_hash]

    let input_is_valid = input.is_valid();
    if input.is_valid() {
        if output.is_none() {  // tapscripts output is not passed as hint
            output = fn(input) // output is deterministically computed from input
        } else {
            fn_valid(input, output) // output is determinstically validated from input
        }
        Add_To_Stack(output, input_is_valid)
    } else {
        Add_To_Stack(mock_output, input_is_valid) // None or any value; doesn't matter as precondition (input validity) has failed
    }

    // Hashing Layer
    // Stack: [input, output, input_is_valid] 
    // Altstack: [operator_claimed_output_hash, operator_claimed_input_hash]
    assert(Hash_fn(input), operator_claimed_input_hash); // invalid input was supplied by the operator
    let can_disprove = false;
    if input_is_valid() {
        can_disprove = Hash_fn(output) != operator_claimed_output_hash
    } else {
        ignore(Hash_fn(output)) // doesn't matter what the output is, drop from stack
        ignore(operator_claimed_output_hash)
        can_disprove = true;
    }

    Add_To_Stack(can_disprove)
}
```

------------

Structure of Chunked Verifier

Refer fn chunk::assert::verify_pairing_scripted()

------------

Data Structures
Runtime Inputs and Outputs of chunks of a verifier are represented by the following type:

``` rust
pub enum DataType {
    Fp6Data(ark_bn254::Fq6), 
    G2EvalData(ElemG2Eval),
    G1Data(ark_bn254::G1Affine),
    U256Data(ark_ff::BigInt<4>),
}
```

Fp6Data is used to reprent the second coefficient in Fp12 i.e. a in (1 + a J)
G2EvalData is used to represent output of chunk_point_ops_and_multiply_line_evals_step_1. It includes G2 accumulator, a line-evaluation and result of partial multiplication.
G1Data is used to represent G1Affine elements (curve points).
U256Data is used to represent 256-bit elements that the groth16 verifier receives as input (e.g field elements, curve points, etc). These are validated to be valid field elements or points on curve 
before working on them any further.

``` rust
pub(crate) enum ElementType {
    Fp6,
    G2EvalPoint,
    G2EvalMul,
    G2Eval,
    FieldElem,
    ScalarElem,
    G1,
}
```

FieldElems and ScalarElems are both U256Data underneath but a distinction is needed because they are used differently (i.e. Fq and Fr).

Additionally, as was mentioned in the section "Merkelize Bitcommitments:", we can represent the same underlying type (G2EvalData) differently on different tapscripts. To make this distinction we use ElementType.
To be specific, G2EvalPoint is the exact type chunk_point_ops_and_multiply_line_evals_step_1 receives as Input because it only requires $T_4$ from previous calculation. The rest of the inputs needed for this step are received from different source. Similarly, G2EvalMul is the exact type chunk_point_ops_and_multiply_line_evals_step_2 receives as Input because it requires all but $T_4$. G2Eval is used to represent base form which is an output of these two tapscripts.


------------

Hashing

We use blake3_u4 hasher which requires stack to only contain the message you want to hash. This introduces necessity to move elements back and forth between mainstack and altstack.

The function blake3compiled::hash_messages() adds a hashing layer to the disprove Script for a given type of elements .
It assumes preimages are loaded on stack and their hashes are on altstack.

For example:
Given 
MainStack[Input: Fp6, Output::G1, Bit_InputIsValid] 
Altstack [Fp6Hash, G1Hash]
In simple terms: the function runs [Hash(Input) == Fp6Hash] and [Hash(Output) != G1Hash if Bit_InputIsValid]


-------
Security

20-byte hashes for 160-bit second preimage resistane security. We aren't concerned with collision resistance in bitvm setup.

-------


