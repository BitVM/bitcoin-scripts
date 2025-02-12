Steps to test:
1. Generate Partial Scripts
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_compile --exact --nocapture
2. Generate Assertions
RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_generate_assertions --exact --nocapture 
3. Validate generated Assertions
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_validate_assertions --exact --nocapture
4. Manually Corrupt each Assertion one at a time and Disprove invalid assertion
RUST_MIN_STACK=104857600 RUST_BACKTRACE=full cargo test --package bitvm --lib -- groth16::g16::test::test_fn_disprove_invalid_assertions --exact --nocapture  


Contents:
api - interface between verifier and external module (like bridge)
assert - functions to generate intermediate values in each chunks used during assertion or disprove
assigner - interface to assign Assertions
blake3compiled - wrapper to blake3_u4 hasher
compile - functions to generate tapscripts
elements - data structure to represent inputs and outputs of each chunk
primitives - utility functions [will likely refactor]
segment - data structure to represent each chunk [script, inputs and outputs, identifiers]
taps_msm - tapscripts for MSM
taps_mul - tapscripts for Fp12 multiplications
taps_point_ops - tapscripts for point operations
taps_premiller - miscellaneous tapscripts external to Miller Loop
wots - wrapper to winternitz methods

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

Point Operation Inside Miller Loop:
Given $T_4, Q_4, P_2, P_3, P_4$, calculate product of line evaluations and new T4 i.e.

$T_4 \leftarrow T_4 + Q_4$

$le \leftarrow l_2(P_2). l_3(P_3). l_4(P_4)$

The above equation doesn't fit inside a single tapscript and has been broken into two fragments.
tap_point_ops::chunk_point_ops_and_mul & tap_point_ops::chunk_complete_point_eval_and_mul

-----
chunk_point_ops_and_mul does the following in order:

- $T_4 \leftarrow T_4 + Q_4$

- $le_4 \leftarrow l_4(P_4) $

- $le_3 \leftarrow l_3(P_3) $

- $le_{34} \leftarrow le_3.c1 \space  X \space le_4.c1 $

- $le_{3plus4} \leftarrow le_3.c1 \space + \space le_4.c1 $

- $le_2 \leftarrow l_2(P_2) $

Here $T_4, Q_4 \in G_2 $

$P_2, P_3, P_4 \in G_1$

$le_4, le_3, le_2 \in Fp_{12} $ and are sparse elements

$ le_3.c1 \space  X \space le_4.c1 $ is a product of second coefficient of each of the $Fp_{12}$ elements

So, $ le_3.c1, le_4.c1, le_{3plus4} le_{34} \in Fp_6$

Output of this chunk is $T_4, le_{3plus4}, le_{34}, le_2 $

---------
chunk_complete_point_eval_and_mul does the following in order

- $le_{3times4} \space X \space le_{3plus4} =?= le_{34}$

where $le_{3times4} = (le_3 \space X \space le_4).c1$

- $le \leftarrow le_{3times4} \space X \space le_2 $

Output of this chunk is $le$

---------

Therefore we have $le$ as the product of line evaluations output from this chunk and $T_4$ as the $G_2$ accumulator.
The subtlety here is that we have had to split the multiplication between $le_3$ and $le_4$ into two parts. The first chunk generates partial output (requiring 1 $Fp_6$ mul) and the second part uses these partial values to generate the complete output of product of $le_3$ and $le_4$ which is $le_{3times4}$

---------



Merkelize Bitcommitments:

The output of chunk_point_ops_and_mul is $A \leftarrow T_4$ and $B \leftarrow$ {$le_{3plus4}, le_{34}, le_2$ } which can later be used by itself for point addition. $A$ and $B$ are used separately in different tapscripts. For example, chunk_complete_point_eval_and_mul only requires $B$ to compute $le$ and chunk_point_ops_and_mul only requires $A$ to obtain new value of $T_4$

This is why we merkelize the output of chunk_point_ops_and_mul, bitcommit to merkle root and reveal pre-image of the relevant node {A or B} and hash of sibling node {B or A} respectively. This merkelization saves us from having to load the entire values (both A and B) in each of the tapscripts and also saves us from having to compute the sibling hash itself.

------------

Optimization on product of Fp_12 accumulator $f$ and line evaluation $le$

line evaluations are of the form $le = (1, le.c1) $ where $le.c1 = (le.c1.c0, le.c1.c1, 0)$

Because le.c1 has zero as the third coefficient, you can get some saving.

Fp6-Sparse-Sparse Mul when we have to multiply two line evaluations
Fp6-Sparse-Dense Mul when we have to multiply a line evaluation with $f$
Fp6-Dense-Dense Mul when we have to multiply a $f$ and $g$ where neither of them is known in advance to have zero

Fp6-Sparse-Sparse Mul requires 6 tmul hints and around 680K Script. Lesser number of tmul hints here because it internally uses LC4. utils_fq6_ss_mul
Fp6-Sparse-Dense Mul requires 6 tmul hints and around 850K Script. Lesser number of tmul hints here because it internally uses LC4. utils_fq6_hinted_sd_mul
Fp6-Dense-Dense Mul requires 20 tmul hints and around 950K Script. Large number of tmul hints here because it internally uses LC2. bn254::Fq6::hinted_mul

