pragma circom 2.2.2;

include "poseidon2_sponge.circom";
include "uhf.circom";

template Compression(N, T) {
    signal input q[N]; // Original public inputs, now private!
    signal input alpha; // Hash of q using SHA256, public!
    signal output beta;
    signal output gamma;

    // Compute beta using Poseidon2 sponge
    beta <== Poseidon2Sponge(N, T)(q);

    // Compute gamma using UHF
    gamma <== UHF(N)(alpha, beta, q);
}
