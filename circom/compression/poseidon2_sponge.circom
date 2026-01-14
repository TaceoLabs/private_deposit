pragma circom 2.2.2;

include "poseidon2/poseidon2.circom";

template TACEO_PRECOMPUTATION_Poseidon2SpongeInstance(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

template Poseidon2Sponge(N, T) {
    signal input in[N];
    signal output out;

    assert(T >= 2); // Minimum state size for Poseidon2
    assert(N >= 1); // Must absorb at least one element

    var ds = 0xDEADBEEF;
    var permutations = (N + T - 2) \ (T-1); // ceil( N / (T - 1))
    var states[permutations + 1][T];

    // Initialize the state
    for (var i = 0; i < T - 1; i++) {
        states[0][i] = 0;
    }
    states[0][T - 1] = ds;

    // Absorb and permute
    var absorbed = 0;
    for (var p = 0; p < permutations; p++) {
        var remaining = N - absorbed;
        if (remaining > T - 1) {
            remaining = T - 1;
        }
        for (var i = 0; i < remaining; i++) {
            states[p][i] = states[p][i] + in[absorbed + i];
        }
        absorbed += remaining;
        states[p + 1] = TACEO_PRECOMPUTATION_Poseidon2SpongeInstance(T)(states[p]);
    }
    out <== states[permutations][0];
}
