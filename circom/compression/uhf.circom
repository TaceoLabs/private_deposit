pragma circom 2.2.2;

template UHF(N) {
    signal input alpha;
    signal input beta;
    signal input x[N];
    signal output gamma;

    assert(N >= 1); // The degree of the polynomial is at least zero

    signal seed <== alpha + beta;
    signal muls[N];
    muls[N - 1] <== 0;
    for (var i = N - 1; i > 0; i--) {
        muls[i - 1] <== seed * (muls[i] + x[i]);
    }
    gamma <== muls[0] + x[0];
}
