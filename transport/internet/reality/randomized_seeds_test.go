package reality

// randomizedSeeds are the fixed seeds of
// transport/internet/tls/randomized_seeds_test.go: with the stock uTLS
// generator and the weights Xray used to give it, they draw each combination
// of X25519MLKEM768 in supported_groups and its key share.
var randomizedSeeds = []struct {
	name, seed string
}{
	{"hybrid group and key share", "601028d9604f1e4dbb1898ce3a20a09949e7a0ff1006d2261f2adada0fdb0578"},
	{"hybrid group without key share", "417dcd23baffdb629c8f220af5b644b53732d59ac67524aa3c00b04482b1dab1"},
	{"hybrid key share without group", "4f4f221b2c049b52426343c0f90fd4d260e94821c1910cd4f0fd029d59211057"},
	{"classic groups and key shares", "32b8ac4901174b2856e670e893f5568c8a0bab62dcd1e030c21290161c750b27"},
}
