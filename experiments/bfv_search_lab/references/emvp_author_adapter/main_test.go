package main

import (
	"RandomLinearCodePIR/dataobjects"
	"RandomLinearCodePIR/linearcode"
	"RandomLinearCodePIR/mvp"
	"RandomLinearCodePIR/utils"
	"runtime"
	"testing"
)

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected consumed/budget rejection")
		}
	}()
	f()
}

func TestCompleteEncodedGateAndFailureBurn(t *testing.T) {
	matrix := &dataobjects.Matrix{Rows: 3, Cols: 4, Data: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}
	g := makeGate(matrix, 2, 2)
	query := []uint32{2, 3, 4, 5}
	response := []uint32{8, 18, 28, 68, 86, 104}
	if !g.verify(0, query, response) {
		t.Fatal("honest complete response failed")
	}
	forged := append([]uint32(nil), response...)
	forged[0]++
	if g.verify(1, query, forged) || g.verify(2, query, response[:5]) {
		t.Fatal("malformed response accepted")
	}
	mustPanic(t, func() { g.verify(1, query, response) })
	g.attempts = 1024
	mustPanic(t, func() { g.verify(3, query, response) })
}

func TestPinnedNativeCodeRegenerationAndTranspose(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const l, k = 256, 768
	field := dataobjects.NewPrimeField(prime)
	first := linearcode.Generate1DDualMatrix(l, k, field, 5401)
	for attempt := 0; attempt < 4; attempt++ {
		runtime.GC()
		next := linearcode.Generate1DDualMatrix(l, k, field, 5401)
		transposed := linearcode.Generate1DRLCMatrix(l, k, field, 5401)
		for i := 0; i < l; i++ {
			for j := 0; j < k; j++ {
				if next[i*k+j] != first[i*k+j] || next[i*k+j] != (prime-transposed[j*l+i])%prime {
					t.Fatal("native generation is inconsistent")
				}
			}
		}
	}
}

func TestReusingStaticTDMForAnEditWouldExposeTheBinaryToggle(t *testing.T) {
	// Defensive composition regression: the static author protocol is not an
	// authenticated private-update API. Do not patch its plaintext encodings
	// with the same trapdoor mask and assume fresh-encryption privacy.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l, k, s, b := utils.Prms(128, 4.0, 4)
	pi := &mvp.SlsnMVP{Params: mvp.SlsnParams{Field: dataobjects.NewPrimeField(prime), P: prime, L: l, K: k, N: l + k, M: 4, S: s, B: b}}
	sk := pi.KeyGen(5401)
	mask := pi.GenerateTDM(sk)
	base := dataobjects.Matrix{Rows: 4, Cols: l, Data: make([]uint32, 4*l)}
	base.Data[0] = 1
	before := pi.Encode(sk, base, mask)
	changed := base
	changed.Data = append([]uint32(nil), base.Data...)
	changed.Data[0] = 0
	after := pi.Encode(sk, changed, mask)
	// Public block layout puts systematic column zero, row zero at index zero.
	observed := (after.Data[0] + prime - before.Data[0]) % prime
	if observed != prime-1 {
		t.Fatal("same-mask systematic difference did not reveal 1->0")
	}
}
