// Partial author-artifact adaptation, not our deliverable encryption scheme.
// No changes to the pinned Go/C++ artifact. Optional complete encoded-response
// gate checks its public field relation BEFORE the author's private decoding.
// The additional gate is our conditional research control, not an author claim.
package main

import (
	"RandomLinearCodePIR/dataobjects"
	"RandomLinearCodePIR/mvp"
	"RandomLinearCodePIR/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"sort"
	"time"
)

const prime uint32 = 65537

type input struct {
	Rows      []string `json:"rows"`
	IDs       []uint64 `json:"ids"`
	Queries   []string `json:"queries"`
	Dimension int      `json:"dimension"`
	KeyOnly   bool     `json:"key_only"`
	Verified  bool     `json:"verified"`
}

type gate struct {
	seeds      [][]byte
	hints      [][]uint32
	m, n, b, s int
	spent      map[int]bool
	attempts   int
}

func challenge(seed []byte, m int) []uint32 {
	block, err := aes.NewCipher(seed)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	result := make([]uint32, 0, m)
	// Reject UINT32_MAX: 2^32-1 = 65535 * 65537. Residues are uniform
	// in the ideal random-byte hybrid. Seeds/challenges never leave the client.
	for len(result) < m {
		buf := make([]byte, 4*(m-len(result)))
		stream.XORKeyStream(buf, buf)
		for i := 0; i < len(buf); i += 4 {
			x := binary.LittleEndian.Uint32(buf[i : i+4])
			if x != ^uint32(0) {
				result = append(result, x%prime)
			}
		}
	}
	return result
}

func makeGate(matrix *dataobjects.Matrix, s, b int) *gate {
	// Nine trials: 1024 / 65537^9 < 2^-128, conditional on hidden
	// independent field challenges/trusted setup and bounded verification only.
	g := &gate{m: int(matrix.Rows), n: int(matrix.Cols), s: s, b: b, spent: make(map[int]bool)}
	for r := 0; r < 9; r++ {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			panic(err)
		}
		rho := challenge(seed, g.m)
		acc := make([]uint64, g.n)
		for block := 0; block < s; block++ {
			for row := 0; row < g.m; row++ {
				start := (block*g.m + row) * b
				for j := 0; j < b; j++ {
					acc[block*b+j] += uint64(rho[row]) * uint64(matrix.Data[start+j])
				}
			}
		}
		hint := make([]uint32, g.n)
		for j, v := range acc {
			hint[j] = uint32(v % uint64(prime))
		}
		g.seeds = append(g.seeds, seed)
		g.hints = append(g.hints, hint)
	}
	return g
}

func (g *gate) verify(id int, query, response []uint32) bool {
	if g.attempts >= 1024 || g.spent[id] {
		panic("verification budget/identifier consumed")
	}
	g.attempts++
	g.spent[id] = true // Burn malformed/rejected attempts too.
	if len(query) != g.n || len(response) != g.s*g.m {
		return false
	}
	for _, x := range query {
		if x >= prime {
			return false
		}
	}
	for _, x := range response {
		if x >= prime {
			return false
		}
	}
	for r, seed := range g.seeds {
		rho := challenge(seed, g.m)
		for block := 0; block < g.s; block++ {
			var actual, expected uint64
			for row, x := range rho {
				actual += uint64(x) * uint64(response[block*g.m+row])
			}
			for j := 0; j < g.b; j++ {
				expected += uint64(g.hints[r][block*g.b+j]) * uint64(query[block*g.b+j])
			}
			if actual%uint64(prime) != expected%uint64(prime) {
				return false
			}
		}
	}
	return true
}

func word(text string, dimension int) *big.Int {
	x, ok := new(big.Int).SetString(text, 16)
	if !ok || x.Sign() < 0 || x.BitLen() > dimension {
		panic("invalid binary row/query")
	}
	return x
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	if len(in.Rows) < 1 || len(in.Rows) > 16384 || len(in.IDs) != len(in.Rows) || len(in.Queries) < 1 || len(in.Queries) > 128 || in.Dimension < 1 || in.Dimension > 512 {
		panic("invalid bounded fixture")
	}
	seen := make(map[uint64]bool)
	for _, id := range in.IDs {
		if seen[id] {
			panic("duplicate stable ID")
		}
		seen[id] = true
	}
	l, k, s, b := utils.Prms(128, 4.0, in.Dimension)
	n := l + k
	if n != s*b || l < uint32(in.Dimension) {
		panic("invalid author dimensions")
	}
	pi := &mvp.SlsnMVP{Params: mvp.SlsnParams{Field: dataobjects.NewPrimeField(prime), P: prime, S: s, B: b, K: k, L: l, N: n, M: uint32(len(in.Rows))}}
	start := time.Now()
	matrix := dataobjects.Matrix{Rows: uint32(len(in.Rows)), Cols: l, Data: dataobjects.AlignedMake[uint32](uint64(len(in.Rows)) * uint64(l))}
	for i, text := range in.Rows {
		x := word(text, in.Dimension)
		for j := 0; j < in.Dimension; j++ {
			matrix.Data[i*int(l)+j] = uint32(x.Bit(j))
		}
	}
	inputS := time.Since(start).Seconds()
	start = time.Now()
	sk := pi.KeyGen(5401)
	keyS := time.Since(start).Seconds()
	start = time.Now()
	mask := pi.GenerateTDM(sk)
	maskS := time.Since(start).Seconds()
	start = time.Now()
	encoded := pi.Encode(sk, matrix, mask)
	encodeS := time.Since(start).Seconds()
	if in.KeyOnly {
		sk.PreLoadedMatrix = nil
	}
	var checker *gate
	gateS := 0.0
	if in.Verified {
		start = time.Now()
		checker = makeGate(encoded, int(s), int(b))
		gateS = time.Since(start).Seconds()
	}
	samples := make([]map[string]any, 0, len(in.Queries))
	for ordinal, text := range in.Queries {
		q := word(text, in.Dimension)
		vec := dataobjects.AlignedMake[uint32](uint64(l))
		offset := 0
		for j := 0; j < in.Dimension; j++ {
			if q.Bit(j) == 0 {
				vec[j] = 1
			} else {
				vec[j] = prime - 1
				offset++
			}
		}
		begin := time.Now()
		start = time.Now()
		query, aux := pi.Query(sk, vec)
		queryS := time.Since(start).Seconds()
		start = time.Now()
		response := pi.Answer(*encoded, *query)
		answerS := time.Since(start).Seconds()
		verifyS := 0.0
		if checker != nil {
			start = time.Now()
			if !checker.verify(ordinal, query.Vec, response) {
				panic("honest response rejected")
			}
			verifyS = time.Since(start).Seconds()
		}
		start = time.Now()
		decoded := pi.Decode(sk, response, *aux)
		decodeS := time.Since(start).Seconds()
		start = time.Now()
		scores := make([]int, len(decoded))
		order := make([]int, len(decoded))
		for i, v := range decoded {
			scores[i] = int((v + uint32(offset)) % prime)
			if scores[i] > in.Dimension {
				panic("invalid exact score")
			}
			order[i] = i
		}
		sort.Slice(order, func(i, j int) bool {
			a, b := order[i], order[j]
			if scores[a] != scores[b] {
				return scores[a] < scores[b]
			}
			return in.IDs[a] < in.IDs[b]
		})
		top := make([][2]uint64, 0, 3)
		for _, i := range order[:min(3, len(order))] {
			top = append(top, [2]uint64{uint64(scores[i]), in.IDs[i]})
		}
		selectS := time.Since(start).Seconds()
		sample := map[string]any{"ordinal": ordinal, "query_s": queryS, "server_s": answerS, "verify_s": verifyS, "decode_s": decodeS, "score_conversion_and_top3_s": selectS, "online_s": time.Since(begin).Seconds(), "scores": scores, "top3": top}
		if ordinal == 0 && checker != nil {
			forged := append([]uint32(nil), response...)
			forged[0] = (forged[0] + 1) % prime
			if checker.verify(1000, query.Vec, forged) || checker.verify(1001, query.Vec, response[:len(response)-1]) {
				panic("invalid response accepted")
			}
			sample["tampered_and_truncated_rejected_before_private_decode"] = true
		}
		samples = append(samples, sample)
	}
	hintsBytes := 0
	if checker != nil {
		hintsBytes = 9 * (32 + int(n)*4)
	}
	// bits.Len32 is recorded for body accounting; the native API uses 4-byte
	// words. No sockets, packed serialization, RSS or security certification.
	result := map[string]any{"profile": map[string]any{"p": prime, "field_bits": bits.Len32(prime), "m": len(in.Rows), "l": l, "k": k, "n": n, "s": s, "b": b, "parameter_rule": "author utils.Prms(128,4.0,d); research heuristic, not assurance"},
		"setup":                   map[string]float64{"binary_input_matrix_s": inputS, "key_s": keyS, "TDM_mask_s": maskS, "encode_s": encodeS, "complete_gate_s": gateS},
		"native_word_body_models": map[string]any{"query_bytes": int(n) * 4, "response_bytes": int(s) * len(in.Rows) * 4, "encoded_index_bytes": len(encoded.Data) * 4, "client_preloaded_code_bytes": len(sk.PreLoadedMatrix) * 4, "additional_private_gate_bytes": hintsBytes, "key_seed_and_context_bytes_model": 96},
		"key_only":                in.KeyOnly, "verified": in.Verified, "samples": samples,
		"scope": "Pinned author HBC primitive; optional own pre-decode full encoded-response conditional gate. No author source edits. Author math/rand/64-bit seed sampling is an experimental artifact, not production cryptographic assurance."}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
