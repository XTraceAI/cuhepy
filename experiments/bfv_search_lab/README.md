# BFV search research sandbox

The [experiment plan](../../docs/research/bfv-search-experiment-plan.md) proposes
12 directions from the accepted BFV CUDA baseline. This directory currently
contains **plaintext algebra checks and analytical operation counts**, not a
new encryption scheme, CUDA backend, or performance result.

Run with Python 3.11+ and no additional dependencies:

```bash
python3 experiments/bfv_search_lab/layout_oracles.py \
  --json-out experiments/bfv_search_lab/models/partial-reduction-8192.json
```

The script checks two hypotheses independently of the library:

- E01: keep several disjoint dimension sums in a packed response, then add them
  on the owner. It simulates slot rotations, masks, tile packing and decoding.
- E06: use signed-bit forward/backward coefficient packing to obtain many
  Hamming correlations in one negacyclic polynomial product. It deliberately
  does not solve encrypted result repacking.

The model counts rotations, relinearizations, response ciphertexts and raw
coefficient bytes. Framing, runtime, noise and security are outside its scope.
The tiny dimensions/plaintext moduli in the oracle are arithmetic fixtures.
Partial sums and unmasked correlations also disclose more to the decrypting
client than final distances, as described in the plan.

Change the modeled public workload without generating a large encrypted index:

```bash
python3 experiments/bfv_search_lab/layout_oracles.py \
  --num-vectors 32768 --embed-len 512 --ring-degree 16384
```

The repository excludes experiments from routine Ruff discovery. To check this
script explicitly with the repository lint rules:

```bash
ruff check --config 'force-exclude=false' --config 'exclude=[]' \
  experiments/bfv_search_lab/layout_oracles.py
mypy experiments/bfv_search_lab/layout_oracles.py
```
