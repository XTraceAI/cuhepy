//! E109 offline proof control, not a deployed service or homemade HE backend.
//! The owner-local exporter supplies the pinned instance and statement files.
//! Proving and verification are separate library operations in one diagnostic.

use bincode::Options;
use libspartan::{ComputationCommitment, InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::Path, panic::{catch_unwind, AssertUnwindSafe}};

#[derive(Deserialize)]
struct Statement {
    id: usize,
    public_file: String,
    witness_file: String,
    domain_hex: String,
}

#[derive(Deserialize)]
struct Negative {
    label: String,
    proof_id: usize,
    public_file: String,
    domain_hex: String,
}

#[derive(Deserialize)]
struct Manifest {
    instance_file: String,
    variables: usize,
    constraints: usize,
    inputs: usize,
    max_nonzeros: usize,
    output_directory: String,
    statements: Vec<Statement>,
    negatives: Vec<Negative>,
}

fn words(path: &str, count: usize) -> Vec<[u8; 32]> {
    let bytes = fs::read(path).expect("owner-local field file");
    assert_eq!(bytes.len(), count * 32);
    bytes.chunks_exact(32).map(|x| x.try_into().unwrap()).collect()
}

fn domain(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0; 32];
    for (i, at) in out.iter_mut().enumerate() {
        *at = u8::from_str_radix(&hex[2*i..2*i+2], 16).unwrap();
    }
    out
}

fn transcript(hex: &str) -> Transcript {
    let mut out = Transcript::new(b"cuhepy-native-proof-control-v1");
    out.append_message(b"owner-local-original-input-full-wire-statement", &domain(hex));
    out
}

fn decode_proof(bytes: &[u8]) -> Option<SNARK> {
    // Explicit bounded, fixed-integer format and canonical whole-packet check.
    if bytes.len() > 1 << 20 { return None; }
    let proof: SNARK = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(1 << 20).reject_trailing_bytes().deserialize(bytes).ok()?;
    if bincode::serialize(&proof).ok()?.as_slice() != bytes { return None; }
    Some(proof)
}

fn verifies(bytes: &[u8], comm: &ComputationCommitment, public: &[[u8; 32]],
            hex: &str, gens: &SNARKGens) -> bool {
    // A panic is rejection in this local diagnostic, not private callback use.
    catch_unwind(AssertUnwindSafe(|| {
        let Some(proof) = decode_proof(bytes) else { return false; };
        let Ok(inputs) = InputsAssignment::new(public) else { return false; };
        proof.verify(comm, &inputs, &mut transcript(hex), gens).is_ok()
    })).unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 8 && args[1] == "verify" {
        // All paths/domain here are supplied by the local owner adapter.
        let gens: SNARKGens = bincode::deserialize(&fs::read(&args[2]).unwrap()).unwrap();
        let comm: ComputationCommitment = bincode::deserialize(&fs::read(&args[3]).unwrap()).unwrap();
        let public = words(&args[4], 256);
        let proof = fs::read(&args[6]).unwrap();
        assert_eq!(args[7], "owner-local-v1");
        println!("{}",json!({"accepted":verifies(&proof,&comm,&public,&args[5],&gens)}));
        return;
    }
    assert_eq!(args.len(), 2, "one trusted owner-local manifest argument");
    let manifest: Manifest = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    assert_eq!((manifest.variables, manifest.constraints, manifest.inputs, manifest.max_nonzeros),
               (28879, 29247, 256, 515086));
    assert_eq!(manifest.statements.len(), 8);
    assert!(!Path::new(&manifest.output_directory).exists());
    fs::create_dir(&manifest.output_directory).unwrap();
    let data = fs::read(&manifest.instance_file).unwrap();
    assert_eq!(data.len() % 41, 0);
    let mut matrices = [Vec::new(), Vec::new(), Vec::new()];
    for entry in data.chunks_exact(41) {
        let matrix = entry[0] as usize;
        assert!(matrix < 3);
        let row = u32::from_le_bytes(entry[1..5].try_into().unwrap()) as usize;
        let column = u32::from_le_bytes(entry[5..9].try_into().unwrap()) as usize;
        matrices[matrix].push((row, column, entry[9..].try_into().unwrap()));
    }
    assert_eq!((matrices[0].len(), matrices[1].len(), matrices[2].len()), (515086, 58126, 0));
    let instance = Instance::new(manifest.constraints, manifest.variables, manifest.inputs,
                                 &matrices[0], &matrices[1], &matrices[2]).unwrap();
    let gens = SNARKGens::new(manifest.constraints, manifest.variables,
                             manifest.inputs, manifest.max_nonzeros);
    let (comm, decomm) = SNARK::encode(&instance, &gens);
    let out = Path::new(&manifest.output_directory);
    let generator_bytes = bincode::serialize(&gens).unwrap();
    let commitment_bytes = bincode::serialize(&comm).unwrap();
    let decommitment_bytes = bincode::serialize(&decomm).unwrap();
    fs::write(out.join("public-generators.bin"), &generator_bytes).unwrap();
    fs::write(out.join("owner-instance-commitment.bin"), &commitment_bytes).unwrap();
    fs::write(out.join("prover-instance-decommitment.bin"), &decommitment_bytes).unwrap();

    let mut proofs = Vec::new();
    let mut cards = Vec::new();
    for statement in &manifest.statements {
        assert_eq!(statement.id, proofs.len());
        let public = words(&statement.public_file, manifest.inputs);
        let witness = words(&statement.witness_file, manifest.variables);
        let vars = VarsAssignment::new(&witness).unwrap();
        let inputs = InputsAssignment::new(&public).unwrap();
        assert!(instance.is_sat(&vars, &inputs).unwrap());
        let proof = SNARK::prove(&instance, &comm, &decomm, vars, &inputs, &gens,
                                 &mut transcript(&statement.domain_hex));
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(verifies(&bytes, &comm, &public, &statement.domain_hex, &gens));
        fs::write(out.join(format!("proof-{}.bin", statement.id)), &bytes).unwrap();
        cards.push(json!({"id":statement.id,"proof_bytes":bytes.len(),
                          "backend_satisfaction":true,"serialized_proof_verified":true}));
        proofs.push(bytes);
        eprintln!("completed honest proof {}", statement.id);
    }

    let mut negatives = Vec::new();
    for negative in &manifest.negatives {
        let public = words(&negative.public_file, manifest.inputs);
        let accepted = verifies(&proofs[negative.proof_id], &comm, &public,
                                 &negative.domain_hex, &gens);
        assert!(!accepted, "negative accepted: {}", negative.label);
        negatives.push(json!({"label":negative.label,"accepted":false}));
    }
    let first = &manifest.statements[0];
    let public = words(&first.public_file, manifest.inputs);
    for (label, bytes) in [
        ("truncated_proof", proofs[0][..proofs[0].len()-1].to_vec()),
        ("trailing_byte", [proofs[0].as_slice(), &[0]].concat()),
        ("changed_proof_byte", { let mut b=proofs[0].clone(); b[32]^=1; b }),
        ("oversize_proof", vec![0; (1 << 20)+1])
    ] {
        assert!(!verifies(&bytes, &comm, &public, &first.domain_hex, &gens));
        negatives.push(json!({"label":label,"accepted":false}));
    }
    let mut changed_comm=commitment_bytes.clone();
    let at=changed_comm.len()/2;
    changed_comm[at]^=1;
    let rejected_commitment=catch_unwind(AssertUnwindSafe(|| {
        let Ok(changed): Result<ComputationCommitment,_>=bincode::deserialize(&changed_comm) else { return true; };
        !verifies(&proofs[0], &changed, &public, &first.domain_hex, &gens)
    })).unwrap_or(true);
    assert!(rejected_commitment);
    negatives.push(json!({"label":"changed_instance_commitment","accepted":false}));

    let mut bad_witness=words(&first.witness_file, manifest.variables);
    bad_witness[0][0]^=1;
    let bad_vars=VarsAssignment::new(&bad_witness).unwrap();
    let inputs=InputsAssignment::new(&public).unwrap();
    assert!(!instance.is_sat(&bad_vars, &inputs).unwrap());
    let attempt=catch_unwind(AssertUnwindSafe(|| {
        let proof=SNARK::prove(&instance,&comm,&decomm,bad_vars,&inputs,&gens,
                              &mut transcript(&first.domain_hex));
        let bytes=bincode::serialize(&proof).unwrap();
        fs::write(out.join("unsatisfied-attempt.bin"),&bytes).unwrap();
        verifies(&bytes,&comm,&public,&first.domain_hex,&gens)
    }));
    let unsat_status=match attempt {
        Ok(false)=>"proof_produced_and_rejected",
        Err(_)=>"prover_panicked_no_accepted_proof",
        Ok(true)=>panic!("unsatisfied witness produced accepted proof"),
    };
    let result=json!({"proof_backend":"pinned_Spartan_SNARK_known_control", "cards":cards,
        "negatives":negatives,"unsatisfied_attempt":unsat_status,
        "generator_bytes":generator_bytes.len(),"instance_commitment_bytes":commitment_bytes.len(),
        "instance_decommitment_bytes":decommitment_bytes.len(),
        "padded_variables":32768,"padded_constraints":32768,
        "same_process_setup_prove_verify_not_deployed_service":true,
        "timing_benchmark":false,"private_callback_available_in_Rust":false});
    fs::write(out.join("backend-result.json"), serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    println!("{}",result);
}
