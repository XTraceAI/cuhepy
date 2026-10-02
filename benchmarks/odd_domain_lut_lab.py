#!/usr/bin/env python3
"""E89 full odd-domain LUT checks and charged precision/rank cards, no timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import product
import json
from math import gcd
from pathlib import Path
import sys

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import batched_score_bridge as gadget
from experiments.bfv_search_lab import odd_domain_lut as lut


def full_lut_cards():
    cards = []
    for t, degree in ((3,4),(3,16),(5,16),(9,32),(17,64),(193,1024),(257,2048),(1153,4096)):
        permutations = tuple(k for k in range(1,t) if gcd(k,t)==1) if t<=17 else (1,t-1)
        checks, independent = 0, 0
        functions = (tuple(range(t)),tuple((h*h+3)%65537 for h in range(t)),tuple(int(h<=t//3) for h in range(t)))
        for permutation in permutations:
            assert lut.spacing(t,degree,permutation)==degree//t
            for values in functions:
                table = lut.compile_lut(values,degree,permutation=permutation)
                for h,center in enumerate(lut.centers(t,degree,permutation)):
                    for error in range(-table.allowed_integer_error,table.allowed_integer_error+1):
                        rotation = (center+error)%(2*degree)
                        assert lut.evaluate(table,rotation)==values[h]
                        checks+=1
                        if degree<=64:
                            assert lut.roundtrip_reference(table,rotation)==values[h]
                            independent+=1
        cards.append({"t":t,"degree":degree,"coprime_permutations_checked":len(permutations),
                      "minimum_cyclic_folded_center_spacing":degree//t,
                      "allowed_integer_rotation_error":(degree//t-1)//2,
                      "all_message_function_error_cases":checks,
                      "independent_explicit_monomial_rotation_checks":independent})
    all_functions = 0
    for values in product(range(3),repeat=3):
        table=lut.compile_lut(values,16,p=3)
        for h,center in enumerate(lut.centers(3,16)):
            for error in range(-table.allowed_integer_error,table.allowed_integer_error+1):
                assert lut.evaluate(table,(center+error)%32)==values[h]
                all_functions+=1
    return {"cards":cards,"all_3_power_3_arbitrary_output_function_checks":all_functions,
            "general_even_antipodes_rejected":True,
            "valid_Q65537_zero_phase_B8_D4_rounds_to_rotation2":lut.scale_phase((4097,)*4,49149,(1,)*4,65537,8),
            "quarter_torus_ideal_radius_known_control":True}


def precision_card(profile,degree,dimension):
    n,q,t,bound=(profile[k] for k in ("n","modeled_Q","t","phase_bound"))
    levels=gadget.context(q,257)
    key_noise=2*levels*n*128  # both original C1/C2 families; illustrative |key error|1
    distance=degree//t if degree>=t else 0
    allowed=(distance-1)//2 if distance else None
    rounding=Fraction(dimension+2,2)  # component rounding + center quantization
    error=Fraction(2*degree,q)*(Fraction(bound,t)+key_noise)+rounding
    remaining=Fraction(allowed)-rounding if allowed is not None else None
    candidate=None
    if remaining is not None and remaining>0:
        # Solve the NEW-context sufficient inequality including changed gadget levels.
        stride=2*max(n,degree)*t
        current=q
        for _ in range(8):
            new_levels=gadget.context(current,257)
            new_key_noise=2*new_levels*n*128
            minimum=Fraction(2*degree)*(Fraction(bound,t)+new_key_noise)/remaining
            minimum_integer=minimum.numerator//minimum.denominator+1
            prime=((max(minimum_integer,q)-1+stride-1)//stride)*stride+1
            while not is_prime(prime):
                prime+=stride
            if prime>=1<<64:
                break
            valid_error=Fraction(2*degree,prime)*(Fraction(bound,t)+2*gadget.context(prime,257)*n*128)+rounding
            if valid_error<allowed:
                candidate={"Q":prime,"Q_bits":prime.bit_length(),"radix257_levels":gadget.context(prime,257),
                           "conditional_total_integer_center_error_bound":str(valid_error),
                           "identity_unit_permutation_and_NTT_context":True,
                           "new_keys_index_and_auxiliary_key_context_required":True}
                break
            current=prime
    shapes=[]
    for rank in (1,4,8):
        for width in (1,4,8):
            union=min(n,dimension+width-1)
            cm=union*4*(rank+width)**2*degree
            ordinary=dimension*4*(rank+1)**2*degree
            ratio=Fraction(cm,width*ordinary)
            shapes.append({"rank":rank,"width":width,"output_GLWE_secret_coefficients":rank*degree,
                           "canonical_orbit_source_union_dimension":union,
                           "CM_BSK_u64_bytes_per_binary_indicator":cm*8,
                           "shared_ordinary_BSK_u64_bytes_per_binary_indicator":ordinary*8,
                           "CM_vs_shared_key_storage_coefficient_ratio":str(Fraction(cm,ordinary)),
                           "block_amortized_dense_product_ratio_NOT_elapsed":str(ratio),
                           "component_product_target_20percent_only":ratio<=Fraction(4,5),
                           "published_Table7_seeded_CM_body_bytes_not_reproduced":union*4*(rank+width)*degree*8,
                           "literal_seeded_CM_body_bytes":union*4*(rank+width)*width*degree*8,
                           "signed_ternary_and_regeneration_full_proof_costs_still_paid":True,
                           "same_security_level_or_PBS_parameters_approved":False})
    return {"dataset":profile["dataset"],"profile":profile["profile"],"original_N":n,
            "original_Q":q,"t":t,"PBS_degree":degree,"target_ternary_prefix_L1_bound":dimension,
            "exact_folded_grid_supported":degree>=t,"minimum_folded_integer_spacing":distance,
            "allowed_integer_rotation_error":allowed,"component_rounding_and_center_quantization_bound":str(rounding),
            "original_Q_post_unit_KS_and_final_2M_switch_bound":str(error),
            "original_Q_satisfies_sufficient_strict_rotation_bound":allowed is not None and error<allowed,
            "no_larger_Q_can_pass_THIS_worst_case_bound":remaining is None or remaining<=0,
            "optional_self_consistent_new_prime_context":candidate,
            "new_context_assumes_original_phase_bound_stays_valid":True,
            "illustrative_key_noise_bound_1_NOT_secure":key_noise,
            "proof_and_BSK_generation_noise_and_failure_probability_reviewed":False,
            "probabilistic_or_bias_corrected_MS_and_Meta_PBS_are_stronger_controls":True,
            "rank_width_component_shapes":shapes,
            "complete_selection_authentication_ID_coverage_cost":None,
            "scope":"Exact grid and sufficient WORST-CASE bound, conditional new prime/gadget/key counts only; no impossibility for stronger probabilistic/high-precision PBS, matched security, timing or complete protocol."}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out",type=Path,required=True)
    args=parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profile_path=ROOT/'benchmarks/results/publication-encrypted-query-gate-control-20261001.json'
    result=metadata([Path(__file__),ROOT/'benchmarks/dictionary_layout_lab.py',profile_path,
                     ROOT/'experiments/bfv_search_lab/odd_domain_lut.py',ROOT/'experiments/bfv_search_lab/test_odd_domain_lut.py',
                     ROOT/'experiments/bfv_search_lab/batched_score_bridge.py',
                     ROOT/'docs/research/odd-domain-lut-preregistration-20261002.md'])
    profiles=json.loads(profile_path.read_text())['retained_geometry_count_screens']
    result.update(kind='E89_known_full_odd_domain_LUT_and_precision_control',exact=full_lut_cards(),
                  paid_precision_cards=[precision_card(p,degree,dimension) for p in profiles
                                        for degree in (256,512,1024,2048,4096,8192,16384,65536,131072,1048576)
                                        for dimension in (512,1024)],
                  decision='Advance known odd-domain full LUT as strong control; stop unpriced ordinary small-ring precision/MS. Meta-PBS/refined digit decomposition and their complete authenticated input/coverage costs are the next discrimination, not a default giant CM ring or invented new odd-modulus primitive.',
                  scope='Homemade plaintext LUT/monomial and exact conditional precision/rank/key counts only. No encrypted PBS, new timing, approved noise/security, feedback-safe production receiver or original complete protocol.')
    args.json_out.parent.mkdir(parents=True,exist_ok=True)
    args.json_out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(args.json_out),'all_LUT_message_error_checks':sum(c['all_message_function_error_cases'] for c in result['exact']['cards']),
                      'precision_cards':len(result['paid_precision_cards']),
                      'rank_width_shapes':sum(len(c['rank_width_component_shapes']) for c in result['paid_precision_cards']),
                      'no_larger_Q_sufficient_worstcase_cards':sum(c['no_larger_Q_can_pass_THIS_worst_case_bound'] for c in result['paid_precision_cards'])}))


if __name__=='__main__':
    main()
