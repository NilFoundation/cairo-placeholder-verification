// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.8.4;

import "../types.sol";
import "../cryptography/transcript.sol";
import "../commitments/lpc_verifier.sol";
import "../commitments/batched_lpc_verifier.sol";
import "./permutation_argument.sol";
import "../components/non_native_field_add_gen.sol";
import "../basic_marshalling.sol";
import "../algebra/field.sol";
import "../logging.sol";

library placeholder_verifier_non_native_field_add_component {
    uint256 constant f_parts = 9;

    uint256 constant OMEGA_OFFSET = 0x20;

    uint256 constant ZERO_INDEX_OFFSET = 0x40;
    uint256 constant E_OFFSET = 0xe0;
    uint256 constant ALPHAS_OFFSET = 0xa0;
    uint256 constant CHALLENGE_OFFSET = 0xc0;
    uint256 constant EVALUATION_POINTS_OFFSET = 0x100;
    uint256 constant F_OFFSET = 0x120;
    uint256 constant F_CONSOLIDATED_OFFSET = 0x140;
    uint256 constant T_CONSOLIDATED_OFFSET = 0x160;
    uint256 constant Z_AT_CHALLENGE_OFFSET = 0x180;
    uint256 constant WITNESS_EVALUATION_POINTS_OFFSET = 0x2e0;

    function verify_proof_be(
        bytes calldata blob,
        types.transcript_data memory tr_state,
        types.placeholder_proof_map memory proof_map,
        types.fri_params_type memory fri_params,
        types.placeholder_common_data memory common_data
    ) internal view returns (bool result) {
        types.placeholder_local_variables memory local_vars;
        // 3. append witness commitments to transcript
        transcript.update_transcript_b32_by_offset_calldata(
            tr_state,
            blob,
            basic_marshalling.skip_length(
                blob,
                proof_map.witness_commitment_offset
            )
        );

        // 4. prepare evaluaitons of the polynomials that are copy-constrained
        // 5. permutation argument
        local_vars.permutation_argument = permutation_argument.verify_eval_be(
            blob,
            tr_state,
            proof_map,
            fri_params,
            common_data,
            local_vars
        );

        // 7. gate argument
        types.gate_argument_local_vars memory gate_params;
        gate_params.modulus = fri_params.modulus;
        gate_params.theta = transcript.get_field_challenge(
            tr_state,
            fri_params.modulus
        );
        gate_params.eval_proof_witness_offset = proof_map
            .eval_proof_witness_offset;
        gate_params.eval_proof_selector_offset = proof_map
            .eval_proof_selector_offset;
        local_vars.gate_argument = non_native_field_add_component_gen
            .evaluate_gates_be(
                blob,
                gate_params,
                common_data.columns_rotations
            );

        // 8. alphas computations
        local_vars.alphas = new uint256[](f_parts);
        transcript.get_field_challenges(
            tr_state,
            local_vars.alphas,
            fri_params.modulus
        );

        // 9. Evaluation proof check
        transcript.update_transcript_b32_by_offset_calldata(
            tr_state,
            blob,
            basic_marshalling.skip_length(blob, proof_map.T_commitments_offset)
        );
        local_vars.challenge = transcript.get_field_challenge(
            tr_state,
            fri_params.modulus
        );
        if (
            local_vars.challenge !=
            basic_marshalling.get_uint256_be(blob, proof_map.eval_proof_offset)
        ) {
            return false;
        }

        // witnesses
        fri_params.leaf_size = batched_lpc_verifier.get_z_n_be(
            blob,
            proof_map.eval_proof_witness_offset
        );
        local_vars.witness_evaluation_points = new uint256[][](
            fri_params.leaf_size
        );
        for (uint256 i = 0; i < fri_params.leaf_size; i++) {
            local_vars.witness_evaluation_points[i] = new uint256[](
                common_data.columns_rotations[i].length
            );
            for (
                uint256 j = 0;
                j < common_data.columns_rotations[i].length;
                j++
            ) {
                local_vars.e =
                    uint256(
                        common_data.columns_rotations[i][j] +
                            int256(fri_params.modulus)
                    ) %
                    fri_params.modulus;
                local_vars.e = field.expmod_static(
                    common_data.omega,
                    local_vars.e,
                    fri_params.modulus
                );
                assembly {
                    mstore(
                        add(local_vars, E_OFFSET),
                        // challenge * omega^rotation_gates[j]
                        mulmod(
                            // challenge
                            mload(add(local_vars, CHALLENGE_OFFSET)),
                            // e = omega^rotation_gates[j]
                            mload(add(local_vars, E_OFFSET)),
                            // modulus
                            mload(fri_params)
                        )
                    )
                }
                local_vars.witness_evaluation_points[i][j] = local_vars.e;
            }
        }
        local_vars.status = batched_lpc_verifier.parse_verify_proof_be(
            blob,
            proof_map.eval_proof_witness_offset,
            local_vars.witness_evaluation_points,
            tr_state,
            fri_params
        );
        if (!local_vars.status) {
            return false;
        }

        // permutation
        local_vars.evaluation_points = new uint256[](2);
        local_vars.evaluation_points[0] = local_vars.challenge;
        // local_vars.evaluation_points_permutation[1] = (local_vars.challenge * common_data.omega) % fri_params.modulus;
        assembly {
            mstore(
                // local_vars.evaluation_points[1]
                add(mload(add(local_vars, EVALUATION_POINTS_OFFSET)), 0x40),
                // (local_vars.challenge * common_data.omega) % fri_params.modulus
                mulmod(
                    // local_vars.challenge
                    mload(add(local_vars, CHALLENGE_OFFSET)),
                    // common_data.omega
                    mload(add(common_data, OMEGA_OFFSET)),
                    // modulus
                    mload(fri_params)
                )
            )
        }
        if (
            !lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_permutation_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // quotient
        local_vars.evaluation_points = new uint256[](1);
        local_vars.evaluation_points[0] = local_vars.challenge;
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_quotient_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // id
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_id_permutation_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // sigma
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_sigma_permutation_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // public_input
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_public_input_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // constant
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_constant_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // selector
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_selector_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // special_selectors
        if (
            !batched_lpc_verifier.parse_verify_proof_be(
                blob,
                proof_map.eval_proof_special_selectors_offset,
                local_vars.evaluation_points,
                tr_state,
                fri_params
            )
        ) {
            return false;
        }

        // 10. final check
        local_vars.F = new uint256[](f_parts);
        local_vars.F[0] = local_vars.permutation_argument[0];
        local_vars.F[1] = local_vars.permutation_argument[1];
        local_vars.F[2] = local_vars.permutation_argument[2];
        // lookup argument is not used in unified addition component
        for (uint256 i = 3; i < 8; i++) {
            local_vars.F[i] = 0;
        }
        local_vars.F[8] = local_vars.gate_argument;

        local_vars.F_consolidated = 0;
        for (uint256 i = 0; i < f_parts; i++) {
            assembly {
                mstore(
                    // local_vars.F_consolidated
                    add(local_vars, F_CONSOLIDATED_OFFSET),
                    addmod(
                        // F_consolidated
                        mload(add(local_vars, F_CONSOLIDATED_OFFSET)),
                        mulmod(
                            // alphas[i]
                            mload(
                                add(
                                    add(
                                        mload(add(local_vars, ALPHAS_OFFSET)),
                                        0x20
                                    ),
                                    mul(0x20, i)
                                )
                            ),
                            // F[i]
                            mload(
                                add(
                                    add(mload(add(local_vars, F_OFFSET)), 0x20),
                                    mul(0x20, i)
                                )
                            ),
                            // modulus
                            mload(fri_params)
                        ),
                        // modulus
                        mload(fri_params)
                    )
                )
            }
        }

        local_vars.T_consolidated = 0;
        local_vars.len = batched_lpc_verifier.get_z_n_be(
            blob,
            proof_map.eval_proof_quotient_offset
        );
        for (uint256 i = 0; i < local_vars.len; i++) {
            local_vars.zero_index = batched_lpc_verifier
                .get_z_i_j_from_proof_be(
                    blob,
                    proof_map.eval_proof_quotient_offset,
                    i,
                    0
                );
            local_vars.e = field.expmod_static(
                local_vars.challenge,
                (fri_params.max_degree + 1) * i,
                fri_params.modulus
            );
            assembly {
                mstore(
                    // local_vars.zero_index
                    add(local_vars, ZERO_INDEX_OFFSET),
                    // local_vars.zero_index * local_vars.e
                    mulmod(
                        // local_vars.zero_index
                        mload(add(local_vars, ZERO_INDEX_OFFSET)),
                        // local_vars.e
                        mload(add(local_vars, E_OFFSET)),
                        // modulus
                        mload(fri_params)
                    )
                )
                mstore(
                    // local_vars.T_consolidated
                    add(local_vars, T_CONSOLIDATED_OFFSET),
                    // local_vars.T_consolidated + local_vars.zero_index
                    addmod(
                        // local_vars.T_consolidated
                        mload(add(local_vars, T_CONSOLIDATED_OFFSET)),
                        // local_vars.zero_index
                        mload(add(local_vars, ZERO_INDEX_OFFSET)),
                        // modulus
                        mload(fri_params)
                    )
                )
            }
        }

        local_vars.Z_at_challenge = field.expmod_static(
            local_vars.challenge,
            common_data.rows_amount,
            fri_params.modulus
        );
        assembly {
            mstore(
                // local_vars.Z_at_challenge
                add(local_vars, Z_AT_CHALLENGE_OFFSET),
                // local_vars.Z_at_challenge - 1
                addmod(
                    // Z_at_challenge
                    mload(add(local_vars, Z_AT_CHALLENGE_OFFSET)),
                    // -1
                    sub(mload(fri_params), 1),
                    // modulus
                    mload(fri_params)
                )
            )
            mstore(
                // local_vars.Z_at_challenge
                add(local_vars, Z_AT_CHALLENGE_OFFSET),
                // Z_at_challenge * T_consolidated
                mulmod(
                    // Z_at_challenge
                    mload(add(local_vars, Z_AT_CHALLENGE_OFFSET)),
                    // T_consolidated
                    mload(add(local_vars, T_CONSOLIDATED_OFFSET)),
                    // modulus
                    mload(fri_params)
                )
            )
        }
        if (local_vars.F_consolidated != local_vars.Z_at_challenge) {
            require(false, "here11");
            return false;
        }

        return true;
    }
}
