from starkware.cairo.common.uint256 import (
    Uint256,
)

from algebra.utils import felt_to_uint256
from algebra.mulmod import math_mulmod
from algebra.addmod import math_addmod

const WITNESSES_N = 11;
const WITNESSES_TOTAL_N = 11;
const GATES_N = 1;

const MODULUS_OFFSET = 0x0;
const THETA_OFFSET = 0x20;
const CONSTRAINT_EVAL_OFFSET = 0x40;
const GATE_EVAL_OFFSET = 0x60;
const WITNESS_EVALUATIONS_OFFSET = 0x80;
const SELECTOR_EVALUATIONS_OFFSET = 0xa0;
const EVAL_PROOF_WITNESS_OFFSET_OFFSET = 0xc0;
const EVAL_PROOF_SELECTOR_OFFSET_OFFSET = 0xe0;
const GATES_EVALUATION_OFFSET = 0x100;
const THETA_ACC_OFFSET = 0x120;
const SELECTOR_EVALUATIONS_OFFSET_OFFSET = 0x140;
const OFFSET_OFFSET = 0x160;

func get_eval_i_by_rotation_idx(idx: Uint256, rot_idx: Uint256, ptr: Uint256*) -> Uint256 {
    return ptr + 0x20 + 0x20 * idx + 0x20 * rot_idx
}

func get_selector_i(idx: Uint256, ptr: Uint256*) -> Uint256 {
    return [ptr + 0x20] + 0x20 * idx
}

// TODO: columns_rotations could be hard-coded
func evaluate_gates_be(
    blog : Uint256*,
    gate_params : Uint256*,
    columns_rotations : Uint256*
) -> (Uint256 gates_evaluation) {
    // TODO: check witnesses number in proof

    gate_params.offset = basic_marshalling.skip_length(
        batched_lpc_verifier.skip_to_z(
            blob,
            gate_params.eval_proof_witness_offset
        )
    );
    gate_params.witness_evaluations_offsets = new uint256[](WITNESSES_N);
    for (uint256 i = 0; i < WITNESSES_N; i++) {
        gate_params.witness_evaluations_offsets[i] = basic_marshalling
            .get_i_uint256_ptr_from_vector(blob, gate_params.offset, 0);
        gate_params.offset = basic_marshalling.skip_vector_of_uint256_be(
            blob,
            gate_params.offset
        );
    }
    gate_params.selector_evaluations = new uint256[](GATES_N);
    for (uint256 i = 0; i < GATES_N; i++) {
        gate_params.selector_evaluations[i] = batched_lpc_verifier
            .get_z_i_j_from_proof_be(
                blob,
                gate_params.eval_proof_selector_offset,
                i,
                0
            );
    }

    uint256 t = 0;
        let modulus = gate_params
        let theta_acc = 1
        [gate_params + GATE_EVAL_OFFSET] = 0


        let x1 := [gate_params + CONSTRAINT_EVAL_OFFSET]
        let x2 := [gate_params + WITNESS_EVALUATIONS_OFFSET]
        let x3 := get_eval_i_by_rotation_idx(0, 0, x2)
        let x4 := get_eval_i_by_rotation_idx(2, 0, x2)

        [gate_params + GATE_EVAL_OFFSET] = 0
        x1 = 0
        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x3,
                    get_eval_i_by_rotation_idx(10, 0, x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        get_eval_i_by_rotation_idx(10, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    get_eval_i_by_rotation_idx(1, 0, x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                get_eval_i_by_rotation_idx(3, 0, x2),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    math_mulmod(x3,
                        get_eval_i_by_rotation_idx(10, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x4,
                math_mulmod(x4,
                    get_eval_i_by_rotation_idx(10, 0, x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x4,
                get_eval_i_by_rotation_idx(1, 0, x2),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    get_eval_i_by_rotation_idx(3, 0, x2),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)

        x1 = 0

        x1 = math_addmod(x1,
            math_mulmod(0x2,
                math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                    get_eval_i_by_rotation_idx(10, 0, x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffffe,
                math_mulmod(x3, x3, modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x2,
                math_mulmod(x3,
                    math_mulmod(get_eval_i_by_rotation_idx(8, 0, x2),
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffffe,
                math_mulmod(x3,
                    math_mulmod(get_eval_i_by_rotation_idx(8, 0, x2),
                        math_mulmod(x3, x3, modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(8, 0, x2),
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x3, 
                math_mulmod(x4, 
                    math_mulmod(get_eval_i_by_rotation_idx(8, 0, x2), 
                        math_mulmod(x3, x3, modulus), 
                    modulus), 
                modulus), 
            modulus), 
        modulus)
        
        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET], 
            math_mulmod(x1, theta_acc, modulus), modulus)
        
        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)

        x1 = 0

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(10, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4, x3, modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4, x4, modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4,
                            get_eval_i_by_rotation_idx(4, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x3,
                            math_mulmod(get_eval_i_by_rotation_idx(10, 0, x2),
                                get_eval_i_by_rotation_idx(10, 0, x2),
                            modulus),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1, 
            math_mulmod(x3, 
                math_mulmod(x4, 
                    math_mulmod(x3, x3, modulus), 
                modulus),
            modulus),
        modulus)
        
        x1 = math_addmod(x1, 
            math_mulmod(x3, 
                math_mulmod(x4,
                    math_mulmod(x3, x4, modulus),
                modulus),
            modulus),
        modulus)
        
        x1 = math_addmod(x1, 
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x3,
                        get_eval_i_by_rotation_idx(4, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)
        
        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET], 
            math_mulmod(x1, theta_acc, modulus), modulus)
            
        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x1 = 0
        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4,
                            math_mulmod(get_eval_i_by_rotation_idx(4, 0, x2),
                                get_eval_i_by_rotation_idx(10, 0, x2),
                            modulus),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x4,
                        math_mulmod(x3,
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4,
                            get_eval_i_by_rotation_idx(1, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x4,
                            get_eval_i_by_rotation_idx(5, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x3,
                        math_mulmod(get_eval_i_by_rotation_idx(4, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(x3,
                            math_mulmod(x3,
                                get_eval_i_by_rotation_idx(10, 0, x2),
                            modulus),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x3,
                        get_eval_i_by_rotation_idx(1, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(x3,
                        get_eval_i_by_rotation_idx(5, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x1 = 0

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                        math_mulmod(get_eval_i_by_rotation_idx(10, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            x3,
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            x4,
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            get_eval_i_by_rotation_idx(4, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                        math_mulmod(get_eval_i_by_rotation_idx(10, 0, x2),
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            x3,
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            x4,
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        // Last working string
        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            get_eval_i_by_rotation_idx(4, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x1 = 0
        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            math_mulmod(get_eval_i_by_rotation_idx(4, 0, x2),
                                get_eval_i_by_rotation_idx(10, 0, x2),
                            modulus),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                        math_mulmod(x3,
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            get_eval_i_by_rotation_idx(1, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(3, 0, x2),
                            get_eval_i_by_rotation_idx(5, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            math_mulmod(get_eval_i_by_rotation_idx(4, 0, x2),
                                get_eval_i_by_rotation_idx(10, 0, x2),
                            modulus),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                        math_mulmod(x3,
                            get_eval_i_by_rotation_idx(10, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            get_eval_i_by_rotation_idx(1, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(x4,
                        math_mulmod(get_eval_i_by_rotation_idx(1, 0, x2),
                            get_eval_i_by_rotation_idx(5, 0, x2),
                        modulus),
                    modulus),
                modulus),
            modulus),
        modulus)
        
        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)
        
        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x1 = 0
        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                x4,
            modulus),
        modulus)

        x1 = math_addmod(x1, get_eval_i_by_rotation_idx(4, 0, x2), modulus)
        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(get_eval_i_by_rotation_idx(6, 0, x2),
                    x4,
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(get_eval_i_by_rotation_idx(6, 0, x2),
                        get_eval_i_by_rotation_idx(4, 0, x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x = 0

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                get_eval_i_by_rotation_idx(3, 0, x2),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            get_eval_i_by_rotation_idx(5, 0, x2),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(get_eval_i_by_rotation_idx(6, 0, x2),
                    get_eval_i_by_rotation_idx(3, 0, x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x3,
                    math_mulmod(get_eval_i_by_rotation_idx(6,0,x2),
                        get_eval_i_by_rotation_idx(5,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x = 0

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                x3,
            modulus),
        modulus)

        x1 = math_addmod(x1, get_eval_i_by_rotation_idx(4,0,x2), modulus)
        x1 = math_addmod(x1,
            math_mulmod(x4,
                math_mulmod(get_eval_i_by_rotation_idx(7,0,x2),
                    x3,
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(7,0,x2),
                        get_eval_i_by_rotation_idx(4,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)
        x = 0
        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                get_eval_i_by_rotation_idx(1, 0, x2),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            get_eval_i_by_rotation_idx(5,0,x2),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(x4,
                math_mulmod(get_eval_i_by_rotation_idx(7,0,x2),
                    get_eval_i_by_rotation_idx(1,0,x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(7, 0, x2),
                        get_eval_i_by_rotation_idx(5,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc,modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc,[gate_params + THETA_OFFSET], modulus)
        x = 0

        x1 = math_addmod(x1, get_eval_i_by_rotation_idx(4, 0, x2), modulus)
        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(get_eval_i_by_rotation_idx(8, 0, x2),
                    get_eval_i_by_rotation_idx(4,0,x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(8,0,x2),
                        get_eval_i_by_rotation_idx(4,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(get_eval_i_by_rotation_idx(1,0,x2),
                    math_mulmod(get_eval_i_by_rotation_idx(9,0,x2),
                        get_eval_i_by_rotation_idx(4,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(get_eval_i_by_rotation_idx(3,0,x2),
                    math_mulmod(get_eval_i_by_rotation_idx(9,0,x2),
                        get_eval_i_by_rotation_idx(4,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)
        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1, theta_acc, modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc,[gate_params + THETA_OFFSET],modulus)
        x = 0
    //1st
        x1 = math_addmod(x1,get_eval_i_by_rotation_idx(5,0,x2), modulus)
        x1 = math_addmod(x1,
            math_mulmod(x3,
                math_mulmod(get_eval_i_by_rotation_idx(8,0,x2),
                    get_eval_i_by_rotation_idx(5,0,x2),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(x4,
                    math_mulmod(get_eval_i_by_rotation_idx(8,0,x2),
                        get_eval_i_by_rotation_idx(5,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(get_eval_i_by_rotation_idx(1,0,x2),
                    math_mulmod(get_eval_i_by_rotation_idx(9,0,x2),
                        get_eval_i_by_rotation_idx(5,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        x1 = math_addmod(x1,
            math_mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,
                math_mulmod(get_eval_i_by_rotation_idx(3,0,x2),
                    math_mulmod(get_eval_i_by_rotation_idx(9,0,x2),
                        get_eval_i_by_rotation_idx(5,0,x2),
                    modulus),
                modulus),
            modulus),
        modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_addmod([gate_params + GATE_EVAL_OFFSET],
            math_mulmod(x1,theta_acc,modulus),
        modulus)

        theta_acc = math_mulmod(theta_acc, [gate_params + THETA_OFFSET], modulus)

        [gate_params + GATE_EVAL_OFFSET] = math_mulmod([gate_params + GATE_EVAL_OFFSET],
            get_selector_i(0,[gate_params + SELECTOR_EVALUATIONS_OFFSET]),modulus))

        gates_evaluation = [gate_params + GATE_EVAL_OFFSET]
    }
}
