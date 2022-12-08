from packed_sha2_512 import BLOCK_SIZE, compute_message_schedule, sha2_compress, get_round_constants
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow

const SHA512_INPUT_CHUNK_SIZE_FELTS = 16
const SHA512_STATE_SIZE_FELTS = 16
# Each instance consists of 16 words of message, 8 words for the input state and 8 words
# for the output state.
const SHA512_INSTANCE_SIZE = SHA512_INPUT_CHUNK_SIZE_FELTS + 2 * SHA512_STATE_SIZE_FELTS

# Computes SHA512 of 'input'. Inputs of up to 55 bytes are supported.
# To use this function, split the input into (up to) 14 words of 32 bits (big endian).
# For example, to compute sha256('Hello world'), use:
#   input = [1214606444, 1864398703, 1919706112]
# where:
#   1214606444 == int.from_bytes(b'Hell', 'big')
#   1864398703 == int.from_bytes(b'o wo', 'big')
#   1919706112 == int.from_bytes(b'rld\x00', 'big')  # Note the '\x00' padding.
#
# output is an array of 8 32-bit words (big endian).
#
# Assumption: n_bytes <= 55.
#
# Note: You must call finalize_sha2() at the end of the program. Otherwise, this function
# is not sound and a malicious prover may return a wrong result.
# Note: the interface of this function may change in the future.
func sha2_512{range_check_ptr, sha512_ptr : felt*}(input : felt*, n_bytes : felt) -> (output : felt*):
    assert_nn_le(n_bytes, 55)
    let sha512_start = sha512_ptr
    _sha512_input(input=input, n_bytes=n_bytes, n_words=SHA512_INPUT_CHUNK_SIZE_FELTS - 2)
    assert sha512_ptr[0] = 0
    assert sha512_ptr[1] = n_bytes * 8
    let sha512_ptr = sha512_ptr + 2

    # Set the initial state to IV.
    assert sha512_ptr[0] = 0x6a09e667
    assert sha512_ptr[1] = 0xf3bcc908
    assert sha512_ptr[2] = 0xbb67ae85
    assert sha512_ptr[3] = 0x84caa73b
    assert sha512_ptr[4] = 0x3c6ef372
    assert sha512_ptr[5] = 0xfe94f82b
    assert sha512_ptr[6] = 0xa54ff53a
    assert sha512_ptr[7] = 0x5f1d36f1
    assert sha512_ptr[8] = 0x510e527f
    assert sha512_ptr[9] = 0xade682d1
    assert sha512_ptr[10] = 0x9b05688c
    assert sha512_ptr[11] = 0x2b3e6c1f
    assert sha512_ptr[12] = 0x1f83d9ab
    assert sha512_ptr[13] = 0xfb41bd6b
    assert sha512_ptr[14] = 0x5be0cd1
    assert sha512_ptr[15] = 0x9137e2179
    let sha512_ptr = sha512_ptr + SHA512_STATE_SIZE_FELTS

    let output = sha512_ptr
    %{
        from starkware.cairo.common.cairo_sha512.sha512_utils import (
            IV, compute_message_schedule, sha2_compress_function)

        _sha512_input_chunk_size_felts = int(ids.SHA512_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _sha512_input_chunk_size_felts < 100

        w = compute_message_schedule(memory.get_range(
            ids.sha512_start, _sha512_input_chunk_size_felts))
        new_state = sha2_compress_function(IV, w)
        segments.write_arg(ids.output, new_state)
    %}
    let sha512_ptr = sha512_ptr + SHA512_STATE_SIZE_FELTS
    return (output)
end

func _sha512_input{range_check_ptr, sha512_ptr : felt*}(
        input : felt*, n_bytes : felt, n_words : felt):
    alloc_locals

    local full_word
    %{ ids.full_word = int(ids.n_bytes >= 4) %}

    if full_word != 0:
        assert sha512_ptr[0] = input[0]
        let sha512_ptr = sha512_ptr + 1
        return _sha512_input(input=input + 1, n_bytes=n_bytes - 4, n_words=n_words - 1)
    end

    # This is the last input word, so we should add a byte '0x80' at the end and fill the rest with
    # zeros.

    if n_bytes == 0:
        assert sha512_ptr[0] = 0x80000000
        memset(dst=sha512_ptr + 1, value=0, n=n_words - 1)
        let sha512_ptr = sha512_ptr + n_words
        return ()
    end

    assert_nn_le(n_bytes, 3)
    let (padding) = pow(512, 3 - n_bytes)
    local range_check_ptr = range_check_ptr

    assert sha512_ptr[0] = input[0] + padding * 0x80

    memset(dst=sha512_ptr + 1, value=0, n=n_words - 1)
    let sha512_ptr = sha512_ptr + n_words
    return ()
end

# Handles n blocks of BLOCK_SIZE SHA512 instances.
func _finalize_sha512_inner{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        sha512_ptr : felt*, n : felt, round_constants : felt*):
    if n == 0:
        return ()
    end

    alloc_locals

    local MAX_VALUE = 2 ** 32 - 1

    let sha512_start = sha512_ptr

    let (local message_start : felt*) = alloc()
    let (local input_state_start : felt*) = alloc()

    # Handle message.

    tempvar message = message_start
    tempvar sha512_ptr = sha512_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = SHA512_INPUT_CHUNK_SIZE_FELTS

    message_loop:
    tempvar x0 = sha512_ptr[0 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 0] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = sha512_ptr[1 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = sha512_ptr[2 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    tempvar x3 = sha512_ptr[3 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 6] = x3
    assert [range_check_ptr + 7] = MAX_VALUE - x3
    tempvar x4 = sha512_ptr[4 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 8] = x4
    assert [range_check_ptr + 9] = MAX_VALUE - x4
    tempvar x5 = sha512_ptr[5 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 10] = x5
    assert [range_check_ptr + 11] = MAX_VALUE - x5
    tempvar x6 = sha512_ptr[6 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 12] = x6
    assert [range_check_ptr + 13] = MAX_VALUE - x6
    assert message[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6

    tempvar message = message + 1
    tempvar sha512_ptr = sha512_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 14
    tempvar m = m - 1
    jmp message_loop if m != 0

    # Handle input state.

    tempvar input_state = input_state_start
    tempvar sha512_ptr = sha512_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = SHA512_STATE_SIZE_FELTS

    input_state_loop:
    tempvar x0 = sha512_ptr[0 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 0] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = sha512_ptr[1 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = sha512_ptr[2 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    tempvar x3 = sha512_ptr[3 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 6] = x3
    assert [range_check_ptr + 7] = MAX_VALUE - x3
    tempvar x4 = sha512_ptr[4 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 8] = x4
    assert [range_check_ptr + 9] = MAX_VALUE - x4
    tempvar x5 = sha512_ptr[5 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 10] = x5
    assert [range_check_ptr + 11] = MAX_VALUE - x5
    tempvar x6 = sha512_ptr[6 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 12] = x6
    assert [range_check_ptr + 13] = MAX_VALUE - x6
    assert input_state[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6

    tempvar input_state = input_state + 1
    tempvar sha512_ptr = sha512_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 14
    tempvar m = m - 1
    jmp input_state_loop if m != 0

    # Run sha256 on the 7 instances.

    local sha512_ptr : felt* = sha512_ptr
    local range_check_ptr = range_check_ptr
    compute_message_schedule(message_start)
    let (outputs) = sha2_compress(input_state_start, message_start, round_constants)
    local bitwise_ptr : BitwiseBuiltin* = bitwise_ptr

    # Handle outputs.

    tempvar outputs = outputs
    tempvar sha512_ptr = sha512_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = SHA512_STATE_SIZE_FELTS

    output_loop:
    tempvar x0 = sha512_ptr[0 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = sha512_ptr[1 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = sha512_ptr[2 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    tempvar x3 = sha512_ptr[3 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 6] = x3
    assert [range_check_ptr + 7] = MAX_VALUE - x3
    tempvar x4 = sha512_ptr[4 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 8] = x4
    assert [range_check_ptr + 9] = MAX_VALUE - x4
    tempvar x5 = sha512_ptr[5 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 10] = x5
    assert [range_check_ptr + 11] = MAX_VALUE - x5
    tempvar x6 = sha512_ptr[6 * SHA512_INSTANCE_SIZE]
    assert [range_check_ptr + 12] = x6
    assert [range_check_ptr + 13] = MAX_VALUE - x6
    assert outputs[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6

    tempvar outputs = outputs + 1
    tempvar sha512_ptr = sha512_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 14
    tempvar m = m - 1
    jmp output_loop if m != 0

    return _finalize_sha512_inner(
        sha512_ptr=sha512_start + SHA512_INSTANCE_SIZE * BLOCK_SIZE,
        n=n - 1,
        round_constants=round_constants)
end

# Verifies that the results of sha512() are valid.
func finalize_sha512{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        sha512_ptr_start : felt*, sha512_ptr_end : felt*):
    alloc_locals

    let (__fp__, _) = get_fp_and_pc()

    let (round_constants) = get_round_constants()

    tempvar n = (sha512_ptr_end - sha512_ptr_start) / SHA512_INSTANCE_SIZE
    if n == 0:
        return ()
    end

    %{
        # Add dummy pairs of input and output.
        from starkware.cairo.common.cairo_sha512.sha512_utils import (
            IV, compute_message_schedule, sha2_compress_function)

        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _block_size < 20
        _sha512_input_chunk_size_felts = int(ids.SHA512_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _sha512_input_chunk_size_felts < 100

        message = [0] * _sha512_input_chunk_size_felts
        w = compute_message_schedule(message)
        output = sha2_compress_function(IV, w)
        padding = (message + IV + output) * (_block_size - 1)
        segments.write_arg(ids.sha512_ptr_end, padding)
    %}

    # Compute the amount of blocks (rounded up).
    let (local q, r) = unsigned_div_rem(n + BLOCK_SIZE - 1, BLOCK_SIZE)
    _finalize_sha512_inner(sha512_ptr_start, n=q, round_constants=round_constants)
    return ()
end
