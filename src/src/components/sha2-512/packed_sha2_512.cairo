from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.registers import get_fp_and_pc

const BLOCK_SIZE = 7
const ALL_ONES = 2 ** 251 - 1
# Pack the different instances with offsets of 35 bits. This is the maximal possible offset for
# 7 32-bit words and it allows space for carry bits in integer addition operations (up to
# 8 summands).
const SHIFTS = 1 + 2 ** 35 + 2 ** (35 * 2) + 2 ** (35 * 3) + 2 ** (35 * 4) + 2 ** (35 * 5) +
    2 ** (35 * 6)

# Given an array of size 16, extends it to the message schedule array (of size 64) by writing
# 48 more values.
# Each element represents 7 32-bit words from 7 difference instances, starting at bits
# 0, 35, 35 * 2, ..., 35 * 6.
func compute_message_schedule{bitwise_ptr : BitwiseBuiltin*}(message : felt*):
    alloc_locals

    # Defining the following constants as local variables saves some instructions.
    local shift_mask3 = SHIFTS * (2 ** 32 - 2 ** 3)
    local shift_mask7 = SHIFTS * (2 ** 32 - 2 ** 7)
    local shift_mask10 = SHIFTS * (2 ** 32 - 2 ** 10)
    local shift_mask17 = SHIFTS * (2 ** 32 - 2 ** 17)
    local shift_mask18 = SHIFTS * (2 ** 32 - 2 ** 18)
    local shift_mask19 = SHIFTS * (2 ** 32 - 2 ** 19)
    local mask32ones = SHIFTS * (2 ** 32 - 1)

    # Loop variables.
    tempvar bitwise_ptr = bitwise_ptr
    tempvar message = message + 16
    tempvar n = 64 - 16

    loop:
    # Compute s0 = right_rot(w[i - 15], 7) ^ right_rot(w[i - 15], 18) ^ (w[i - 15] >> 3).
    tempvar w0 = message[-15]
    assert bitwise_ptr[0].x = w0
    assert bitwise_ptr[0].y = shift_mask7
    let w0_rot7 = (2 ** (32 - 7)) * w0 + (1 / 2 ** 7 - 2 ** (32 - 7)) * bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = w0
    assert bitwise_ptr[1].y = shift_mask18
    let w0_rot18 = (2 ** (32 - 18)) * w0 + (1 / 2 ** 18 - 2 ** (32 - 18)) * bitwise_ptr[1].x_and_y
    assert bitwise_ptr[2].x = w0
    assert bitwise_ptr[2].y = shift_mask3
    let w0_shift3 = (1 / 2 ** 3) * bitwise_ptr[2].x_and_y
    assert bitwise_ptr[3].x = w0_rot7
    assert bitwise_ptr[3].y = w0_rot18
    assert bitwise_ptr[4].x = bitwise_ptr[3].x_xor_y
    assert bitwise_ptr[4].y = w0_shift3
    let s0 = bitwise_ptr[4].x_xor_y
    let bitwise_ptr = bitwise_ptr + 5 * BitwiseBuiltin.SIZE

    # Compute s1 = right_rot(w[i - 2], 17) ^ right_rot(w[i - 2], 19) ^ (w[i - 2] >> 10).
    tempvar w1 = message[-2]
    assert bitwise_ptr[0].x = w1
    assert bitwise_ptr[0].y = shift_mask17
    let w1_rot17 = (2 ** (32 - 17)) * w1 + (1 / 2 ** 17 - 2 ** (32 - 17)) * bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = w1
    assert bitwise_ptr[1].y = shift_mask19
    let w1_rot19 = (2 ** (32 - 19)) * w1 + (1 / 2 ** 19 - 2 ** (32 - 19)) * bitwise_ptr[1].x_and_y
    assert bitwise_ptr[2].x = w1
    assert bitwise_ptr[2].y = shift_mask10
    let w1_shift10 = (1 / 2 ** 10) * bitwise_ptr[2].x_and_y
    assert bitwise_ptr[3].x = w1_rot17
    assert bitwise_ptr[3].y = w1_rot19
    assert bitwise_ptr[4].x = bitwise_ptr[3].x_xor_y
    assert bitwise_ptr[4].y = w1_shift10
    let s1 = bitwise_ptr[4].x_xor_y
    let bitwise_ptr = bitwise_ptr + 5 * BitwiseBuiltin.SIZE

    assert bitwise_ptr[0].x = message[-16] + s0 + message[-7] + s1
    assert bitwise_ptr[0].y = mask32ones
    assert message[0] = bitwise_ptr[0].x_and_y
    let bitwise_ptr = bitwise_ptr + BitwiseBuiltin.SIZE

    tempvar bitwise_ptr = bitwise_ptr
    tempvar message = message + 1
    tempvar n = n - 1
    jmp loop if n != 0

    return ()
end

func sha2_compress{bitwise_ptr : BitwiseBuiltin*}(
        state : felt*, message : felt*, round_constants : felt*) -> (new_state : felt*):
    alloc_locals

    # Defining the following constants as local variables saves some instructions.
    local shift_mask2 = SHIFTS * (2 ** 32 - 2 ** 2)
    local shift_mask13 = SHIFTS * (2 ** 32 - 2 ** 13)
    local shift_mask22 = SHIFTS * (2 ** 32 - 2 ** 22)
    local shift_mask6 = SHIFTS * (2 ** 32 - 2 ** 6)
    local shift_mask11 = SHIFTS * (2 ** 32 - 2 ** 11)
    local shift_mask25 = SHIFTS * (2 ** 32 - 2 ** 25)
    local mask32ones = SHIFTS * (2 ** 32 - 1)

    tempvar a = state[0]
    tempvar b = state[1]
    tempvar c = state[2]
    tempvar d = state[3]
    tempvar e = state[4]
    tempvar f = state[5]
    tempvar g = state[6]
    tempvar h = state[7]
    tempvar round_constants = round_constants
    tempvar message = message
    tempvar bitwise_ptr = bitwise_ptr
    tempvar n = 64

    loop:
    # Compute s0 = right_rot(a, 2) ^ right_rot(a, 13) ^ right_rot(a, 22).
    assert bitwise_ptr[0].x = a
    assert bitwise_ptr[0].y = shift_mask2
    let a_rot2 = (2 ** (32 - 2)) * a + (1 / 2 ** 2 - 2 ** (32 - 2)) * bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = a
    assert bitwise_ptr[1].y = shift_mask13
    let a_rot13 = (2 ** (32 - 13)) * a + (1 / 2 ** 13 - 2 ** (32 - 13)) * bitwise_ptr[1].x_and_y
    assert bitwise_ptr[2].x = a
    assert bitwise_ptr[2].y = shift_mask22
    let a_rot22 = (2 ** (32 - 22)) * a + (1 / 2 ** 22 - 2 ** (32 - 22)) * bitwise_ptr[2].x_and_y
    assert bitwise_ptr[3].x = a_rot2
    assert bitwise_ptr[3].y = a_rot13
    assert bitwise_ptr[4].x = bitwise_ptr[3].x_xor_y
    assert bitwise_ptr[4].y = a_rot22
    let s0 = bitwise_ptr[4].x_xor_y
    let bitwise_ptr = bitwise_ptr + 5 * BitwiseBuiltin.SIZE

    # Compute s1 = right_rot(e, 6) ^ right_rot(e, 11) ^ right_rot(e, 25).
    assert bitwise_ptr[0].x = e
    assert bitwise_ptr[0].y = shift_mask6
    let e_rot6 = (2 ** (32 - 6)) * e + (1 / 2 ** 6 - 2 ** (32 - 6)) * bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = e
    assert bitwise_ptr[1].y = shift_mask11
    let e_rot11 = (2 ** (32 - 11)) * e + (1 / 2 ** 11 - 2 ** (32 - 11)) * bitwise_ptr[1].x_and_y
    assert bitwise_ptr[2].x = e
    assert bitwise_ptr[2].y = shift_mask25
    let e_rot25 = (2 ** (32 - 25)) * e + (1 / 2 ** 25 - 2 ** (32 - 25)) * bitwise_ptr[2].x_and_y
    assert bitwise_ptr[3].x = e_rot6
    assert bitwise_ptr[3].y = e_rot11
    assert bitwise_ptr[4].x = bitwise_ptr[3].x_xor_y
    assert bitwise_ptr[4].y = e_rot25
    let s1 = bitwise_ptr[4].x_xor_y
    let bitwise_ptr = bitwise_ptr + 5 * BitwiseBuiltin.SIZE

    # Compute ch = (e & f) ^ ((~e) & g).
    assert bitwise_ptr[0].x = e
    assert bitwise_ptr[0].y = f
    assert bitwise_ptr[1].x = ALL_ONES - e
    assert bitwise_ptr[1].y = g
    let ch = bitwise_ptr[0].x_and_y + bitwise_ptr[1].x_and_y
    let bitwise_ptr = bitwise_ptr + 2 * BitwiseBuiltin.SIZE

    # Compute maj = (a & b) ^ (a & c) ^ (b & c).
    assert bitwise_ptr[0].x = a
    assert bitwise_ptr[0].y = b
    assert bitwise_ptr[1].x = bitwise_ptr[0].x_xor_y
    assert bitwise_ptr[1].y = c
    let maj = (a + b + c - bitwise_ptr[1].x_xor_y) / 2
    let bitwise_ptr = bitwise_ptr + 2 * BitwiseBuiltin.SIZE

    tempvar temp1 = h + s1 + ch + round_constants[0] + message[0]
    tempvar temp2 = s0 + maj

    assert bitwise_ptr[0].x = temp1 + temp2
    assert bitwise_ptr[0].y = mask32ones
    let new_a = bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = d + temp1
    assert bitwise_ptr[1].y = mask32ones
    let new_e = bitwise_ptr[1].x_and_y
    let bitwise_ptr = bitwise_ptr + 2 * BitwiseBuiltin.SIZE

    tempvar new_a = new_a
    tempvar new_b = a
    tempvar new_c = b
    tempvar new_d = c
    tempvar new_e = new_e
    tempvar new_f = e
    tempvar new_g = f
    tempvar new_h = g
    tempvar round_constants = round_constants + 1
    tempvar message = message + 1
    tempvar bitwise_ptr = bitwise_ptr
    tempvar n = n - 1
    jmp loop if n != 0

    # Add the compression result to the original state:
    let (res) = alloc()
    assert bitwise_ptr[0].x = state[0] + new_a
    assert bitwise_ptr[0].y = mask32ones
    assert res[0] = bitwise_ptr[0].x_and_y
    assert bitwise_ptr[1].x = state[1] + new_b
    assert bitwise_ptr[1].y = mask32ones
    assert res[1] = bitwise_ptr[1].x_and_y
    assert bitwise_ptr[2].x = state[2] + new_c
    assert bitwise_ptr[2].y = mask32ones
    assert res[2] = bitwise_ptr[2].x_and_y
    assert bitwise_ptr[3].x = state[3] + new_d
    assert bitwise_ptr[3].y = mask32ones
    assert res[3] = bitwise_ptr[3].x_and_y
    assert bitwise_ptr[4].x = state[4] + new_e
    assert bitwise_ptr[4].y = mask32ones
    assert res[4] = bitwise_ptr[4].x_and_y
    assert bitwise_ptr[5].x = state[5] + new_f
    assert bitwise_ptr[5].y = mask32ones
    assert res[5] = bitwise_ptr[5].x_and_y
    assert bitwise_ptr[6].x = state[6] + new_g
    assert bitwise_ptr[6].y = mask32ones
    assert res[6] = bitwise_ptr[6].x_and_y
    assert bitwise_ptr[7].x = state[7] + new_h
    assert bitwise_ptr[7].y = mask32ones
    assert res[7] = bitwise_ptr[7].x_and_y
    let bitwise_ptr = bitwise_ptr + 8 * BitwiseBuiltin.SIZE

    return (res)
end

# Returns the 64 round constants of SHA512.
func get_round_constants() -> (round_constants : felt*):
    alloc_locals
    let (__fp__, _) = get_fp_and_pc()
    local round_constants = 0x428a2f98d728ae22 * SHIFTS
    local a = 0x7137449123ef65cd * SHIFTS
    local a = 0xb5c0fbcfec4d3b2f * SHIFTS
    local a = 0xe9b5dba58189dbbc * SHIFTS
    local a = 0x3956c25bf348b538 * SHIFTS
    local a = 0x59f111f1b605d019 * SHIFTS
    local a = 0x923f82a4af194f9b * SHIFTS
    local a = 0xab1c5ed5da6d8118 * SHIFTS
    local a = 0xd807aa98a3030242 * SHIFTS
    local a = 0x12835b0145706fbe * SHIFTS
    local a = 0x243185be4ee4b28c * SHIFTS
    local a = 0x550c7dc3d5ffb4e2 * SHIFTS
    local a = 0x72be5d74f27b896f * SHIFTS
    local a = 0x80deb1fe3b1696b1 * SHIFTS
    local a = 0x9bdc06a725c71235 * SHIFTS
    local a = 0xc19bf174cf692694 * SHIFTS
    local a = 0xe49b69c19ef14ad2 * SHIFTS
    local a = 0xefbe4786384f25e3 * SHIFTS
    local a = 0x0fc19dc68b8cd5b5 * SHIFTS
    local a = 0x240ca1cc77ac9c65 * SHIFTS
    local a = 0x2de92c6f592b0275 * SHIFTS
    local a = 0x4a7484aa6ea6e483 * SHIFTS
    local a = 0x5cb0a9dcbd41fbd4 * SHIFTS
    local a = 0x76f988da831153b5 * SHIFTS
    local a = 0x983e5152ee66dfab * SHIFTS
    local a = 0xa831c66d2db43210 * SHIFTS
    local a = 0xb00327c898fb213f * SHIFTS
    local a = 0xbf597fc7beef0ee4 * SHIFTS
    local a = 0xc6e00bf33da88fc2 * SHIFTS
    local a = 0xd5a79147930aa725 * SHIFTS
    local a = 0x06ca6351e003826f * SHIFTS
    local a = 0x142929670a0e6e70 * SHIFTS
    local a = 0x27b70a8546d22ffc * SHIFTS
    local a = 0x2e1b21385c26c926 * SHIFTS
    local a = 0x4d2c6dfc5ac42aed * SHIFTS
    local a = 0x53380d139d95b3df * SHIFTS
    local a = 0x650a73548baf63de * SHIFTS
    local a = 0x766a0abb3c77b2a8 * SHIFTS
    local a = 0x81c2c92e47edaee6 * SHIFTS
    local a = 0x92722c851482353b * SHIFTS
    local a = 0xa2bfe8a14cf10364 * SHIFTS
    local a = 0xa81a664bbc423001 * SHIFTS
    local a = 0xc24b8b70d0f89791 * SHIFTS
    local a = 0xc76c51a30654be30 * SHIFTS
    local a = 0xd192e819d6ef5218 * SHIFTS
    local a = 0xd69906245565a910 * SHIFTS
    local a = 0xf40e35855771202a * SHIFTS
    local a = 0x106aa07032bbd1b8 * SHIFTS
    local a = 0x19a4c116b8d2d0c8 * SHIFTS
    local a = 0x1e376c085141ab53 * SHIFTS
    local a = 0x2748774cdf8eeb99 * SHIFTS
    local a = 0x34b0bcb5e19b48a8 * SHIFTS
    local a = 0x391c0cb3c5c95a63 * SHIFTS
    local a = 0x4ed8aa4ae3418acb * SHIFTS
    local a = 0x5b9cca4f7763e373 * SHIFTS
    local a = 0x682e6ff3d6b2b8a3 * SHIFTS
    local a = 0x748f82ee5defb2fc * SHIFTS
    local a = 0x78a5636f43172f60 * SHIFTS
    local a = 0x84c87814a1f0ab72 * SHIFTS
    local a = 0x8cc702081a6439ec * SHIFTS
    local a = 0x90befffa23631e28 * SHIFTS
    local a = 0xa4506cebde82bde9 * SHIFTS
    local a = 0xbef9a3f7b2c67915 * SHIFTS
    local a = 0xc67178f2e372532b * SHIFTS
    local a = 0xca273eceea26619c * SHIFTS
    local a = 0xd186b8c721c0c207 * SHIFTS
    local a = 0xeada7dd6cde0eb1e * SHIFTS
    local a = 0xf57d4f7fee6ed178 * SHIFTS
    local a = 0x06f067aa72176fba * SHIFTS
    local a = 0x0a637dc5a2c898a6 * SHIFTS
    local a = 0x113f9804bef90dae * SHIFTS
    local a = 0x1b710b35131c471b * SHIFTS
    local a = 0x28db77f523047d84 * SHIFTS
    local a = 0x32caab7b40c72493 * SHIFTS
    local a = 0x3c9ebe0a15c9bebc * SHIFTS
    local a = 0x431d67c49c100d4c * SHIFTS
    local a = 0x4cc5d4becb3e42b6 * SHIFTS
    local a = 0x597f299cfc657e2a * SHIFTS
    local a = 0x5fcb6fab3ad6faec * SHIFTS
    local a = 0x6c44198c4a475817 * SHIFTS
    return (&round_constants)
end
