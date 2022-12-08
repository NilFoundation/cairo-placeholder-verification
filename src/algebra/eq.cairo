from starkware.cairo.common.uint256 import Uint256, uint256_eq

func math_eq(lhs: felt, rhs: felt) -> (result: felt) {
    if (lhs == rhs) {
        return (1,);
    } else {
        return (0,);
    }
}

func math_eq256{range_check_ptr}(lhs: Uint256, rhs: Uint256) -> (res: felt) {
    let (res) = uint256_eq(lhs, rhs);
    return (res,);
}
