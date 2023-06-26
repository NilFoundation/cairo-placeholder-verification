
//TODO implement
// fn invmod( a: u256, p:u256) -> u256 {
//     0
// }
use debug::PrintTrait;
use integer::{
    BoundedInt, u128_wrapping_sub, u16_sqrt, u32_sqrt, u64_sqrt, u8_sqrt, u512, u256_wide_mul,
    u256_as_non_zero, u512_safe_div_rem_by_u256, u128_as_non_zero
};

fn addmod(a:u256 ,b: u256 , modulus :u256) -> u256{
    0
}

fn fsub(a:u256 ,b: u256 , modulus :u256) -> u256{
    0
}

fn fmul(a:u256 ,b: u256 , modulus :u256) -> u256{
    let non_z_m =  integer::u256_as_non_zero(modulus);
    let mul  = u256_wide_mul(a,b);
    //exp result = 199455130043951077247265858823823987229570523056509026484192158816218200659
    //low=113853868090416934761451734512923595473, high=3386775350622369879150939222746353594
    let (q, r) = u512_safe_div_rem_by_u256(mul,non_z_m);
    r
    //r = 121014868465565852019741182220546947667,586145946522973012039988434362278182
}

fn fdiv(a:u256 ,b: u256 , modulus :u256) -> u256{
    0
}

fn log2(x:u256)-> u256{
    0
}

fn expmod_static(base:u256 ,expoent: u256 , modulus :u256) -> u256{
    0
}

fn inverse_static(val: u256 , modulus :u256) -> u256{
    0
}



