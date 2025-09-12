use std::net::Ipv4Addr;

use nom::combinator::map;
use nom::number::complete::be_u32;
use nom::{IResult, Parser};

pub fn parse_ipv4_addr(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from).parse(input)
}
