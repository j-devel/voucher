#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{vec, vec::Vec}};

pub fn foo() {
    let v = vec![0, 1, 2];
    println!("v: {:?}", v);
    assert_eq!(v, Vec::from([0, 1, 2]));
}

#[test]
fn test_foo() {
    foo();
}
