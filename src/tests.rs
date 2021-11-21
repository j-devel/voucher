

//

pub fn misc() {
    #[cfg(feature = "std")]
    use std::{println, vec, vec::Vec};
    #[cfg(not(feature = "std"))]
    use mcu_if::{println, alloc::{vec, vec::Vec}};

    let v = vec![0, 1, 2];
    println!("v: {:?}", v);
    assert_eq!(v, Vec::from([0, 1, 2]));
}

#[test]
fn test_misc() {
    misc();
}
