use std::ops::{BitOr, Deref, BitAnd};

struct Apply<T>(T);

impl<T> Apply<T> {
    fn unwrap(t: T) -> T {
        t
    }
}
impl<T, F, U> BitAnd<F> for Apply<T>
    where F: FnOnce(T) -> U {
    type Output = Apply<U>;

    // rhs is the "right-hand side" of the expression `a | b`
    fn bitand(self, rhs: F) -> Apply<U> {
        Apply(rhs(self.0))
    }
}
impl<T, F, U> BitOr<F> for Apply<T>
    where F: FnOnce(T) -> U {
    type Output = U;

    // rhs is the "right-hand side" of the expression `a | b`
    fn bitor(self, rhs: F) -> U {
        rhs(self.0)
    }
}

impl<T> Deref for Apply<T> {
    type Target = T;
    fn deref(&self) -> &<Self as std::ops::Deref>::Target {
        &self.0
    }
}

#[no_mangle]
fn main() -> u16 {
    Apply([2, 2]) 
        & u16::from_be_bytes
        & (|x| x+1)
        & (|x| x+1)
        | Apply::unwrap
}