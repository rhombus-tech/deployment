#[macro_export]
macro_rules! lc {
    ($e:expr) => {
        ark_relations::r1cs::LinearCombination::<_>::zero() + $e
    };
    (($c:expr, $e:expr)) => {
        ark_relations::r1cs::LinearCombination::<_>::zero() + ($c, $e)
    };
}
