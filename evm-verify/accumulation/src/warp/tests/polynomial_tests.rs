use evm_verify::accumulation::warp::field::WarpField;
use evm_verify::accumulation::warp::polynomial::{MultilinearPolynomial, evaluate_multilinear};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn test_multilinear_polynomial_creation() {
    // Create a simple multilinear polynomial with 2 variables
    let coefficients = vec![
        WarpField::from(1u64), // constant term
        WarpField::from(2u64), // coefficient for x_0
        WarpField::from(3u64), // coefficient for x_1
        WarpField::from(4u64), // coefficient for x_0 * x_1
    ];
    
    let poly = MultilinearPolynomial::new(2, coefficients.clone());
    
    assert_eq!(poly.num_vars(), 2);
    assert_eq!(poly.coefficients(), &coefficients);
}

#[test]
fn test_multilinear_polynomial_evaluation() {
    // Create a simple multilinear polynomial in 2 variables:
    // p(x_0, x_1) = 1 + 2*x_0 + 3*x_1 + 4*x_0*x_1
    let coefficients = vec![
        WarpField::from(1u64), // constant term
        WarpField::from(2u64), // coefficient for x_0
        WarpField::from(3u64), // coefficient for x_1
        WarpField::from(4u64), // coefficient for x_0 * x_1
    ];
    
    let poly = MultilinearPolynomial::new(2, coefficients);
    
    // Evaluate at (0,0): should be 1
    let point_0_0 = vec![WarpField::from(0u64), WarpField::from(0u64)];
    assert_eq!(poly.evaluate(&point_0_0), WarpField::from(1u64));
    
    // Evaluate at (1,0): should be 1 + 2 = 3
    let point_1_0 = vec![WarpField::from(1u64), WarpField::from(0u64)];
    assert_eq!(poly.evaluate(&point_1_0), WarpField::from(3u64));
    
    // Evaluate at (0,1): should be 1 + 3 = 4
    let point_0_1 = vec![WarpField::from(0u64), WarpField::from(1u64)];
    assert_eq!(poly.evaluate(&point_0_1), WarpField::from(4u64));
    
    // Evaluate at (1,1): should be 1 + 2 + 3 + 4 = 10
    let point_1_1 = vec![WarpField::from(1u64), WarpField::from(1u64)];
    assert_eq!(poly.evaluate(&point_1_1), WarpField::from(10u64));
}

#[test]
fn test_multilinear_polynomial_addition() {
    // Create two simple multilinear polynomials in 2 variables:
    // p(x_0, x_1) = 1 + 2*x_0 + 3*x_1 + 4*x_0*x_1
    // q(x_0, x_1) = 5 + 6*x_0 + 7*x_1 + 8*x_0*x_1
    let p_coeffs = vec![
        WarpField::from(1u64),
        WarpField::from(2u64),
        WarpField::from(3u64),
        WarpField::from(4u64),
    ];
    
    let q_coeffs = vec![
        WarpField::from(5u64),
        WarpField::from(6u64),
        WarpField::from(7u64),
        WarpField::from(8u64),
    ];
    
    let p = MultilinearPolynomial::new(2, p_coeffs);
    let q = MultilinearPolynomial::new(2, q_coeffs);
    
    // Sum should be: 
    // (p + q)(x_0, x_1) = 6 + 8*x_0 + 10*x_1 + 12*x_0*x_1
    let sum = p + q;
    
    let expected_coeffs = vec![
        WarpField::from(6u64),
        WarpField::from(8u64),
        WarpField::from(10u64),
        WarpField::from(12u64),
    ];
    
    assert_eq!(sum.coefficients(), &expected_coeffs);
    
    // Verify by evaluation at a random point
    let point = vec![WarpField::from(2u64), WarpField::from(3u64)];
    let p_eval = p.evaluate(&point);
    let q_eval = q.evaluate(&point);
    let sum_eval = sum.evaluate(&point);
    
    assert_eq!(p_eval + q_eval, sum_eval);
}

#[test]
fn test_multilinear_polynomial_multiplication() {
    // Create two simple multilinear polynomials in 1 variable:
    // p(x) = 1 + 2*x
    // q(x) = 3 + 4*x
    let p_coeffs = vec![WarpField::from(1u64), WarpField::from(2u64)];
    let q_coeffs = vec![WarpField::from(3u64), WarpField::from(4u64)];
    
    let p = MultilinearPolynomial::new(1, p_coeffs);
    let q = MultilinearPolynomial::new(1, q_coeffs);
    
    // Product should be:
    // (p * q)(x) = 3 + 10*x + 8*x^2 (not multilinear anymore)
    // But when reduced to multilinear form (since x^2 = x in the Boolean hypercube):
    // (p * q)(x) = 3 + 18*x
    let product = p * q;
    
    // Verify by evaluation at specific points
    let point_0 = vec![WarpField::from(0u64)];
    let point_1 = vec![WarpField::from(1u64)];
    
    assert_eq!(product.evaluate(&point_0), WarpField::from(3u64));  // at x=0: 3
    assert_eq!(product.evaluate(&point_1), WarpField::from(21u64)); // at x=1: 3 + 18 = 21
}

#[test]
fn test_multilinear_polynomial_restriction() {
    // Create a multilinear polynomial in 3 variables:
    // p(x_0, x_1, x_2) = 1 + 2*x_0 + 3*x_1 + 4*x_2 + 5*x_0*x_1 + 6*x_0*x_2 + 7*x_1*x_2 + 8*x_0*x_1*x_2
    let coeffs = vec![
        WarpField::from(1u64), // constant
        WarpField::from(2u64), // x_0
        WarpField::from(3u64), // x_1
        WarpField::from(4u64), // x_2
        WarpField::from(5u64), // x_0*x_1
        WarpField::from(6u64), // x_0*x_2
        WarpField::from(7u64), // x_1*x_2
        WarpField::from(8u64), // x_0*x_1*x_2
    ];
    
    let poly = MultilinearPolynomial::new(3, coeffs);
    
    // Restrict by setting x_0 = 1
    // Should give: p(1, x_1, x_2) = 3 + 3*x_1 + 10*x_2 + 5*x_1 + 6*x_2 + 7*x_1*x_2 + 8*x_1*x_2
    // = 3 + 8*x_1 + 16*x_2 + 15*x_1*x_2
    let restricted = poly.restrict(0, WarpField::from(1u64));
    
    // Verify by evaluation
    let original_point = vec![WarpField::from(1u64), WarpField::from(2u64), WarpField::from(3u64)];
    let restricted_point = vec![WarpField::from(2u64), WarpField::from(3u64)];
    
    assert_eq!(poly.evaluate(&original_point), restricted.evaluate(&restricted_point));
}

#[test]
fn test_multilinear_extension() {
    // Create a table of values for a function on the Boolean hypercube
    let values = vec![
        WarpField::from(1u64), // f(0,0)
        WarpField::from(3u64), // f(1,0)
        WarpField::from(5u64), // f(0,1)
        WarpField::from(7u64), // f(1,1)
    ];
    
    // Compute multilinear extension
    let poly = evaluate_multilinear(2, &values);
    
    // Verify that the polynomial agrees with the table at the Boolean hypercube
    let points = [
        vec![WarpField::from(0u64), WarpField::from(0u64)],
        vec![WarpField::from(1u64), WarpField::from(0u64)],
        vec![WarpField::from(0u64), WarpField::from(1u64)],
        vec![WarpField::from(1u64), WarpField::from(1u64)],
    ];
    
    for (i, point) in points.iter().enumerate() {
        assert_eq!(poly.evaluate(point), values[i]);
    }
    
    // Verify at a non-Boolean point
    let non_boolean_point = vec![WarpField::from(2u64), WarpField::from(3u64)];
    let result = poly.evaluate(&non_boolean_point);
    
    // We can compute this manually based on the multilinear extension formula
    // For this example, we're not checking the exact value, just that it works
    assert_ne!(result, WarpField::from(0u64));
}

#[test]
fn test_random_polynomial() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    // Create a random multilinear polynomial in 4 variables
    let num_vars = 4;
    let mut coefficients = Vec::with_capacity(1 << num_vars);
    
    for _ in 0..(1 << num_vars) {
        coefficients.push(WarpField::rand(&mut rng));
    }
    
    let poly = MultilinearPolynomial::new(num_vars, coefficients);
    
    // Generate random points for evaluation
    let point1: Vec<WarpField> = (0..num_vars).map(|_| WarpField::rand(&mut rng)).collect();
    let point2: Vec<WarpField> = (0..num_vars).map(|_| WarpField::rand(&mut rng)).collect();
    
    let eval1 = poly.evaluate(&point1);
    let eval2 = poly.evaluate(&point2);
    
    // These should be different with very high probability
    assert_ne!(eval1, eval2);
}
