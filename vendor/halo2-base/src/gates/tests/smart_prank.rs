use crate::{
    gates::GateInstructions, halo2_proofs::halo2curves::bn256::Fr, utils::testing::base_test,
};

#[test]
fn smart_prank_select_wrong_value() {
    // Prank the output of select with a wrong value.
    // We add a copy constraint on the output to ensure smart_prank propagates
    // the pranked value. The gate constraint should fail, but the copy constraint
    // between `out` and `out_copy` should hold.
    let a_val = Fr::from(10u64);
    let b_val = Fr::from(20u64);
    let sel_val = Fr::from(1u64); // true
    let prank_value = Fr::from(99u64);

    base_test()
        .k(10u32)
        .expect_satisfied(false)
        .run_gate(|ctx, gate| {
            let a = ctx.load_witness(a_val);
            let b = ctx.load_witness(b_val);
            let sel = ctx.load_witness(sel_val);
            let out = gate.select(ctx, a, b, sel);

            // Create a copy of `out` to test that smart_prank propagates to it
            let out_copy = ctx.load_witness(*out.value());
            ctx.constrain_equal(&out, &out_copy);

            let count = out.debug_smart_prank(ctx, prank_value);
            assert_eq!(count, 2);

            // Check that the copy's value was also pranked
            assert_eq!(
                *ctx.get(out_copy.cell.unwrap().offset as isize).value(),
                prank_value
            );
        });
}

#[test]
fn smart_prank_select_correct_value() {
    // Prank with the correct value, circuit should be satisfied.
    // We add a copy constraint on the output to ensure smart_prank propagates
    // the pranked value.
    let a_val = Fr::from(10u64);
    let b_val = Fr::from(20u64);
    let sel_val = Fr::from(1u64); // true
    let prank_value = Fr::from(10u64);

    base_test()
        .k(10u32)
        .expect_satisfied(true)
        .run_gate(|ctx, gate| {
            let a = ctx.load_witness(a_val);
            let b = ctx.load_witness(b_val);
            let sel = ctx.load_witness(sel_val);
            let out = gate.select(ctx, a, b, sel);

            // Create a copy of `out` to test that smart_prank propagates to it
            let out_copy = ctx.load_witness(*out.value());
            ctx.constrain_equal(&out, &out_copy);

            let count = out.debug_smart_prank(ctx, prank_value);
            assert_eq!(count, 2);

            // Check that the copy's value was also pranked
            assert_eq!(
                *ctx.get(out_copy.cell.unwrap().offset as isize).value(),
                prank_value
            );
        });
}

#[test]
fn smart_prank_with_existing_cell() {
    // The key scenario: a cell is used as Existing (creating a copy constraint),
    // then we prank the original. smart_prank should also update the copy.
    let a_val = Fr::from(42u64);
    let b_val = Fr::from(7u64);

    base_test()
        .k(10u32)
        .expect_satisfied(false)
        .run_gate(|ctx, gate| {
            let a = ctx.load_witness(a_val);
            let b = ctx.load_witness(b_val);

            // a + b using Existing(a), this creates a copy constraint on `a` and `b`
            let _sum = gate.add(ctx, a, b);

            // Now prank `a` with a wrong value. smart_prank should also update
            // the copy of `a` used inside the add gate, so the equality constraint
            // holds but the gate constraint (a + b = sum) fails because sum was
            // computed with the original a = 42, but now we say a = 99
            let prank_value = Fr::from(99u64);
            let num_pranked = a.debug_smart_prank(ctx, prank_value);

            // Should have pranked 2 cells (the original + copy from Existing)
            assert_eq!(num_pranked, 2);
        });
}

#[test]
fn find_equivalent_cells_transitive() {
    // Test that equivalence is transitive: if a==b and b==c, then pranking a
    // should also prank c.
    base_test()
        .k(10u32)
        .expect_satisfied(false)
        .run_gate(|ctx, gate| {
            let val = Fr::from(7u64);
            let prank_val = Fr::from(8u64);
            let a = ctx.load_witness(val);
            let b = ctx.load_witness(val);
            let c = ctx.load_witness(val);
            let _sum = gate.add(ctx, c, c);

            // a == b, b == c (transitive: a == c)
            ctx.constrain_equal(&a, &b);
            ctx.constrain_equal(&b, &c);

            // Prank all with a different value
            let count = a.debug_smart_prank(ctx, prank_val);
            assert_eq!(count, 5);
        });
}

#[test]
fn find_equivalent_cells_cycle() {
    // Test that equivalence finding handles cycles (a=b, b=c, c=d, d=a)
    // and that smart_prank correctly updates all cell values in the cycle,
    // breaking a subsequent gate constraint.
    let initial_val = Fr::from(7u64);
    let prank_val = Fr::from(88u64);
    let other_val = Fr::from(123u64);
    assert_ne!(initial_val, prank_val);

    base_test()
        .k(10u32)
        .expect_satisfied(false)
        .run_gate(|ctx, gate| {
            let a = ctx.load_witness(initial_val);
            let b = ctx.load_witness(initial_val);
            let c = ctx.load_witness(initial_val);
            let d = ctx.load_witness(initial_val);
            let other = ctx.load_witness(other_val);
            let sel_true = ctx.load_constant(Fr::from(1));

            // sel_out is computed based on the *original* value of `d`
            let sel_out = gate.select(ctx, d, other, sel_true);
            assert_eq!(*sel_out.value(), initial_val);

            // a == b, b == c, c == d, d == a (cycle)
            ctx.constrain_equal(&a, &b);
            ctx.constrain_equal(&b, &c);
            ctx.constrain_equal(&c, &d);
            ctx.constrain_equal(&d, &a);

            // Prank all cells in the cycle with a new value.
            let count = a.debug_smart_prank(ctx, prank_val);
            assert_eq!(count, 5);

            // The `select` gate constraint should now fail, because the witness for `d`
            // has changed to `prank_val`, but `sel_out` still holds `initial_val`.
        });
}

#[test]
fn smart_prank_with_constant_constraint_fail() {
    // Test smart_prank with a constant constraint in the equality chain.
    // a=b, b=c, c=const. Pranking `a` with a different value should fail.
    let constant_val = Fr::from(42);
    let prank_val = Fr::from(99);
    assert_ne!(constant_val, prank_val);

    base_test()
        .k(10u32)
        .expect_satisfied(false)
        .run_gate(|ctx, _gate| {
            let a = ctx.load_witness(Fr::from(0u64)); // initial value doesn't matter
            let b = ctx.load_witness(Fr::from(0u64));
            let c = ctx.load_constant(constant_val);
            let d = ctx.load_witness(Fr::from(1u64)); // Unconstrained cell

            // a == b, b == c
            ctx.constrain_equal(&a, &b);
            ctx.constrain_equal(&b, &c);

            // Check is_constant_constrained
            {
                let copy_manager = ctx.copy_manager.lock().unwrap();
                assert_eq!(
                    copy_manager.is_constant_constrained(a.cell.unwrap()),
                    Some(constant_val)
                );
                assert_eq!(
                    copy_manager.is_constant_constrained(b.cell.unwrap()),
                    Some(constant_val)
                );
                assert_eq!(
                    copy_manager.is_constant_constrained(c.cell.unwrap()),
                    Some(constant_val)
                );
                assert_eq!(copy_manager.is_constant_constrained(d.cell.unwrap()), None);
            }

            // Prank `a` with a different value.
            // smart_prank will update a, b, and c's advice cells to `prank_val`.
            // The circuit should fail because the copy constraint between c's cell
            // and the fixed column will be violated.
            let count = a.debug_smart_prank(ctx, prank_val);
            assert_eq!(count, 3);
        });
}
