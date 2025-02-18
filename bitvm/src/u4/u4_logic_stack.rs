use crate::treepp::*;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use crate::u4::u4_logic::u4_sort;

use super::{
    u4_logic::{u4_push_half_and_table, u4_push_half_xor_table, u4_push_full_lookup, u4_push_full_xor_table},
    u4_shift_stack::u4_rshift_stack,
};

/// Push half AND table
pub fn u4_push_half_and_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_and_table(), "and_table")
}

/// Push half XOR table
pub fn u4_push_half_xor_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_xor_table(), "xor_half_table")
}

/// Push full XOR table
pub fn u4_push_full_xor_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(256, u4_push_full_xor_table(), "xor_full_table")
}

/// Pushes the table to calculate the order of ordered pairs (a, b) satisfying the conditions a <= b and 0 <= a, b < 15
pub fn u4_push_half_lookup_0_based() -> Script {
    script! {
        120
        119
        117
        114
        110
        105
        99
        92
        84
        75
        65
        54
        42
        29
        15
        0
    }
}

/// Pushes table for the value x * 16 
pub fn u4_push_from_depth_full_lookup(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in (0..16).rev() {
        stack.numberi((i + 1) * -16 + delta);
    }
    let lookup = stack.join_count(&mut stack.get_var_from_stack(15), 15);
    stack.rename(lookup, "lookup");
    lookup
}

/// Pushes the table to calculate the order of ordered pairs (a, b) satisfying the conditions a <= b and 0 <= a, b < 16
pub fn u4_push_from_depth_half_lookup(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in (1..17).rev() {
        let diff = ((16 - i) * (16 - i + 1)) / 2;
        let value = -diff + delta;
        stack.numberi(value);
    }
    let lookup = stack.join_count(&mut stack.get_var_from_stack(15), 15);
    stack.rename(lookup, "lookup");
    lookup
}

/// Pushes the table to calculate the order of ordered pairs (a, b) satisfying the conditions a <= b and 0 <= a, b < 15
pub fn u4_push_half_lookup_table_0_based_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(16, u4_push_half_lookup_0_based(), "lookup_table")
}

/// Pushes table for the value x * 16 
pub fn u4_push_full_lookup_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(17, u4_push_full_lookup(), "full_lookup_table")
}

/// Does the given logical operation with parameters
pub fn u4_logic_with_table_stack(stack: &mut StackTracker, lookup_table: StackVariable, logic_table: StackVariable) -> StackVariable {
    let use_full_table = logic_table.size() > 136;
    if !use_full_table {
        stack.custom(u4_sort(), 0, false, 0, "sort");
    }
    stack.get_value_from_table(lookup_table, None);
    stack.op_add();
    stack.get_value_from_table(logic_table, None)
}

/// Calculates the bitwise AND of top 2 u4 values using XOR tables
/// Uses the formula (a and b) = ((a + b) - a XOR b) >> 1
pub fn u4_and_with_xor_stack(stack: &mut StackTracker, lookup_table: StackVariable, logic_table: StackVariable, shift_table: StackVariable) -> StackVariable {
    stack.op_2dup();
    u4_logic_with_table_stack(stack, lookup_table, logic_table);
    stack.op_sub();
    stack.op_add();
    u4_rshift_stack(stack, shift_table, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::u4::u4_shift_stack::u4_push_shift_tables_stack;
    use bitcoin_script_stack::stack::StackTracker;

    #[test]
    fn test_and_with_xor_full_table() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_full_xor_table_stack(&mut stack);
                let lookup = u4_push_full_lookup_table_stack(&mut stack);
                let shift = u4_push_shift_tables_stack(&mut stack);
                stack.number(x);
                stack.number(y);
                u4_and_with_xor_stack(&mut stack, lookup, xor, shift);
                stack.number(x & y);
                stack.op_equalverify();
                stack.drop(shift);
                stack.drop(lookup);
                stack.drop(xor);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_and_with_xor_half_table() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_half_xor_table_stack(&mut stack);
                let lookup = u4_push_half_lookup_table_0_based_stack(&mut stack);
                let shift = u4_push_shift_tables_stack(&mut stack);
                stack.number(x);
                stack.number(y);
                u4_and_with_xor_stack(&mut stack, lookup, xor, shift);
                stack.number(x & y);
                stack.op_equalverify();
                stack.drop(shift);
                stack.drop(lookup);
                stack.drop(xor);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_xor() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_full_xor_table_stack(&mut stack);
                let lookup = u4_push_full_lookup_table_stack(&mut stack);
                stack.number(x);
                stack.number(y);
                u4_logic_with_table_stack(&mut stack, lookup, xor);
                stack.number(x ^ y);
                stack.op_equalverify();
                stack.drop(lookup);
                stack.drop(xor);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_xor_half() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let xor = u4_push_half_xor_table_stack(&mut stack);
                let lookup = u4_push_half_lookup_table_0_based_stack(&mut stack);
                stack.number(x);
                stack.number(y);
                u4_logic_with_table_stack(&mut stack, lookup, xor);
                stack.number(x ^ y);
                stack.op_equalverify();
                stack.drop(lookup);
                stack.drop(xor);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }

    #[test]
    fn test_and_half() {
        for x in 0..16 {
            for y in 0..16 {
                let mut stack = StackTracker::new();
                let and = u4_push_half_and_table_stack(&mut stack);
                let lookup = u4_push_half_lookup_table_0_based_stack(&mut stack);
                stack.number(x);
                stack.number(y);
                u4_logic_with_table_stack(&mut stack, lookup, and);
                stack.number(x & y);
                stack.op_equalverify();
                stack.drop(lookup);
                stack.drop(and);
                stack.op_true();
                assert!(stack.run().success);
            }
        }
    }
}
