#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::execute_script_without_stack_limit;
    pub use crate::execute_script;
    pub use crate::run;
    pub use bitcoin_script::{script, Script};
}

use core::fmt;

use bitcoin::{
    hashes::Hash,
    hex::DisplayHex,
    taproot::{LeafVersion, TAPROOT_ANNEX_PREFIX},
    Opcode, Script, ScriptBuf, TapLeafHash, Transaction, TxOut,
};
use bitcoin_scriptexec::{Exec, ExecCtx, ExecError, ExecStats, Options, Stack, TxTemplate};

pub mod bigint;
pub mod bn254;
pub mod chunker;
pub mod chunk;
pub mod groth16;
pub mod hash;
pub mod pseudo;
pub mod signatures;
pub mod u32;
pub mod u4;

/// A wrapper for the stack types to print them better.
pub struct FmtStack(pub Stack);
impl fmt::Display for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter_str().enumerate().peekable();
        write!(f, "\n0:\t\t ")?;
        while let Some((index, mut item)) = iter.next() {
            if item.is_empty() {
                write!(f, "    []    ")?;
            } else {
                item.reverse();
                write!(f, "0x{:8}", item.as_hex())?;
            }
            if iter.peek().is_some() {
                if (index + 1) % f.width().unwrap_or(4) == 0 {
                    write!(f, "\n{}:\t\t", index + 1)?;
                }
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

impl FmtStack {
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    pub fn get(&self, index: usize) -> Vec<u8> { self.0.get(index) }
}

impl fmt::Debug for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ExecuteInfo {
    pub success: bool,
    pub error: Option<ExecError>,
    pub final_stack: FmtStack,
    pub remaining_script: String,
    pub last_opcode: Option<Opcode>,
    pub stats: ExecStats,
}

impl fmt::Display for ExecuteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            writeln!(f, "Script execution successful.")?;
        } else {
            writeln!(f, "Script execution failed!")?;
        }
        if let Some(ref error) = self.error {
            writeln!(f, "Error: {:?}", error)?;
        }
        if !self.remaining_script.is_empty() {
            if self.remaining_script.len() < 500 {
                writeln!(f, "Remaining Script: {}", self.remaining_script)?;
            } else {
                let mut string = self.remaining_script.clone();
                string.truncate(500);
                writeln!(f, "Remaining Script: {}...", string)?;
            }
        }
        if !self.final_stack.is_empty() {
            match f.width() {
                None => writeln!(f, "Final Stack: {:4}", self.final_stack)?,
                Some(width) => {
                    writeln!(f, "Final Stack: {:width$}", self.final_stack, width = width)?
                }
            }
        }
        if let Some(ref opcode) = self.last_opcode {
            writeln!(f, "Last Opcode: {:?}", opcode)?;
        }
        writeln!(f, "Stats: {:?}", self.stats)?;
        Ok(())
    }
}

pub fn execute_script(script: treepp::Script) -> ExecuteInfo {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script.compile(),
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
}

/// Dry-runs a specific taproot input
pub fn dry_run_taproot_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> ExecuteInfo {
    let script = tx.input[input_index].witness.tapscript().unwrap();
    let stack = {
        let witness_items = tx.input[input_index].witness.to_vec();
        let last = witness_items.last().unwrap();

        // From BIP341:
        // If there are at least two witness elements, and the first byte of
        // the last element is 0x50, this last element is called annex a
        // and is removed from the witness stack.
        let script_index =
            if witness_items.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                witness_items.len() - 3
            } else {
                witness_items.len() - 2
            };

        witness_items[0..script_index].to_vec()
    };

    let leaf_hash = TapLeafHash::from_script(
        Script::from_bytes(script.as_bytes()),
        LeafVersion::TapScript,
    );

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.into(),
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf_hash, None)),
        },
        ScriptBuf::from_bytes(script.to_bytes()),
        stack,
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    let info = ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    };

    info
}

/// Dry-runs all taproot input scripts. Return Ok(()) if all scripts execute successfully,
/// or Err((input_index, ExecuteInfo)) otherwise
pub fn dry_run_taproots(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), ExecuteInfo> {
    let taproot_indices = prevouts
        .iter()
        .enumerate()
        .filter(|(_, prevout)| prevout.script_pubkey.as_script().is_p2tr()) // only taproots
        .filter(|(idx, _)| tx.input[*idx].witness.tapscript().is_some()) // only script path spends
        .map(|(idx, _)| idx);

    for taproot_index in taproot_indices {
        let result = dry_run_taproot_input(tx, taproot_index, prevouts);
        if !result.success {
            return Err(result);
        }
    }

    Ok(())
}

pub fn run(script: treepp::Script) {
    // let stack = script.clone().analyze_stack();
    // if !stack.is_valid_final_state_without_inputs() {
    //     println!("Stack analysis does not end in valid state: {:?}", stack);
    //     assert!(false);
    // }
    let exec_result = execute_script(script);
    if !exec_result.success {
        println!(
            "ERROR: {:?} <--- \n STACK: {:4} ",
            exec_result.last_opcode, exec_result.final_stack
        );
    }
    //println!("Max_stack_items = {}", exec_result.stats.max_nb_stack_items);
    assert!(exec_result.success);
}

// Execute a script on stack without `MAX_STACK_SIZE` limit.
// This function is only used for script test, not for production.
//
// NOTE: Only for test purposes.
pub fn execute_script_without_stack_limit(script: treepp::Script) -> ExecuteInfo {
    // Get the default options for the script exec.
    // Do not enforce the stack limit.
    let opts = Options { enforce_stack_limit: false, ..Default::default() };

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        opts,
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script.compile(),
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
}

pub fn execute_raw_script_with_inputs(script: Vec<u8>, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    // Get the default options for the script exec.
    // Do not enforce the stack limit.
    let opts = Options { enforce_stack_limit: false, ..Default::default() };

    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        opts,
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        ScriptBuf::from_bytes(script),
        witness,
    )
    .expect("error creating exec");

    loop {
        let temp_res = exec.exec_next();
        match temp_res {
            Ok(()) => (),
            Err(err) => {
                if !err.success {
                    // println!("temp_res: {:?}", temp_res);
                }
                break;
            }
        }
    }

    let res = exec.result().unwrap();
    let execute_info = ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        // alt_stack: FmtStack(exec.altstack().clone()),
        remaining_script: exec.remaining_script().to_owned().to_asm_string(),
        stats: exec.stats().clone(),
    };

    execute_info
}

pub fn execute_script_with_inputs(script: treepp::Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    execute_raw_script_with_inputs(script.compile().to_bytes(), witness)
}

#[cfg(test)]
mod test {
    use crate::bn254;
    use crate::bn254::fp254impl::Fp254Impl;

    use super::execute_script_without_stack_limit;
    use super::treepp::*;

    #[test]
    fn test_script_debug() {
        let script = script! {
            OP_TRUE
            DEBUG
            OP_TRUE
            OP_VERIFY
        };
        let exec_result = execute_script(script);
        assert!(!exec_result.success);
    }

    #[test]
    fn test_script_execute() {
        let script = script! {
            for i in 0..36 {
                { 0x0babe123 + i }
            }
        };
        let exec_result = execute_script(script);
        // The width decides how many stack elements are printed per row
        println!(
            "{:width$}",
            exec_result,
            width = bn254::fq::Fq::N_LIMBS as usize
        );
        println!("{:4}", exec_result);
        println!("{}", exec_result);
        assert!(!exec_result.success);
        assert_eq!(exec_result.error, None);
    }

    #[test]
    fn test_execute_script_without_stack_limit() {
        let script = script! {
            for _ in 0..1001 {
                OP_1
            }
            for _ in 0..1001 {
                OP_DROP
            }
            OP_1
        };
        let exec_result = execute_script_without_stack_limit(script);
        assert!(exec_result.success);
    }
}
