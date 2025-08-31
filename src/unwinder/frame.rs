use gimli::{
    BaseAddresses, CfaRule, Register, RegisterRule, UnwindContext, UnwindExpression, UnwindTableRow,
};
#[cfg(feature = "dwarf-expr")]
use gimli::{Evaluation, EvaluationResult, Location, Value};

use super::arch::*;
use super::find_fde::{self, FDEFinder, FDESearchResult};
use crate::abi::PersonalityRoutine;
use crate::arch::*;
use crate::util::*;
use crate::baremetal_debug::unwinding_debugln;

struct StoreOnStack;

// gimli's MSRV doesn't allow const generics, so we need to pick a supported array size.
const fn next_value(x: usize) -> usize {
    let supported = [0, 1, 2, 3, 4, 8, 16, 32, 64, 128];
    let mut i = 0;
    while i < supported.len() {
        if supported[i] >= x {
            return supported[i];
        }
        i += 1;
    }
    192
}

impl<O: gimli::ReaderOffset> gimli::UnwindContextStorage<O> for StoreOnStack {
    type Rules = [(Register, RegisterRule<O>); next_value(MAX_REG_RULES)];
    type Stack = [UnwindTableRow<O, Self>; 2];
}

#[cfg(feature = "dwarf-expr")]
impl<R: gimli::Reader> gimli::EvaluationStorage<R> for StoreOnStack {
    type Stack = [Value; 64];
    type ExpressionStack = [(R, R); 0];
    type Result = [gimli::Piece<R>; 1];
}

#[derive(Debug)]
pub struct Frame {
    fde_result: FDESearchResult,
    row: UnwindTableRow<usize, StoreOnStack>,
}

impl Frame {
    pub fn from_context(ctx: &Context, signal: bool) -> Result<Option<Self>, gimli::Error> {
        let mut ra = ctx[Arch::RA];
        unwinding_debugln!("Frame::from_context: RA = 0x{:x}, signal = {}", ra, signal);

        // Reached end of stack
        if ra == 0 {
            unwinding_debugln!("Frame::from_context: RA is 0, end of stack");
            return Ok(None);
        }

        // RA points to the *next* instruction, so move it back 1 byte for the call instruction.
        if !signal {
            ra -= 1;
            unwinding_debugln!("Frame::from_context: adjusted RA to 0x{:x} for non-signal frame", ra);
        }

        unwinding_debugln!("Frame::from_context: searching for FDE at RA 0x{:x}", ra);
        let fde_result = match find_fde::get_finder().find_fde(ra as _) {
            Some(v) => {
                        unwinding_debugln!("Frame::from_context: found FDE");
        unwinding_debugln!("Frame::from_context: FDE initial address: 0x{:x}", v.fde.initial_address());
        unwinding_debugln!("Frame::from_context: FDE end address: 0x{:x}", v.fde.end_address());
        unwinding_debugln!("Frame::from_context: eh_frame base: 0x{:x}", v.bases.eh_frame.data.unwrap_or(0));
        unwinding_debugln!("Frame::from_context: text base: 0x{:x}", v.bases.eh_frame.text.unwrap_or(0));
        unwinding_debugln!("Frame::from_context: section base: 0x{:x}", v.bases.eh_frame.section.unwrap_or(0));
        unwinding_debugln!("Frame::from_context: eh_frame_hdr base: 0x{:x}", v.bases.eh_frame_hdr.data.unwrap_or(0));
        v
    },
            None => {
                unwinding_debugln!("Frame::from_context: no FDE found");
                return Ok(None);
            }
        };
        
        unwinding_debugln!("Frame::from_context: creating unwind context");
        let mut unwinder = UnwindContext::<_, StoreOnStack>::new_in();
        unwinding_debugln!("Frame::from_context: calling unwind_info_for_address with RA 0x{:x}", ra);
        unwinding_debugln!("Frame::from_context: bases before call: text={:?}, section={:?}, eh_frame={:?}, eh_frame_hdr={:?}", 
            fde_result.bases.eh_frame.text, fde_result.bases.eh_frame.section, fde_result.bases.eh_frame.data, fde_result.bases.eh_frame_hdr);
        let row = fde_result
            .fde
            .unwind_info_for_address(
                &fde_result.eh_frame,
                &fde_result.bases,
                &mut unwinder,
                ra as _,
            )?;
        unwinding_debugln!("Frame::from_context: unwind_info_for_address returned successfully");
        let row = row.clone();
        unwinding_debugln!("Frame::from_context: row cloned successfully");

        unwinding_debugln!("Frame::from_context: frame created successfully");
        Ok(Some(Self { fde_result, row }))
    }

    #[cfg(feature = "dwarf-expr")]
    fn evaluate_expression(
        &self,
        ctx: &Context,
        expr: UnwindExpression<usize>,
    ) -> Result<usize, gimli::Error> {
        let expr = expr.get(&self.fde_result.eh_frame).unwrap();
        let mut eval =
            Evaluation::<_, StoreOnStack>::new_in(expr.0, self.fde_result.fde.cie().encoding());
        let mut result = eval.evaluate()?;
        loop {
            match result {
                EvaluationResult::Complete => break,
                EvaluationResult::RequiresMemory { address, .. } => {
                    let value = unsafe { (address as usize as *const usize).read_unaligned() };
                    result = eval.resume_with_memory(Value::Generic(value as _))?;
                }
                EvaluationResult::RequiresRegister { register, .. } => {
                    let value = ctx[register];
                    result = eval.resume_with_register(Value::Generic(value as _))?;
                }
                EvaluationResult::RequiresRelocatedAddress(address) => {
                    let value = unsafe { (address as usize as *const usize).read_unaligned() };
                    result = eval.resume_with_memory(Value::Generic(value as _))?;
                }
                _ => unreachable!(),
            }
        }

        Ok(
            match eval
                .as_result()
                .last()
                .ok_or(gimli::Error::PopWithEmptyStack)?
                .location
            {
                Location::Address { address } => address as usize,
                _ => unreachable!(),
            },
        )
    }

    #[cfg(not(feature = "dwarf-expr"))]
    fn evaluate_expression(
        &self,
        _ctx: &Context,
        _expr: UnwindExpression<usize>,
    ) -> Result<usize, gimli::Error> {
        Err(gimli::Error::UnsupportedEvaluation)
    }

    pub fn adjust_stack_for_args(&self, ctx: &mut Context) {
        let size = self.row.saved_args_size();
        ctx[Arch::SP] = ctx[Arch::SP].wrapping_add(size as usize);
    }

    pub fn unwind(&self, ctx: &Context) -> Result<Context, gimli::Error> {
        unwinding_debugln!("Frame::unwind: starting frame unwind");
        let row = &self.row;
        let mut new_ctx = ctx.clone();

        let cfa = match *row.cfa() {
                            CfaRule::RegisterAndOffset { register, offset } => {
                    let cfa = ctx[register].wrapping_add(offset as usize);
                    unwinding_debugln!("Frame::unwind: CFA = register {:?} + offset {} = 0x{:x}", register, offset, cfa);
                    cfa
                }
            CfaRule::Expression(expr) => {
                unwinding_debugln!("Frame::unwind: CFA from expression");
                self.evaluate_expression(ctx, expr)?
            }
        };

        new_ctx[Arch::SP] = cfa as _;
        new_ctx[Arch::RA] = 0;
        unwinding_debugln!("Frame::unwind: set SP to 0x{:x}, RA to 0", cfa);

        #[warn(non_exhaustive_omitted_patterns)]
        for (reg, rule) in row.registers() {
            let value = match *rule {
                RegisterRule::Undefined | RegisterRule::SameValue => {
                    unwinding_debugln!("Frame::unwind: register {:?} = same value 0x{:x}", reg, ctx[*reg]);
                    ctx[*reg]
                },
                RegisterRule::Offset(offset) => {
                    let addr = cfa.wrapping_add(offset as usize);
                    let value = unsafe { *((addr) as *const usize) };
                    unwinding_debugln!("Frame::unwind: register {:?} = [0x{:x} + {}] = 0x{:x}", reg, cfa, offset, value);
                    value
                },
                RegisterRule::ValOffset(offset) => {
                    let value = cfa.wrapping_add(offset as usize);
                    unwinding_debugln!("Frame::unwind: register {:?} = 0x{:x} + {} = 0x{:x}", reg, cfa, offset, value);
                    value
                },
                RegisterRule::Register(r) => {
                    let value = ctx[r];
                    unwinding_debugln!("Frame::unwind: register {:?} = register {:?} = 0x{:x}", reg, r, value);
                    value
                },
                RegisterRule::Expression(expr) => {
                    unwinding_debugln!("Frame::unwind: register {:?} from expression", reg);
                    let addr = self.evaluate_expression(ctx, expr)?;
                    let value = unsafe { *(addr as *const usize) };
                    unwinding_debugln!("Frame::unwind: register {:?} = [0x{:x}] = 0x{:x}", reg, addr, value);
                    value
                }
                RegisterRule::ValExpression(expr) => {
                    unwinding_debugln!("Frame::unwind: register {:?} from value expression", reg);
                    let value = self.evaluate_expression(ctx, expr)?;
                    unwinding_debugln!("Frame::unwind: register {:?} = 0x{:x}", reg, value);
                    value
                },
                RegisterRule::Architectural => unreachable!(),
                RegisterRule::Constant(value) => {
                    unwinding_debugln!("Frame::unwind: register {:?} = constant 0x{:x}", reg, value);
                    value as usize
                },
                _ => unreachable!(),
            };
            new_ctx[*reg] = value;
        }

        unwinding_debugln!("Frame::unwind: frame unwind completed successfully");
        Ok(new_ctx)
    }

    pub fn bases(&self) -> &BaseAddresses {
        &self.fde_result.bases
    }

    pub fn personality(&self) -> Option<PersonalityRoutine> {
        self.fde_result
            .fde
            .personality()
            .map(|x| unsafe { deref_pointer(x) })
            .map(|x| unsafe { core::mem::transmute(x) })
    }

    pub fn lsda(&self) -> usize {
        self.fde_result
            .fde
            .lsda()
            .map(|x| unsafe { deref_pointer(x) })
            .unwrap_or(0)
    }

    pub fn initial_address(&self) -> usize {
        self.fde_result.fde.initial_address() as _
    }

    pub fn is_signal_trampoline(&self) -> bool {
        self.fde_result.fde.is_signal_trampoline()
    }
}