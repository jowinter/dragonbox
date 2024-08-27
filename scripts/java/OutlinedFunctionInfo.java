
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;

/**
 * @brief Analysis data of an outlined function.
 */
public class OutlinedFunctionInfo {
	Function function;
	Function target;
	OutlinedFunctionKind kind;
	private OutlinedRegisterInfo regs;

	/**
	 * Analyzes the given outlined function.
	 *
	 * @param func is the function to be analyzed.
	 */
	public OutlinedFunctionInfo(Function func) {
		this.function = func;

		List<Instruction> insns = getBodyInstructions(func);

		this.kind = OutlinedFunctionKind.classify(insns);

		// Analyze depending on the function category
		if (this.kind == OutlinedFunctionKind.DELEGATE) {
			// Outlined delegate function (last instruction is a tail-call)
			//
			// We assume linear control flow up to the start of the function.
			//
			Address[] flows = insns.get(insns.size() - 1).getFlows();
			if (flows.length == 1) {
				// We have exactly one target flow
				this.target = function.getProgram().getListing().getFunctionAt(flows[0]);
			} else {
				// No unique target
				this.target = null;
			}

			this.regs = approximateRegisterUsage(insns, this.target, false);

		} else if (this.kind == OutlinedFunctionKind.SIMPLE) {
			// Simple outlined function (no calls, terminator at the end)
			//
			// We assume linear control flow up to the terminator at the end of the outlined
			// function.
			//
			this.target = null;
			this.regs = approximateRegisterUsage(insns, null, false);

		} else if (this.kind == OutlinedFunctionKind.COMPUTED_JUMP) {
			// Simple outlined function (no calls, terminator at the end) with a computed
			// jump at the end.
			//
			// We assume linear control flow up to the terminator at the end of the outlined
			// function. Analysis is similar to the SIMPLE case, but we additionally analyze
			// the terminator instruction to capture the target function pointer.
			//
			this.target = null;
			this.regs = approximateRegisterUsage(insns, null, true);

		} else {
			// Complex outlined function
			this.target = null;
			this.regs = null;
		}
	}

	/**
	 * Gets the underlying outlined function.
	 *
	 * @return The outlined function that was analyzed to produce this analysis data
	 *         object.
	 */
	public Function getFunction() {
		return this.function;
	}

	/**
	 * Gets the (delegate) target function of the underlying outlined function.
	 *
	 * @return The target function that is tail-called by the underlying outlined
	 *         function, or {@code null} if the underlying outlined function is not
	 *         a delegate function.
	 */
	public Function getTarget() {
		return this.target;
	}

	/**
	 * Gets the (approximated) register usage analysis of this function.
	 *
	 * @return The set of (raw) input / output registers (potentially containing the
	 *         stack pointer and CPU flags) that were discovered during analysis, or
	 *         {@code null} if the set is unknown (complex outlined function).
	 */
	public OutlinedRegisterInfo getRegisters() {
		return this.regs;
	}

	/**
	 * Gets the category of the underlying outlined function.
	 *
	 * @return The categroy of the underlying outlined function.
	 */
	public OutlinedFunctionKind getKind() {
		return this.kind;
	}

	/**
	 * Gets a list of all instructions in the body of a function.
	 *
	 * @param func the function to be scennaed.
	 * @return A list of the instruction in the body of a functions.
	 */
	private List<Instruction> getBodyInstructions(Function func) {
		ArrayList<Instruction> insns = new ArrayList<>();
		for (Instruction insn : func.getProgram().getListing().getInstructions(func.getBody(), true)) {
			insns.add(insn);
		}

		return insns;
	}

	/**
	 * Computes the (estimated) set of input registers and output registers of an
	 * outlined function.
	 *
	 * This analysis step assumes that the body of the outlined function consists of
	 * a linear sequence of unconditional instructions followed by a single branch
	 * or terminator at the end. (i.e. the body has basic block like semantics).
	 *
	 * @param insns              is the list of instruction found in the body of the
	 *                           outlined function.
	 *
	 * @param target_func        is the target function (if any)
	 * 
	 * @param analyze_terminator controls if the terminator instruction itself
	 *                           should be analyzed for the register usage
	 *                           estimation.
	 *
	 * @return The (raw) set of input registers (potentially including the stack
	 *         pointer and stale flags) that are used in this function.
	 */
	private OutlinedRegisterInfo approximateRegisterUsage(List<Instruction> insns, Function target_func,
			boolean analyze_terminator) {

		OutlinedRegisterInfo info = new OutlinedRegisterInfo(this);

		// Scan over the instructions (in execution order), and track definition and use
		// of registers:
		//
		// - We consider any registers that are used before definition as primary inputs
		// of the outlined function.
		//
		final int num_insns = analyze_terminator ? insns.size() : (insns.size() - 1);

		for (int i = 0; i < num_insns; ++i) {
			Instruction insn = insns.get(i);

			// Scan over the inputs of this instruction
			for (Object input_obj : insn.getInputObjects()) {
				if (input_obj instanceof Register) {
					// Register operand
					Register reg = (Register) input_obj;

					info.use(reg);

				} else {
					// Scalar or other unhandled operand
					//
					// TODO: Any special handling required?
				}
			}

			// Scan over the inputs of this instruction
			for (Object output_obj : insn.getResultObjects()) {
				if (output_obj instanceof Register) {
					// Register operand
					Register reg = (Register) output_obj;

					// Track as defined register
					info.define(reg);
				} else {
					// Scalar or other unhandled operand
					//
					// TODO: Any special handling required?
				}
			}
		}

		// Handle the target function at the end of the block
		if (target_func != null) {
			for (Parameter param : target_func.getParameters()) {
				// Add all input registers that are not part of the defined registers set
				info.use(param.getRegisters());
			}
		}

		// TODO: Better handling for the stack pointer and of processor flags
		//
		// - We probably should bail out if we see a modification of the stack pointer.
		// - Processor flags could potentially be handled by looking at PCode (and
		// analysis capabilities)
		return info;
	}
}