
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;

/**
 * @brief Analysis data (simple def-use style analysis) of an outlined function.
 */
public class OutlinedRegisterInfo {
	/**
	 * @brief Gets the parent function that was analyzed to produce this data set.
	 */
	private OutlinedFunctionInfo parent;

	/**
	 * @brief Set of input register identified in an outlined function.
	 */
	private Set<Register> inputs;

	/**
	 * @brief Set of registers that are defined in an outlined function.
	 */
	private Set<Register> defined;

	/**
	 * @brief Constructs an empty (mutable) register analysis data set.
	 */
	OutlinedRegisterInfo(OutlinedFunctionInfo parent) {
		this.parent = parent;
		this.inputs = new HashSet<>();
		this.defined = new HashSet<>();
	}

	/**
	 * @brief Tests if a given register should be tracked.
	 *
	 * @param reg is the register to be tracked.
	 * @return True if the register should be tracked, false otherwise.
	 */
	private boolean shouldTrack(Register reg) {
		// Ignore hidden and blacklisted register
		//
		// FIXME: We need a more portable way to identify "blacklisted" register.
		// (Currently we ignore anything starting with "tmp" or named "shift_carry"
		// based on the ARM model).
		String name = reg.getName();
		if (reg.isHidden() || name.equals("shift_carry") || name.startsWith("tmp")) {
			return false;
		}

		// Check compiler and platform specific traits
		Function func = this.parent.getFunction();
		CompilerSpec cspec = func.getProgram().getCompilerSpec();

		// TODO: Better handling of the stack pointer? (we currently track the stack
		// pointer to provide better disassembly for functions that have e.g. stack
		// relative stores)
		//
		// Register sp = cspec.getStackPointer();
		// if (sp.equals(reg)) {
		// return false;
		// }

		// FIXME: Portable lookup for link register
		Register lr = func.getProgram().getProgramContext().getRegister("lr");
		if (lr.equals(reg)) {
			return false;
		}

		// Assume that the register is to be tracked.
		return true;
	}

	/**
	 * @brief Track the (potentially first) use of registers in an iterable sequence
	 *
	 * @param regs is the iterable sequence of register to be tracked. (Can be
	 *             {@code null} or empty)
	 */
	public void use(Iterable<Register> regs) {
		if (regs != null) {
			for (Register reg : regs) {
				use(reg);
			}
		}
	}

	/**
	 * @brief Tracks the (potentially first) use of a register.
	 *
	 * @param reg is the register being used.
	 */
	public void use(Register reg) {
		if (shouldTrack(reg)) {
			if (!this.inputs.contains(reg) && !this.defined.contains(reg)) {
				// No definition (from primary input or assignments) found, track as primary
				// input
				this.inputs.add(reg);
			}
		}
	}

	/**
	 * @brief Track the (potentially first) (re-)definition of registers in an
	 *        iterable sequence
	 *
	 * @param regs is the iterable sequence of register to be tracked. (Can be
	 *             {@code null} or empty)
	 */
	public void define(Iterable<Register> regs) {
		if (regs != null) {
			for (Register reg : regs) {
				define(reg);
			}
		}
	}

	/**
	 * @brief Tracks (re-)definition of a register.
	 *
	 * @param reg is the register to be (re-)defined.
	 */
	public void define(Register reg) {
		if (shouldTrack(reg)) {
			this.defined.add(reg);
		}
	}

	/**
	 * @brief Gets the parent function that was used to produce this data set.
	 *
	 * @return The parent function of this analysis data set.
	 */
	public OutlinedFunctionInfo getParent() {
		return this.parent;
	}

	/**
	 * @brief Gets (approximated) set of input register of an outlined function.
	 *
	 * @return
	 */
	public Set<Register> getInputs() {
		return this.inputs;
	}

	/**
	 * @brief Gets (approximated) set of (re-)defined registers of an outlined
	 *        function.
	 *
	 * @return
	 */
	public Set<Register> getDefined() {
		return this.defined;
	}
}