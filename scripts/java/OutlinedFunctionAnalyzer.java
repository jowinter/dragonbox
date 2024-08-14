// Basic analysis and back-annotation tool for clang-style outlined functions.
//
//@author Johannes Winter <jrandom@speed.at>
//@category dragonbox
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class OutlinedFunctionAnalyzer extends GhidraScript {
	/**
	 * Regex name matcher for compiler-generated outlined functions.
	 */
	private final Pattern outlineNamePattern = Pattern.compile("^OUTLINED_FUNCTION_([0-9]+)$");

	/**
	 * Name infix appended to outlined functions that are identified as delegate
	 * functions.
	 */
	private final String delegateInfix = ".To.";

	/**
	 * Name suffix appended to outlined functions that are identified as "simple"
	 * type.
	 */
	private final String simpleSuffix = ".Asm";

	@Override
	protected void run() throws Exception {
		// Extract outlined functions
		List<OutlinedFunctionInfo> outlines = getOutlinedFunctions(currentProgram);

		for (OutlinedFunctionInfo outline : outlines) {
			String basename = outline.function.getName();

			int dot_index = basename.indexOf('.');
			if (dot_index != -1) {
				// Already have some dot suffix - strip it
				basename = basename.substring(0, dot_index);
			}

			if (outline.getKind() == OutlinedFunctionKind.Delegate && outline.target != null) {
				// Rename "delegate" style functions
				//
				// NOTE: This prevents (re-)analysis by this script (as a side effect) as the
				// new name
				// no longer matches the outline name pattern.
				String new_name = basename + this.delegateInfix + outline.target.getName();
				outline.function.setName(new_name, SourceType.ANALYSIS);

				// Approximate the prototype
				approximatPrototype(outline);
			} else if (outline.getKind() == OutlinedFunctionKind.Simple) {
				// Rename "simple" style functions
				//
				// NOTE: This prevents (re-)analysis by this script (as a side effect) as the
				// new name
				// no longer matches the outline name pattern.
				String new_name = basename + this.simpleSuffix;
				outline.function.setName(new_name, SourceType.ANALYSIS);

				// TODO: Enable approximation of the prototype (requires better handling of CPU
				// flags etc).
				approximatPrototype(outline);
			}
		}
	}

	/**
	 * Analyzes all outlined functions in a program.
	 *
	 * @param program the program to be analyzed.
	 *
	 * @return A list of analysis results for the outlined functions in the given
	 *         program.
	 */
	public List<OutlinedFunctionInfo> getOutlinedFunctions(Program program) {
		List<OutlinedFunctionInfo> results = new ArrayList<>();

		for (Function func = getFirstFunction(); func != null; func = getFunctionAfter(func)) {
			if (isOutlinedFunction(func)) {
				OutlinedFunctionInfo info = new OutlinedFunctionInfo(func);
				results.add(info);
			}
		}

		return results;
	}

	/**
	 * Tests if the given function is an outlined function that can be analyzed by
	 * this script.
	 *
	 * @param func is the function to be tested.
	 * @return True if the function can be analyzed by this script, false otherwise.
	 */
	public boolean isOutlinedFunction(Function func) {
		// We currently only accept functions that match the OUTLINED_FUNCTION_xxx name
		// pattern,
		// and an unknown calling convention.
		return outlineNamePattern.matcher(func.getName()).matches() && func.hasUnknownCallingConventionName();
	}

	/**
	 * Approximates the prototype (function signature) of an outlined function.
	 *
	 * @param info provides the analysis information of the outlined function.
	 *
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	private void approximatPrototype(OutlinedFunctionInfo info) throws DuplicateNameException, InvalidInputException {
		Function func = info.getFunction();

		Variable ret_value = null;
		List<Variable> params = new ArrayList<>();
		String calling_conv = CompilerSpec.CALLING_CONVENTION_unknown;

		DataTypeManager dtm = func.getProgram().getDataTypeManager();

		OutlinedRegisterInfo regs = info.getRegisters();

		// Construct the input registers
		for (Register in_reg : regs.getInputs()) {
			DataType param_type = getDefaultDataType(dtm, in_reg.getNumBytes());
			Parameter in_param = new ParameterImpl(null, param_type, in_reg, func.getProgram(), SourceType.ANALYSIS);
			params.add(in_param);
		}

		// Sort the incoming paramters (using Ghidra's native register sorting order)
		Collections.sort(params);

		// Approximate the return value
		if (info.kind == OutlinedFunctionKind.Delegate && info.getTarget() != null) {
			// Delegate with well-known target
			Parameter target_ret = info.getTarget().getReturn();

			if (target_ret != null && !VoidDataType.isVoidDataType(target_ret.getDataType())) {
				ret_value = new ReturnParameterImpl(target_ret, func.getProgram());
			}

		} else if (info.kind == OutlinedFunctionKind.Simple) {

			// Outline function of "simple" kind
			ret_value = approximateReturnValueFromRegisters(dtm, info);
		}

		// Update the function signature (leave the return value intact - for now)
		func.updateFunction(calling_conv, ret_value, params, FunctionUpdateType.CUSTOM_STORAGE, true,
				SourceType.ANALYSIS);

	}

	/**
	 * @brief Approximates the return value (tuple) of an outlined function from its
	 *        register information.
	 * 
	 * @return A return value param
	 * @throws InvalidInputException
	 */
	private Parameter approximateReturnValueFromRegisters(DataTypeManager dtm, OutlinedFunctionInfo info)
			throws InvalidInputException {

		List<Register> out_regs = new ArrayList<Register>(info.getRegisters().getDefined());

		if (out_regs.size() == 0) {
			// Void result (no change)
			return null;

		} else if (out_regs.size() == 1) {
			// Simple outlined function with a single return register
			DataType param_type = getDefaultDataType(dtm, out_regs.get(0).getNumBytes());
			return new ReturnParameterImpl(param_type, out_regs.get(0), info.getFunction().getProgram());

		} else {
			// Simple outlined function result (need to synthesize a tuple type)
			Function func = info.getFunction();

			// Sort the list of output register by register size (this simplifies
			// straightforward packing into the tuple output structure)
			out_regs.sort(new Comparator<Register>() {
				@Override
				public int compare(Register o1, Register o2) {
					int delta = o1.getNumBytes() - o2.getNumBytes();

					if (delta > 0) {
						return -1;

					} else if (delta < 0) {
						return 1;

					} else {
						// Same size, fallback to Ghidra's default sorting order
						return o1.compareTo(o2);
					}
				}
			});

			// Construct the compound type
			CategoryPath outline_types = new CategoryPath("/OutlineReturnTuples");
			Category type_cat = dtm.createCategory(outline_types);
			String type_name = func.getName() + ".RetVal_t";

			StructureDataType ret_type = new StructureDataType(type_name, 0, dtm);
			ret_type.setDescription(
					String.format("Return tuple-type inferred for %s @ %s", func.getName(), func.getEntryPoint()));
			ret_type.setExplicitPackingValue(1);
			ret_type.setExplicitMinimumAlignment(1);

			List<DataTypeComponent> comps = new ArrayList<DataTypeComponent>(out_regs.size());

			for (Register out_reg : out_regs) {
				DataType field_type = getDefaultDataType(dtm, out_reg.getNumBytes());
				DataTypeComponent comp = ret_type.add(field_type, 0, out_reg.getName(), null);
			}

			DataType final_ret_type = type_cat.addDataType(ret_type, null);

			// Construct the variable storage for the return value
			//
			// TODO: Check if the "reversed" order is dependent on big/little endian
			// setting.
			List<Register> storage_regs = new ArrayList<Register>(out_regs);
			Collections.reverse(storage_regs);

			VariableStorage ret_storage = new VariableStorage(dtm.getProgramArchitecture(),
					storage_regs.toArray(new Register[0]));

			Parameter ret_param = new ReturnParameterImpl(final_ret_type, ret_storage, func.getProgram());

			printf("%s\n", ret_param);

			return ret_param;
		}
	}

	/**
	 * Gets our default data-type for the given size in bytes.
	 *
	 * @param dtm  is the data-type manager to use for lookup.
	 * @param size is the size in bytes.
	 * @return The matching default data type.
	 */
	private DataType getDefaultDataType(DataTypeManager dtm, int size) {
		String name = "/undefined";

		if (size == 1 || size == 2 || size == 4 || size == 8) {
			name += size;
		}

		return dtm.getDataType(name);
	}

	/**
	 * Category (kind) of an outlined function from perspective of this analyzer.
	 */
	public static enum OutlinedFunctionKind {
		/**
		 * Complex outlined function (no other more specific category applies).
		 */
		Complex,

		/**
		 * Simple outline function.
		 */
		Simple,

		/**
		 * Delegate (thunk-like) outline function.
		 */
		Delegate;

		/**
		 * Classifies an outlined function.
		 *
		 * @param body is an {@link Iterable} over the instruction of the function to be
		 *             analyzed.
		 * @return The analyzer category for the outlined function.
		 */
		public static OutlinedFunctionKind classify(Iterable<Instruction> body) {
			OutlinedFunctionKind kind = null;

			for (Instruction insn : body) {
				// TODO: Use attributes of flow type instead of object compares below
				FlowType flow = insn.getFlowType();

				if ((flow == RefType.CALL_TERMINATOR) && (kind == null)) {
					// Block terminator (tail-call)
					kind = OutlinedFunctionKind.Delegate;
				} else if (flow == RefType.TERMINATOR && (kind == null)) {
					// Block terminator (return)
					kind = OutlinedFunctionKind.Simple;
				} else if (flow == RefType.FALL_THROUGH && (kind == null)) {
					// Normal (fall-through) instruction
				} else {
					// Other flow type (e.g. computed call, ...) or "strange" block (e.g.
					// FALL_THROUGH after terminator)
					kind = OutlinedFunctionKind.Complex;
					break;
				}
			}

			// Fallback to complex
			return (kind != null) ? kind : OutlinedFunctionKind.Complex;
		}
	}

	/**
	 * @brief Analysis data (simple def-use style analysis) of an outlined function.
	 */
	public static class OutlinedRegisterInfo {
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
			this.inputs = new HashSet<Register>();
			this.defined = new HashSet<Register>();
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

	/**
	 * @brief Analysis data of an outlined function.
	 */
	public static class OutlinedFunctionInfo {
		private Function function;
		private Function target;
		private OutlinedFunctionKind kind;
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
			if (this.kind == OutlinedFunctionKind.Delegate) {
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

				this.regs = approximateRegisterUsage(insns, this.target);

			} else if (this.kind == OutlinedFunctionKind.Simple) {
				// Simple outlined function (no calls, terminator at the end)
				//
				// We assume linear control flow up to the start of the outlined function.
				//
				this.target = null;
				this.regs = approximateRegisterUsage(insns, null);

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
		 * @param insns  is the list of instruction found in the body of the outlined
		 *               function.
		 * @param target is the target function (if any)
		 * @return The (raw) set of input registers (potentially including the stack
		 *         pointer and stale flags) that are used in this function.
		 */
		private OutlinedRegisterInfo approximateRegisterUsage(List<Instruction> insns, Function target) {

			OutlinedRegisterInfo info = new OutlinedRegisterInfo(this);

			// Scan over the instructions (in execution order), and track definition and use
			// of registers:
			//
			// - We consider any registers that are used before definition as primary inputs
			// of
			// the outlined function.
			//
			for (int i = 0; i < (insns.size() - 1); ++i) {
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
			if (target != null) {
				for (Parameter param : target.getParameters()) {
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
}
