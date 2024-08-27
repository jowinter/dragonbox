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
import java.util.List;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
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

		List<Register> out_regs = new ArrayList<>(info.getRegisters().getDefined());

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

			for (Register out_reg : out_regs) {
				DataType field_type = getDefaultDataType(dtm, out_reg.getNumBytes());
				ret_type.add(field_type, 0, out_reg.getName(), null);
			}

			DataType final_ret_type = type_cat.addDataType(ret_type, null);

			// Construct the variable storage for the return value
			//
			// TODO: Check if the "reversed" order is dependent on big/little endian
			// setting.
			List<Register> storage_regs = new ArrayList<>(out_regs);
			Collections.reverse(storage_regs);

			VariableStorage ret_storage = new VariableStorage(dtm.getProgramArchitecture(),
					storage_regs.toArray(new Register[0]));

			Parameter ret_param = new ReturnParameterImpl(final_ret_type, ret_storage, func.getProgram());

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
}
