// Basic analysis and back-annotation tool for clang-style outlined functions.
//
//@author Johannes Winter <jrandom@speed.at>
//@category dragonbox
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class OutlinedFunctionAnalyzer extends GhidraScript 
{
	/**
	 * Regex name matcher for compiler-generated outlined functions.
	 */
	private final Pattern outlineNamePattern = Pattern.compile("^OUTLINED_FUNCTION_([0-9]+)$");  
	
	/**
	 * Name infix appended to outlined functions that are identified as delegate functions.
	 */
	private final String delegateInfix = ".To.";
	
	/**
	 * Name suffix appended to outlined functions that are identified as "simple" type.
	 */
	private final String simpleSuffix = ".Asm";
	
	@Override
	protected void run() throws Exception 
	{
		// Extract outlined functions
		List<OutlinedFunctionInfo> outlines = getOutlinedFunctions(currentProgram);
		
		for (OutlinedFunctionInfo outline : outlines)
		{
			String basename = outline.function.getName();
			
			int dot_index = basename.indexOf('.');
			if (dot_index != -1)
			{
				// Already have some dot suffix - strip it
				basename = basename.substring(0, dot_index);
			}
			
			if (outline.getKind() == OutlinedFunctionKind.Delegate && outline.target != null)
			{
				// Rename "delegate" style functions
				//
				// NOTE: This prevents (re-)analysis by this script (as a side effect) as the new name
				// no longer matches the outline name pattern.
				String new_name = basename + this.delegateInfix + outline.target.getName();
				outline.function.setName(new_name, SourceType.ANALYSIS);
				
				// Approximate the prototype
				approximatPrototype(outline);
			}
			else if (outline.getKind() == OutlinedFunctionKind.Simple)
			{
				// Rename "simple" style functions 
				//
				// NOTE: This prevents (re-)analysis by this script (as a side effect) as the new name
				// no longer matches the outline name pattern.
				String new_name = basename + this.simpleSuffix;
				outline.function.setName(new_name, SourceType.ANALYSIS);
				
				// TODO: Enable approximation of the prototype (requires better handling of CPU flags etc).
				// approximatPrototype(outline);
			}
		}
	}
	
	/**
	 * Analyzes all outlined functions in a program.
	 * 
	 * @param program the program to be analyzed.
	 * 
	 * @return A list of analysis results for the outlined functions in the given program.
	 */
	public List<OutlinedFunctionInfo> getOutlinedFunctions(Program program)
	{
		List<OutlinedFunctionInfo> results = new ArrayList<OutlinedFunctionInfo>();
		
		for (Function func = getFirstFunction(); func != null; func = getFunctionAfter(func))
		{
			if (isOutlinedFunction(func))
			{
				OutlinedFunctionInfo info = new OutlinedFunctionInfo(func);
				results.add(info);
			}
		}
		
		return results;
	}
	
	/**
	 * Tests if the given function is an outlined function that can be analyzed by this script.
	 *  
	 * @param func is the function to be tested.
	 * @return True if the function can be analyzed by this script, false otherwise.
	 */
	public boolean isOutlinedFunction(Function func)
	{
		// We currently only accept functions that match the OUTLINED_FUNCTION_xxx name pattern,
		// and an unknown calling convention.		
		return outlineNamePattern.matcher(func.getName()).matches() &&
			func.hasUnknownCallingConventionName();
	}
	
	/**
	 * Approximates the prototype (function signature) of an outlined function.
	 *
	 * @param info provides the analysis information of the outlined function.
	 * 
	 * @throws InvalidInputException 
	 * @throws DuplicateNameException 
	 */
	private void approximatPrototype(OutlinedFunctionInfo info) throws DuplicateNameException, InvalidInputException
	{		
		Function func = info.getFunction();
		CompilerSpec cspec = func.getProgram().getCompilerSpec();		
		
		Variable ret_value = null;
		List<Variable> params = new ArrayList<Variable>();
		String calling_conv = CompilerSpec.CALLING_CONVENTION_unknown;

		// Remove stack pointer from input set
		Set<Register> inputs = new HashSet<Register>(info.getInputs());
		if (inputs != null)
		{
			Register sp = cspec.getStackPointer();
			
			// FIXME: Portable lookup for link register
			Register lr = func.getProgram().getProgramContext().getRegister("lr");

			DataTypeManager dtm = func.getProgram().getDataTypeManager();

			for (Register in_reg : inputs)
			{
				// We currently ignore the stack pointer (and link register, if it exists) as inputs
				if (in_reg == sp || in_reg == lr) {
					continue;
				}

				// TODO: Type inference, etc.
				DataType param_type = getDefaultDataType(dtm, in_reg.getNumBytes());
				Parameter in_param = new ParameterImpl(null, param_type, in_reg, func.getProgram(), SourceType.ANALYSIS);

				params.add(in_param);
			}
		}
		
		// Infer the return value
		if (info.kind == OutlinedFunctionKind.Delegate && info.getTarget() != null)
		{
			Parameter target_ret = info.getTarget().getReturn();
			if (target_ret != null && !VoidDataType.isVoidDataType(target_ret.getDataType()))
			{
				// TODO: Is there a better way to construct the parameter? (factory?)
				ret_value = new ParameterImpl(target_ret, func.getProgram());
			}
		}
		
		// And finally update the function signature
		func.updateFunction(calling_conv, ret_value, params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
	}
	
	
	/**
	 * Gets our default data-type for the given size in bytes.
	 *  
	 * @param dtm is the data-type manager to use for lookup.
	 * @param size is the size in bytes.
	 * @return The matching default data type.
	 */
	private DataType getDefaultDataType(DataTypeManager dtm, int size)
	{
		String name = "/undefined";
		
		if (size == 1 || size == 2 || size == 4 || size == 8)
		{
			name += size;
		}
		
		return dtm.getDataType(name);
	}
	
	/**
	 * Category (kind) of an outlined function from perspective of this analyzer.
	 */
	public static enum OutlinedFunctionKind
	{
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
		 * @param body is an {@link Iterable} over the instruction of the function to be analyzed.
		 * @return The analyzer category for the outlined function.
		 */
		public static OutlinedFunctionKind classify(Iterable<Instruction> body)
		{
			OutlinedFunctionKind kind = null;

			for (Instruction insn : body)
			{
				// TODO: Use attributes of flow type instead of object compares below
				FlowType flow = insn.getFlowType();
				
				if ((flow == FlowType.CALL_TERMINATOR) && (kind == null))
				{
					// Block terminator (tail-call)
					kind = OutlinedFunctionKind.Delegate;
				}
				else if (flow == FlowType.TERMINATOR && (kind == null))
				{
					// Block terminator (return)
					kind = OutlinedFunctionKind.Simple;
				}
				else if (flow == FlowType.FALL_THROUGH && (kind == null))
				{
					// Normal (fall-through) instruction
				}
				else
				{
					// Other flow type (e.g. computed call, ...) or "strange" block (e.g. FALL_THROUGH after terminator)
					kind = OutlinedFunctionKind.Complex;
					break;
				}
			}
			
			// Fallback to complex
			return (kind != null) ? kind : OutlinedFunctionKind.Complex;
		}
	}
	
	/**
	 * @brief Analysis data for an outlined function.
	 */
	public static class OutlinedFunctionInfo
	{
		private Function function;
		private Function target;
		private OutlinedFunctionKind kind;
		private Set<Register> inputs;

		/**
		 * Analyzes the given outlined function.
		 * 
		 * @param func is the function to be analyzed.
		 */
		public OutlinedFunctionInfo(Function func)
		{
			this.function = func;
						
			List<Instruction> insns = getBodyInstructions(func);

			this.kind = OutlinedFunctionKind.classify(insns);

			// Analyze depending on the function category
			if (this.kind == OutlinedFunctionKind.Delegate)
			{
				// Outlined delegate function (last instruction is a tail-call)
				//
				// We assume linear control flow up to the start of the function.
				//
				Address[] flows = insns.get(insns.size() - 1).getFlows();
				if (flows.length == 1)
				{
					// We have exactly one target flow
					this.target = function.getProgram().getListing().getFunctionAt(flows[0]);					
				}
				else
				{
					// No unique target
					this.target = null;
				}
				
				this.inputs = getInputRegisters(insns, this.target);
			}
			else if (this.kind == OutlinedFunctionKind.Simple)
			{
				// Simple outlined function (no calls, terminator at the end)
				//
				// We assume linear control flow up to the start of the outlined function.
				//
				this.target = null;
				this.inputs = getInputRegisters(insns, null);
			}
			else
			{
				// Complex outlined function
				this.target = null;
				this.inputs = null;
			}
		}

		/**
		 * Gets the underlying outlined function.
		 * 
		 * @return The outlined function that was analyzed to produce this analysis data object.
		 */
		public Function getFunction()
		{
			return this.function;
		}
		
		/**
		 * Gets the (delegate) target function of the underlying outlined function.
		 * 
		 * @return The target function that is tail-called by the underlying outlined function,
		 *   or {@code null} if the underlying outlined function is not a delegate function.
		 */
		public Function getTarget()
		{
			return this.target;
		}
		
		/**
		 * Gets the set of (known) input register of the underlying outlined function.
		 * 
		 * @return The set of (raw) input registers (potentially containing the stack pointer and
		 *   CPU flags) that were discovered during analysis, or {@code null} if the set is
		 *   unknown (complex outlined function).
		 */
		public Set<Register> getInputs()
		{			
			return this.inputs;
		}

		/**
		 * Gets the category of the underlying outlined function.
		 *
		 * @return The categroy of the underlying outlined function.
		 */
		public OutlinedFunctionKind getKind()
		{
			return this.kind;
		}
		
		/**
		 * Gets a list of all instructions in the body of a function.
		 * 
		 * @param func the function to be scennaed.
		 * @return A list of the instruction in the body of a functions.
		 */
		private List<Instruction> getBodyInstructions(Function func)
		{
			ArrayList<Instruction> insns = new ArrayList<Instruction>();
			for (Instruction insn : func.getProgram().getListing().getInstructions(func.getBody(), true))
			{
				insns.add(insn);
			}
			
			return insns;
		}
		
		/**
		 * Computes the (estimated) set of input registers of an outlined function.
		 * 
		 * This analysis step assumes that the body of the outlined function consists of a
		 * linear sequence of unconditional instructions followed by a single branch
		 * or terminator at the end. (i.e. the body has basic block like semantics).
		 * 
		 * @param insns is the list of instruction found in the body of the outlined function.
		 * @param target is the target function (if any)
		 * @return The (raw) set of input registers (potentially including the stack pointer and stale
		 *   flags) that are used in this function.
		 */
		private Set<Register> getInputRegisters(List<Instruction> insns, Function target)
		{
			Set<Register> primary_inputs = new HashSet<Register>();
			Set<Register> defined_regs   = new HashSet<Register>();
			
			// TODO: Populate the initial set of input register from the terminator instruction
					
			// Scan over the instructions (in execution order), and track definition and use
			// of registers:
			//
			// - We consider any registers that are used before definition as primary inputs of
			//   the outlined function.
			//
			for (int i = 0; i < (insns.size() - 1); ++i)
			{
				Instruction insn = insns.get(i);
				
				// Scan over the inputs of this instruction
				for (Object input_obj : insn.getInputObjects())
				{
					if (input_obj instanceof Register)
					{
						// Register operand
						Register reg = (Register) input_obj;
						if (!defined_regs.contains(reg)) 
						{
							// Track as primary input (if we don't have a definition yet)
							primary_inputs.add(reg);
							
							// And track as defined register
							defined_regs.add(reg);
						}
					}
					else
					{
						// Scalar or other unhandled operand
						//
						// TODO: Any special handling required?
					}
				}
				
				// Scan over the inputs of this instruction
				for (Object output_obj : insn.getResultObjects())
				{
					if (output_obj instanceof Register)
					{
						// Register operand
						Register reg = (Register) output_obj;
						
						// Track as defined register						
						defined_regs.add(reg);
					}
					else
					{
						// Scalar or other unhandled operand
						//
						// TODO: Any special handling required?
					}
				}
			}
			
			// Handle the target function at the end of the block
			if (target != null)
			{
				for (Parameter param : target.getParameters())
				{
					// Add all input registers that are not part of the defined registers set
					List<Register> regs = param.getRegisters();
					
					if (regs != null)
					{
						for (Register reg : regs)
						{
							if (!defined_regs.contains(reg)) 
							{
								primary_inputs.add(reg);
							}
						}
					}
				}
			}

			// TODO: Better handling for the stack pointer and of processor flags
			//
			// - We probably should bail out if we see a modification of the stack pointer.
			// - Processor flags could potentially be handled by looking at PCode (and analysis capabilities)
			return Collections.unmodifiableSet(primary_inputs);
		}
	}
}
