
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * Category (kind) of an outlined function from perspective of this analyzer.
 */
public enum OutlinedFunctionKind {
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