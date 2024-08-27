
import ghidra.app.script.GhidraScript;
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
	COMPLEX,

	/**
	 * Simple outline function.
	 */
	SIMPLE,

	/**
	 * Delegate (thunk-like) outline function with static branch target.
	 */
	DELEGATE,

	/**
	 * Delegate (think-like) outline function with computed a computed branch at its
	 * end.
	 */
	COMPUTED_JUMP;

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
				kind = OutlinedFunctionKind.DELEGATE;
			} else if (flow == RefType.TERMINATOR && (kind == null)) {
				// Block terminator (return)
				kind = OutlinedFunctionKind.SIMPLE;
			} else if (flow == RefType.FALL_THROUGH && (kind == null)) {
				// Normal (fall-through) instruction
			} else if (flow == RefType.COMPUTED_JUMP && (kind == null)) {
				// Block terminator (computed jump)
				kind = OutlinedFunctionKind.COMPUTED_JUMP;
			} else {
				// Other flow type (e.g. computed call, ...) or "strange" block (e.g.
				// FALL_THROUGH after terminator)
				kind = OutlinedFunctionKind.COMPLEX;
				break;
			}
		}

		// Fallback to complex
		return (kind != null) ? kind : OutlinedFunctionKind.COMPLEX;
	}
}