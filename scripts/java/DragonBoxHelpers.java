import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/**
 * @brief Helper functions shared between the "dragonbox" scripts.
 */
public abstract class DragonBoxHelpers {
	private DragonBoxHelpers() {
	}

	/**
	 * Gets the (possibly empty) set of functions in the currently selected address
	 * range.
	 * 
	 * @param script    is the calling Ghidra script.
	 * 
	 * @param selection is the current program selection. The users is asked whether
	 *                  the whole program should be scanned, if an empty or @c null
	 *                  selection is passed. In headless mode it is assumed that the
	 *                  caller wants to scan the whole program (without user
	 *                  interaction) if an empty or @c null selection is given.
	 * 
	 * @return A (possibly empty) array of functions in the current selection.
	 *         Functions listed in the result array are sorted by increasing memory
	 *         addresses.
	 */
	public static Function[] getSelectedFunctions(GhidraScript script, ProgramSelection selection, boolean ask_user) {
		Function[] result = new Function[0];

		Program prog = script.getCurrentProgram();

		if (prog != null) {
			Set<Function> functions = new HashSet<Function>();

			if (selection != null && !selection.isEmpty()) {
				// Selection provided by caller, scan only the selected tange
				for (Address addr : selection.getAddresses(true)) {
					Function func = script.getFunctionContaining(addr);
					if (func != null) {
						functions.add(func);
					}
				}

			} else if (script.isRunningHeadless() || script.askYesNo("Target selection",
					"The current program selection is empty.\nWould you like to scan the entire program?")) {

				// Script is running in headless mode, or use wants to scan the whole program.
				for (Function func = script.getFirstFunction(); func != null; func = script.getFunctionAfter(func)) {
					functions.add(func);
				}
			}

			result = functions.toArray(result);

			Arrays.sort(result, new Comparator<Function>() {
				@Override
				public int compare(Function o1, Function o2) {
					return o1.getEntryPoint().compareTo(o2.getEntryPoint());
				}

			});
		}

		return result;
	}
}
