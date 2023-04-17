//Interface for Pyrun
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.io.*;

public class C3Main extends GhidraScript {

    private HashMap<String,Function> functions;
	// The path to your pyrun installation
	// Should be in your ghidra_scripts folder
	final String PYRUN_PATH = System.getProperty("user.home") + "/ghidra_scripts/";

	@Override
	public void run() throws Exception {

		String choice =
			askChoice("Choose Export Type", "Do you want to export this program's decompiled code or assembly?", Arrays.asList("Decompiled Code", "Assembly"), "Decompiled Code");

		if (choice.equals("Decompiled Code")) {
			importFunctions();
			choice = askChoice("Choose Export Type", "Do you want to export one function (and dependencies) or all?", Arrays.asList("All Functions", "One Function"), "All Functions");
			if (choice.equals("All Functions")) {
				do {
					runCommand(getPyrunScriptPath("extract.py"));
					choice = askChoice("Choose Function", "Choose a function to run", new ArrayList<String>(functions.keySet()),null);
					Function f = functions.get(choice);
					runFunction(f);
				}
				while (askYesNo("Continue?", "Do you want to continue running functions?"));
			}
			else if (choice.equals("One Function")) {
			do {
				choice = askChoice("Choose Function", "Choose a function to export", new ArrayList<String>(functions.keySet()),null);
				runCommand(getPyrunScriptPath("extract.py") + " -f " + choice);
				Function f = functions.get(choice);
				runFunction(f);
			} while (askYesNo("Continue?", "Do you want to export and run a new function?"));
			}
		}
		else if (choice.equals("Assembly")) {
			runScript("ExportAssembly.java");
		}
	}

	private void importFunctions() {
        functions = new HashMap<String,Function>();
		Function function = getFirstFunction();
		while (true) {
			if (monitor.isCancelled()) {
				break;
			}
			if (function == null) {
				break;
			}
            functions.put(getPyrunFunctionName(function),function);
			function = getFunctionAfter(function);
		}
	}

	private void runFunction(Function f) {
		try {
			String args = getPyrunScriptPath("runner.py") + " " + getPyrunFunctionName(f) + " ";
			for (Parameter p : f.getParameters()) {
				String param = askString(getPyrunFunctionName(f) + " Parameter Entry", "Enter a value for parameter " + p.getName() + " of type " + p.getFormalDataType().getDisplayName());
				args += param + " ";
			}
			runCommand(args);
		}
		catch(CancelledException e) {
			e.printStackTrace();
		}
	}

	private String getPyrunFunctionName(Function f) {
		return f.getName() + "@" + f.getEntryPoint();
	}

	private String getPyrunScriptPath(String name) {
		return   "python3 " + PYRUN_PATH + name;
	}

	private void runCommand(String command) {
		ProcessBuilder processBuilder = new ProcessBuilder();
		processBuilder.command("bash", "-c", command);
		processBuilder.directory(new File(PYRUN_PATH));
		processBuilder.redirectErrorStream(true);
		try {
			Process process = processBuilder.start();
			StringBuilder output = new StringBuilder();

			BufferedReader reader = new BufferedReader(
					new InputStreamReader(process.getInputStream()));

			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line + "\n");
			}

			int exitVal = process.waitFor();
			if (exitVal == 0) {
				println(output.toString());
			}
			else {
				println(output.toString());
			} 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}