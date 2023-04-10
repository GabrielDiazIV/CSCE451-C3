/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Outputs Decompiled Assembly to a chosen file, attempts to format the assembly somewhat as well
// Must be run in Ghidra
// @category Assembly
import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.ArrayList;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ExportAssembly extends GhidraScript {
	@Override
	public void run() throws Exception {
		List<String> registers64 = new ArrayList<String>();
		registers64.add("rax");
		registers64.add("rbx");
 		registers64.add("rcx");
		registers64.add("rdx");
		registers64.add("rsp");
		registers64.add("rbp");

		List<String> registers32 = new ArrayList<String>();
		registers32.add("eax");
		registers32.add("ebx");
		registers32.add("ecx");
		registers32.add("edx");
		registers32.add("esp");
		registers32.add("ebp");

		List<String> registers = new ArrayList<String>();
		registers.addAll(registers64);
		registers.addAll(registers32);

		File outputFile = askFile("Please Select Output File", "Choose");

		FileWriter outputWriter = new FileWriter(outputFile);

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();

			Address e = f.getEntryPoint();
			
			while(true) {
					Instruction instr = getInstructionAt(e);
			
			if (instr != null) {
			String instruction = instr.toString().toLowerCase();

			for (String register : registers) {
				if (instruction.contains(register) && !instruction.contains("["+register)) {
			instruction = new StringBuilder(instruction).insert(instruction.indexOf(register), "%").toString();
			}
			}
				outputWriter.write(instruction+ "\n");

			if (instr.getMnemonicString().contains("RET")) {
				break;
			}
			}
			
			e = e.next();
			}
		}

		outputWriter.close();

		println("Wrote functions to " + outputFile);
	}
}
