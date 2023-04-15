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
// @category Assembly
import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.ArrayList;
import java.lang.String;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ExportAssembly extends GhidraScript {
	@Override
	public void run() throws Exception {
		// Mising or new registers can be added following the format of the registers below
		// It is recommended to create a new array list of registers before adding it to the
		// Complete collection of registers. We gather all the possible registers here so we can
		// Perform string manipulation on the assembly later that will affect all registers
		List<String> registers64 = new ArrayList<String>();
		registers64.add("rax");
		registers64.add("rbx");
 		registers64.add("rcx");
		registers64.add("rdx");
		registers64.add("rsp");
		registers64.add("rbp");
		registers64.add("rsi");
		registers64.add("rdi");
		registers64.add("r8");
		registers64.add("r9");
		registers64.add("r10");
		registers64.add("r11");
		registers64.add("r12");
		registers64.add("r13");
		registers64.add("r14");
		registers64.add("r15");		

		List<String> registers32 = new ArrayList<String>();
		registers32.add("eax");
		registers32.add("ebx");
		registers32.add("ecx");
		registers32.add("edx");
		registers32.add("esp");
		registers32.add("ebp");
		registers32.add("edi");
		registers32.add("esi");
		registers32.add("r8d");
		registers32.add("r9d");
		registers32.add("r10d");
		registers32.add("r11d");
		registers32.add("r12d");
		registers32.add("r13d");
		registers32.add("r14d");
		registers32.add("r15d");

		List<String> registers16 = new ArrayList<String>();
		registers16.add("ax");
		registers16.add("bx");
		registers16.add("cx");
		registers16.add("dx");
		registers16.add("sp");
		registers16.add("bp");
		registers16.add("di");
		registers16.add("si");
		registers16.add("r8w");
		registers16.add("r9w");
		registers16.add("r10w");
		registers16.add("r11w");
		registers16.add("r12w");
		registers16.add("r13w");
		registers16.add("r14w");
		registers16.add("r15w");

		List<String> registers8h = new ArrayList<String>();
		registers8h.add("ah");
		registers8h.add("bh");
		registers8h.add("ch");
		registers8h.add("dh");

		List<String> registers8l = new ArrayList<String>();
		registers16.add("al");
		registers16.add("bl");
		registers16.add("cl");
		registers16.add("dl");
		registers16.add("spl");
		registers16.add("bpl");
		registers16.add("dil");
		registers16.add("sil");
		registers16.add("r8b");
		registers16.add("r9b");
		registers16.add("r10b");
		registers16.add("r11b");
		registers16.add("r12b");
		registers16.add("r13b");
		registers16.add("r14b");
		registers16.add("r15b");

		List<String> registers = new ArrayList<String>();
		registers.addAll(registers64);
		registers.addAll(registers32);
		registers.addAll(registers16);
		registers.addAll(registers8h);
		registers.addAll(registers8l);

		File outputFile = askFile("Please Select Output File", "Choose");

		FileWriter outputWriter = new FileWriter(outputFile);

		InstructionIterator instructions = currentProgram.getListing().getInstructions(true);

		while (instructions.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = instructions.next();
			String instr = instruction.toString().toLowerCase();

			/*
			Examples of code transformation:

			//modify all registers here
			for (String register : registers) {
				// add % before all registers
				instr = instr.replace(" " + register, " %" + register);
				instr = instr.replace("[" + register, "[%" + register);
			}

			// remove qword, dword, or ptr
			instr = instr.replace("qword ", "");
			instr = instr.replace("dword ", "");
			instr = instr.replace("ptr ", "");

			// Reverse order of instructions ie src, dst to dst, src
			if (instr.contains(",")) {
			int f = instr.indexOf(" ");
			int s = instr.indexOf(",");
			String first = instr.substring(f,s);
			instr = instr.replace(first + ",", " ");
			instr = instr + "," + first;
			} 
			*/
			
			// Output to file, SHOULD ALWAYS BE AFTER STRING MANIPULATION
			outputWriter.write(instr + "\n");
		}

		outputWriter.close();

		println("Wrote functions to " + outputFile);
	}
}
