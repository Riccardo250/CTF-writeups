//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ISF.*;

public class UnpackMolly extends GhidraScript {
	
	public byte unpack_byte(byte b, byte key)  {
		byte temp1 = (byte)((b >> 4) & 0x0F);
		byte temp2 = (byte)((b << 4) & 0xF0);
	    byte temp = (byte)((temp1 | temp2) & 0xff);
	    byte res = (byte)(temp ^ key);
	    return res;
	}

    public void run() throws Exception {
		Program p = getState().getCurrentProgram();
		Listing l = p.getListing();
		
		MemoryBlock textBlock = null;
		
		for(MemoryBlock block: p.getMemory().getBlocks()) {
			if(block.getName().equals(".text")) {
				println("Text found!");
				textBlock = block;
			}
		}
		
		if(textBlock != null) {
			AddressRange addressRange = textBlock.getAddressRange();
			l.clearCodeUnits(addressRange.getMinAddress(), addressRange.getMaxAddress(), true);
			int i = 0;
			byte[] key = "forgivemefather".getBytes(); 
			for(Address a : addressRange) {
				try {
					byte currByte = getByte(a);
					byte res = unpack_byte(currByte, key[i % 15]);
					
					setByte(a, res);
					
					i = i + 1;
					i = i % 0x1000;
					
				} catch (Exception MemoryAccessException) {
					i = i + 1;
					i = i % 0x1000;
					continue;
				}
			}	
		}	
    }
}
