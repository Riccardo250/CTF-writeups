let fileWriter = null;
let counter = 0;
const log = x => host.diagnostics.debugLog(x);
let disassembler = null;
let shellcode_base = 0;

function writeToFile(fileWriter, str)
{
    fileWriter.WriteLine(str);
}

const logFile = x => writeToFile(fileWriter, x);

function myExecuteCommand(command) {
    // Execute the command in WinDbg and get the result
    let result = host.namespace.Debugger.Utility.Control.ExecuteCommand(command);
    
    // Convert the result to an array of lines
    let resultArray = Array.from(result);

    // The specific error message to check for
    const errorMessage = "Unable to read dynamic function table entry at";

    // Iterate through the result array to find the first element that doesn't contain the error message
    for (let line of resultArray) {
        //log(`line: ${line}\n`);
        if (!line.includes(errorMessage)) {
            //log(`returning line: ${line}\n`);
            // Return the first line that does not contain the error message
            return line;
        }
    }

    // If all lines contain the error message or the array is empty, return null
    return null;
}

function evaluateOperand(operand, isMemoryAccess, memoryLength) {
    const control = host.namespace.Debugger.Utility.Control;
    let to_ret = "";

    //log(`operand: ${operand}, isMemoryAccess: ${isMemoryAccess}, memoryLength: ${memoryLength}\n`);

    if (isMemoryAccess) 
    {
        let real_operand = operand.replace(/\b[a-z]+\s+ptr\s+\[/, "").replace(/\]/, "");
        let instructionData = "";
        switch (memoryLength) 
        {
            case 1: instructionData = myExecuteCommand(`db ${real_operand} L1`); break;
            case 2: instructionData = myExecuteCommand(`dw ${real_operand} L1`); break;
            case 4: instructionData = myExecuteCommand(`dd ${real_operand} L1`); break;
            case 8: instructionData = myExecuteCommand(`dq ${real_operand} L1`); break;
            default: instructionData = "unknown"; break;
        }

        let pointer = myExecuteCommand(`? ${real_operand}`);
        pointer = pointer.split(/\s+/).slice(4).join(" ");
        let content = instructionData.split(/\s+/).slice(1).join(" ");
        to_ret = `${pointer} => ${content}`;  
        //log(`instructionData: ${instructionData}, to_ret: ${to_ret}\n`);
    } else {
        let instructionData = myExecuteCommand(`? ${operand}`);
        to_ret = instructionData.split(/\s+/).slice(4).join(" ");
        //log(`instructionData: ${instructionData}, to_ret: ${to_ret}\n`);
    }

    return to_ret;
}

function getMemoryAccessInfo(operand) 
{
    const memoryAccessPattern = /\b([a-z]+)\s+ptr\s+\[([^\]]+)\]/i;
    const memoryMatch = operand.match(memoryAccessPattern);
    if (memoryMatch) 
    {
        const accessType = memoryMatch[1].toLowerCase();
        let length;
        switch (accessType) 
        {
            case 'byte': length = 1; break;
            case 'word': length = 2; break;
            case 'dword': length = 4; break;
            case 'qword': length = 8; break;
            default: length = null; // Unknown access type
        }
        return { isMemoryAccess: true, length: length };
    }
    return { isMemoryAccess: false, length: null };
}

function evaluateInstructionOperands(instruction) {
    // Regular expression to match the instruction pattern: opcode [operands...]
    const instructionPattern = /^[a-z]+\s+(.*)$/i;
    const match = instruction.match(instructionPattern);

    if (!match) 
    {
        // If the instruction doesn't match the expected format, return null
        return null;
    }

    // Split the operands (separated by commas)
    const operands = match[1].split(',').map(op => op.trim());

    // Evaluate each operand using the evaluateOperand function
    const evaluatedOperands = operands.map(operand => {
        const memoryInfo = getMemoryAccessInfo(operand);
        return evaluateOperand(operand, memoryInfo.isMemoryAccess, memoryInfo.length);
    });

    return evaluatedOperands;
}

function deobfuscateExceptionHandler()
{
    const control = host.namespace.Debugger.Utility.Control;
    let nInstructions = 0;

    logFile(`##### Deobfuscating exception #${counter} #####`);
    control.ExecuteCommand("t");

    //log(`first instruction bytes: ${disassembler.DisassembleInstructions(host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rip).First().CodeBytes[0].toString(16)}\n`);

   
    while(true)
    {
        let curr_instruction = disassembler.DisassembleInstructions(host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rip).First();
        let curr_instruction_info = "";
        let offset = 0;
        let in_call = false;
        let parts = null;
        let result = null;
        let to_print = null;
        let evaluatedOperands =null;

        //test instruction
        let temp = myExecuteCommand("u rip L1");
        if(temp.includes("test")){
            log("test instruction, end of equation\n");
            return false;
        }

        if(curr_instruction.Attributes.IsCall)
        {
            in_call = true;
            control.ExecuteCommand("t 8");
            offset = host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rip - shellcode_base;
            curr_instruction_info = control.ExecuteCommand("u rip L1")[0];
            
            parts = curr_instruction_info.split(/\s+/);
            result = parts.slice(2).join(" ");
            to_print = result;
            evaluatedOperands = evaluateInstructionOperands(result);
    
            control.ExecuteCommand("t");
            if(disassembler.DisassembleInstructions(host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rip).First().CodeBytes[0] == 0xf4)
            {
                break;
            }
            control.ExecuteCommand("t 5");

        } else {
            offset = host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rip - shellcode_base;
            curr_instruction_info = control.ExecuteCommand("u rip L1")[0];

            parts = curr_instruction_info.split(/\s+/);
            result = parts.slice(2).join(" ");
            to_print = result;
            evaluatedOperands = evaluateInstructionOperands(result);
        }


        if (evaluatedOperands) 
        {
            to_print = result + ' ; ' + evaluatedOperands.join(', ');
        }

        logFile(`${to_print}`);

        control.ExecuteCommand("t");
        nInstructions++;
    }

    logFile(`##### end of deobfuscating exception #${counter} #####\n`);
    counter++;
    return true;
}

function deobfuscateAllExceptions()
{
    const control = host.namespace.Debugger.Utility.Control;


    for (let i = 0; i < 32; i++)
    {
        counter = 0;
        log(`equation #${i}\n`);
        logFile(`equation #${i}\n`);

        control.ExecuteCommand("g");
        while(deobfuscateExceptionHandler())
        {
            control.ExecuteCommand("g");
        }

        let test_instruction = myExecuteCommand("u rip L1");
        let test_register = test_instruction.split(/\s+/)[3].split(",")[0];
        control.ExecuteCommand(`r ${test_register} = 0`);
    }
}

function initializeScript()
{
    host.diagnostics.debugLog("Invoking script \n");
}


function invokeScript()
{
    const control = host.namespace.Debugger.Utility.Control;
    let file = host.namespace.Debugger.Utility.FileSystem.OpenFile("C:\\Users\\Ric\\Desktop\\FlareOn11\\9-serpentine\\my_solution\\logtst.txt");
    fileWriter =  host.namespace.Debugger.Utility.FileSystem.CreateTextWriter(file);
    disassembler = host.namespace.Debugger.Utility.Code.CreateDisassembler("X64");

    control.ExecuteCommand("g serpentine+1522");
    shellcode_base = host.namespace.Debugger.State.DebuggerVariables.curregisters.User.rax;
    control.ExecuteCommand("bp ntdll!RtlpExecuteHandlerForException+0xd");

    deobfuscateAllExceptions();
    logFile("#end of trace");
    file.Close()
}


