import subprocess

solverHeader = """
from z3 import *

key = [BitVec(f'key_{i}', 8) for i in range(32)]
constraints = [And(key[i] > 0x20, key[i] <= 0x7E) for i in range(32)]
"""

solverTail = """
solver = Solver()
solver.add(constraints)
solution_count = 0
while solver.check() == sat:
    solution_count += 1
    model = solver.model()
    solution = ''.join(chr(model[key[i]].as_long()) for i in range(32))
    print(f"Solution {solution_count}: {solution}")
    
    solver.add(Or([key[i] != model[key[i]] for i in range(32)]))

if solution_count == 0:
    print("No solution found.")
else:
    print(f"Total solutions found: {solution_count}")
"""

myInputKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
base = 0x140000000

def winDbgStringToNumber(winDbgString):
    temp = winDbgString.replace("`", "")
    return int(temp, 16)

def getEvaluatedOperandsOp(instructionLine):

    # mul line example:
    # mul rax,qword ptr [rsp] ; 00000000`00000045, 00000000`067fd780 => 00000000`00ef7a8c
    evaluatedOperands = instructionLine.split(" ; ")[1]
    firstOperand = winDbgStringToNumber(evaluatedOperands.split(", ")[0])
    secondOperand = winDbgStringToNumber(evaluatedOperands.split("=> ")[1])

    return firstOperand, secondOperand

def indexOfNextBlock(lines, startIndex):
    i = startIndex
    while(not lines[i].startswith("##### end")):
        i += 1
    return i + 2

def indexOfCurrentBlock(lines, startIndex):
    i = startIndex
    while(not lines[i].startswith("##### Deobfuscating")):
        i -= 1
    return i

def indexOfPreviousBlock(lines, startIndex):
    i = startIndex
    i = indexOfCurrentBlock(lines, i)
    i -= 1
    while(not lines[i].startswith("##### Deobfuscating")):
        i -= 1
    return i

def isInstructionInCurrentBlock(lines, startIndex, instruction):
    i = startIndex
    i = indexOfCurrentBlock(lines, i)
    while(not lines[i].startswith("##### end")):
        if lines[i].startswith(instruction):
            return True
        i += 1
    return False

def indexOfNextInstructionBlock(lines, startIndex, instruction):
    i = startIndex
    while(not isInstructionInCurrentBlock(lines, i, instruction)):
        i = indexOfNextBlock(lines, i)
    return i  

def isCurrentBlockEnd(lines, startIndex):
    i = startIndex
    while(not lines[i].startswith("##### end")):
        if lines[i].startswith("#end of trace"):
            return True
        i += 1
    return False

def parseSub(lines, startIndex):
    i = startIndex

    isPositionsAlreadyDone = [False] * 8
    operand = [-1] * 8

    i = indexOfNextBlock(lines, i)
    i = indexOfNextBlock(lines, i)

    runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
    staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
    byte = binaryData[staticLookUpTableAddres]

    if byte == 0x00:
        operand[7] = "00"
    else:
        operand[7] = hex(0x100 - byte)[2:].zfill(2)

    while not isInstructionInCurrentBlock(lines, i, "mul"):
        i = indexOfNextBlock(lines, i)

        if isCurrentBlockEnd(lines, i):
            break

        if isInstructionInCurrentBlock(lines, i , "ldmxcsr"):
            
            # if we are at the last term of the operation, there is 
            # no multiplication after, but there is a sub operation.
            # to handle this case we have to check if there is 
            # a shl,8 operation at a ceratin offset in this block
            # this mean that the current sub has ended and 
            # and a new one is starting

            # example line:
            # shl rcx,8 ; 00000000`00000000, 00000000`00000008
            if lines[i + 9].startswith("shl") and lines[i + 9].split(",")[1].startswith("8"):
                break

            i = indexOfNextBlock(lines, i)
            i = indexOfNextBlock(lines, i)

            runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
            staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
            byte = binaryData[staticLookUpTableAddres]

            # example: 
            # shl rcx,10h ; 00000000`00000038, 00000000`00000010

            if lines[i + 11].startswith("shl"):
                position = 7 - int(lines[i + 11].split(",")[1].split(" ")[0].replace("h", ""), 16) // 8

                if not isPositionsAlreadyDone[position]:
                    if byte == 0x00:
                        operand[position] = "00"
                    else:
                        operand[position] = hex(0x100 - byte)[2:].zfill(2)

                    isPositionsAlreadyDone[position] = True

    for j in range(8):
        if operand[j] == -1:
            operand[j] = "00"
    
    return ("".join(operand), i)

def parseAdd(lines, startIndex):
    i = startIndex 

    isPositionsAlreadyDone = [False] * 8
    operand = [-1] * 8

    i = indexOfNextBlock(lines, i)
    i = indexOfNextBlock(lines, i)

    runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
    staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
    byte = binaryData[staticLookUpTableAddres]

    if byte == 0x00:
        operand[7] = "00"
    else:
        operand[7] = hex(byte)[2:].zfill(2)

    while not isInstructionInCurrentBlock(lines, i, "mul"):
        i = indexOfNextBlock(lines, i)

        if isInstructionInCurrentBlock(lines, i , "ldmxcsr"):

            # if we are at the last term of the operation, there is 
            # no multiplication after, but there is a sub operation.
            # to handle this case we have to check if there is 
            # a sub operation at a ceratin offset in this block
            if lines[i + 10].startswith("sub"):
                break

            i = indexOfNextBlock(lines, i)
            i = indexOfNextBlock(lines, i)

            runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
            staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
            byte = binaryData[staticLookUpTableAddres]


            # example: 
            # shl rcx,10h ; 00000000`00000038, 00000000`00000010
            position = 7 - int(lines[i + 11].split(",")[1].split(" ")[0].replace("h", ""), 16) // 8

            if not isPositionsAlreadyDone[position]:
                if byte == 0x00:
                    operand[position] = "00"
                else:
                    operand[position] = hex(byte)[2:].zfill(2)

                isPositionsAlreadyDone[position] = True


    for j in range(8):
        if operand[j] == -1:
            operand[j] = "00"
    
    return ("".join(operand), i)
   
def parseXor(lines, startIndex):
    i = startIndex

    isPositionsAlreadyDone = [False] * 8
    operand = [-1] * 8

    i = indexOfNextBlock(lines, i)
    i = indexOfNextBlock(lines, i)

    runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
    staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
    byte = binaryData[staticLookUpTableAddres]

    if byte == 0x00:
        operand[7] = "00"
    else:
        operand[7] = hex(byte)[2:].zfill(2)

    while not isInstructionInCurrentBlock(lines, i, "mul"):
        i = indexOfNextBlock(lines, i)

        if isInstructionInCurrentBlock(lines, i , "ldmxcsr"):

            # if we are at the last term of the operation, there is 
            # no multiplication after, but there is a sub operation.
            # to handle this case we have to check if there is 
            # a sub operation at a ceratin offset in this block

            if lines[i + 10].startswith("sub"):
                break
  
            i = indexOfNextBlock(lines, i)
            i = indexOfNextBlock(lines, i)

            runLookUpTableAddress = winDbgStringToNumber(lines[i + 4].split("=> ")[1])
            staticLookUpTableAddres = runLookUpTableAddress - base - 0x1c00
            byte = binaryData[staticLookUpTableAddres]

            # example: 
            # shl rcx,10h ; 00000000`00000038, 00000000`00000010
            position = 7 - int(lines[i + 11].split(",")[1].split(" ")[0].replace("h", ""), 16) // 8
            if not isPositionsAlreadyDone[position]:
                if byte == 0x00:
                    operand[position] = "00"
                else:
                    operand[position] = hex(byte)[2:].zfill(2)

                isPositionsAlreadyDone[position] = True

    for j in range(8):
        if operand[j] == -1:
            operand[j] = "00"
    
    return ("".join(operand), i)

def parseOperand(lines, i):
    i = indexOfNextInstructionBlock(lines, i, "ldmxcsr")

    if lines[i + 4].startswith("add"):
        if lines[i + 10].startswith("sub"):
            operand, i =  parseSub(lines, i)
            str = f"temp -= 0x{operand.upper()}\n"
        else: 
            operand, i =  parseAdd(lines, i)
            str = f"temp += 0x{operand.upper()}\n"
    else:
        operand, i =  parseXor(lines, i)
        str = f"temp ^= 0x{operand.upper()}\n"

    return str, i

def parseMul(lines, i, first):            
    i = indexOfNextInstructionBlock(lines, i, "mul")

    if first:
        firstOperand, secondOperand = getEvaluatedOperandsOp(lines[i + 6])
        str = f"temp = key[{myInputKey.index(chr(firstOperand))}] * 0x{hex(secondOperand)[2:].upper().zfill(8)}\n"

    else:
        firstOperand, secondOperand = getEvaluatedOperandsOp(lines[i + 7])
        i = indexOfNextBlock(lines, i)

        if lines[i + 3].startswith("xor"):
            operation = "^="
        elif lines[i + 3].startswith("add"):
            operation = "+="
        elif lines[i + 3].startswith("sub"):
            operation = "-="

        str = f"temp {operation} key[{myInputKey.index(chr(firstOperand))}] * 0x{hex(secondOperand)[2:].upper().zfill(8)}\n"

    return (str, i)
        
def parseEquations(lines):
    equations = []
    i = 0

    for x in range(32):
        equation = ""

        str, i = parseMul(lines, i, True)
        equation += str

        str, i = parseOperand(lines, i)
        equation += str

        for _ in range(7):
            str, i = parseMul(lines, i, False)
            equation += str
            
            str, i = parseOperand(lines, i)
            equation += str
            
        operand, i =  parseSub(lines, i)
        equation += f"temp -= 0x{operand.upper()}\n"

        equation = f"# equation {x}\n" + equation + "constraints.append(temp == 0)\n"
        equations.append(equation)

    return equations

binaryFile = open("serpentine.exe", "rb")
binaryData = binaryFile.read()

log_lines = open("logtst.txt", "r").readlines()
equations = parseEquations(log_lines)

output_file = open("solver.py", "w")
output_file.write(solverHeader + "\n".join(equations) + solverTail)
output_file.close()

subprocess.run(["python", "solver.py"])

