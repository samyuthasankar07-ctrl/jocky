"""
jocky/vm.py - JOCKY bytecode virtual machine
Entirely in-memory execution of .jcx bytecode and encrypted .jxp files.
"""

import struct
from typing import List, Optional, Any, Dict
from io import BytesIO


class Opcode:
    LOAD_CONST       = 0x01
    LOAD_VAR         = 0x02
    STORE_VAR        = 0x03
    CALL_BUILTIN     = 0x04
    CALL_FUNC        = 0x05
    JUMP             = 0x06
    JUMP_IF_FALSE    = 0x07
    RETURN           = 0x08
    BUILD_LIST       = 0x09
    ITER_NEXT        = 0x0A
    NOP              = 0x0B
    BINARY_OP        = 0x0C
    UNARY_OP         = 0x0D
    INDEX_ACCESS     = 0x0E


class VMError(Exception):
    """VM execution error."""
    pass


class JockyVM:
    def __init__(self, bytecode: bytes, builtins: Optional[Dict[str, callable]] = None):
        """
        Initialize VM with bytecode (bytes).
        bytecode: raw .jcx bytecode (not file path)
        builtins: dict of builtin function names to callables
        """
        self.bytecode = bytecode
        self.pc = 0  # program counter
        self.stack: List[Any] = []
        self.variables: Dict[int, Any] = {}
        self.constants: List[Any] = []
        self.builtins = builtins or {}
        self.return_value: Optional[Any] = None
        self.iterators: Dict[int, Any] = {}
        
        self._parse_bytecode()
    
    def _parse_bytecode(self):
        """Parse the bytecode header and constant pool."""
        stream = BytesIO(self.bytecode)
        
        # Check magic
        magic = stream.read(4)
        if magic != b"JCX\x01":
            raise VMError(f"Invalid bytecode magic: {magic}")
        
        # Read constant pool size
        const_count_bytes = stream.read(2)
        const_count = struct.unpack("<H", const_count_bytes)[0]
        
        # Parse constants
        for _ in range(const_count):
            type_byte = stream.read(1)
            if not type_byte:
                raise VMError("Unexpected EOF while reading constants")
            
            if type_byte == b"I":
                # Integer
                value_bytes = stream.read(8)
                value = struct.unpack("<q", value_bytes)[0]
                self.constants.append(value)
            elif type_byte == b"S":
                # String
                len_bytes = stream.read(4)
                str_len = struct.unpack("<I", len_bytes)[0]
                value = stream.read(str_len).decode("utf-8")
                self.constants.append(value)
            elif type_byte == b"B":
                # Boolean
                value_byte = stream.read(1)
                self.constants.append(value_byte == b"\x01")
            elif type_byte == b"N":
                # Null
                self.constants.append(None)
            else:
                raise VMError(f"Unknown constant type: {type_byte}")
        
        # Read bytecode
        bytecode_len_bytes = stream.read(4)
        bytecode_len = struct.unpack("<I", bytecode_len_bytes)[0]
        self.code = stream.read(bytecode_len)
    
    def push(self, value: Any):
        """Push a value onto the stack."""
        self.stack.append(value)
    
    def pop(self) -> Any:
        """Pop a value from the stack."""
        if not self.stack:
            raise VMError("Stack underflow")
        return self.stack.pop()
    
    def peek(self) -> Any:
        """Peek at the top of the stack without popping."""
        if not self.stack:
            raise VMError("Stack underflow")
        return self.stack[-1]
    
    def _read_u32(self) -> int:
        """Read a 32-bit unsigned integer from bytecode."""
        if self.pc + 4 > len(self.code):
            raise VMError("Unexpected EOF reading u32")
        value = struct.unpack("<I", bytes(self.code[self.pc:self.pc+4]))[0]
        self.pc += 4
        return value
    
    def _is_truthy(self, value: Any) -> bool:
        """Determine if a value is truthy."""
        if value is None or value is False:
            return False
        if value == 0 or value == "" or (isinstance(value, list) and len(value) == 0):
            return False
        return True
    
    def execute(self) -> Any:
        """Execute the bytecode and return the final stack value."""
        self.pc = 0
        
        while self.pc < len(self.code):
            opcode = self.code[self.pc]
            self.pc += 1
            
            if opcode == Opcode.NOP:
                # No operation
                pass
            
            elif opcode == Opcode.LOAD_CONST:
                idx = self._read_u32()
                if idx >= len(self.constants):
                    raise VMError(f"Constant index out of range: {idx}")
                self.push(self.constants[idx])
            
            elif opcode == Opcode.LOAD_VAR:
                var_idx = self._read_u32()
                value = self.variables.get(var_idx, None)
                self.push(value)
            
            elif opcode == Opcode.STORE_VAR:
                var_idx = self._read_u32()
                value = self.pop()
                self.variables[var_idx] = value
            
            elif opcode == Opcode.CALL_BUILTIN:
                name_idx = self._read_u32()
                arg_count = self._read_u32()
                
                if name_idx >= len(self.constants):
                    raise VMError(f"Builtin name index out of range: {name_idx}")
                
                name = self.constants[name_idx]
                if not isinstance(name, str):
                    raise VMError(f"Builtin name must be string, got {type(name)}")
                
                args = [self.pop() for _ in range(arg_count)]
                args.reverse()
                
                if name not in self.builtins:
                    raise VMError(f"Unknown builtin: {name}")
                
                try:
                    result = self.builtins[name](*args)
                    self.push(result)
                except Exception as e:
                    raise VMError(f"Error calling builtin {name}: {e}")
            
            elif opcode == Opcode.CALL_FUNC:
                # Not implemented in this version
                raise VMError("Function calls not yet implemented")
            
            elif opcode == Opcode.JUMP:
                target = self._read_u32()
                self.pc = target
            
            elif opcode == Opcode.JUMP_IF_FALSE:
                target = self._read_u32()
                value = self.pop()
                if not self._is_truthy(value):
                    self.pc = target
            
            elif opcode == Opcode.RETURN:
                if self.stack:
                    self.return_value = self.pop()
                return self.return_value
            
            elif opcode == Opcode.BUILD_LIST:
                count = self._read_u32()
                elements = [self.pop() for _ in range(count)]
                elements.reverse()
                self.push(elements)
            
            elif opcode == Opcode.ITER_NEXT:
                # Get iterator from stack
                iterable = self.pop()
                if isinstance(iterable, list):
                    # For simplicity, convert list to iterator
                    # In a real implementation, would track iterator state
                    if not hasattr(self, "_iter_idx"):
                        self._iter_idx = 0
                        self._iter_list = iterable
                    
                    if self._iter_idx < len(self._iter_list):
                        value = self._iter_list[self._iter_idx]
                        self._iter_idx += 1
                        self.push(value)
                        self.push(True)  # has next
                    else:
                        self.push(False)  # no more items
                        del self._iter_idx
                        del self._iter_list
                else:
                    raise VMError(f"Cannot iterate over {type(iterable)}")
            
            elif opcode == Opcode.BINARY_OP:
                op_idx = self._read_u32()
                if op_idx >= len(self.constants):
                    raise VMError(f"Operator index out of range: {op_idx}")
                
                op = self.constants[op_idx]
                right = self.pop()
                left = self.pop()
                
                try:
                    if op == "+":
                        result = left + right
                    elif op == "-":
                        result = left - right
                    elif op == "*":
                        result = left * right
                    elif op == "/":
                        result = left / right if isinstance(left, float) or isinstance(right, float) else left // right
                    elif op == "%":
                        result = left % right
                    elif op == "==":
                        result = left == right
                    elif op == "!=":
                        result = left != right
                    elif op == "<":
                        result = left < right
                    elif op == "<=":
                        result = left <= right
                    elif op == ">":
                        result = left > right
                    elif op == ">=":
                        result = left >= right
                    elif op == "and":
                        result = left and right
                    elif op == "or":
                        result = left or right
                    else:
                        raise VMError(f"Unknown binary operator: {op}")
                    
                    self.push(result)
                except Exception as e:
                    raise VMError(f"Error in binary op {op}: {e}")
            
            elif opcode == Opcode.UNARY_OP:
                op_idx = self._read_u32()
                if op_idx >= len(self.constants):
                    raise VMError(f"Operator index out of range: {op_idx}")
                
                op = self.constants[op_idx]
                operand = self.pop()
                
                if op == "-":
                    result = -operand
                elif op == "+":
                    result = +operand
                elif op == "not":
                    result = not self._is_truthy(operand)
                else:
                    raise VMError(f"Unknown unary operator: {op}")
                
                self.push(result)
            
            elif opcode == Opcode.INDEX_ACCESS:
                index = self.pop()
                obj = self.pop()
                try:
                    result = obj[index]
                    self.push(result)
                except Exception as e:
                    raise VMError(f"Index access error: {e}")
            
            else:
                raise VMError(f"Unknown opcode: {opcode:#x} at PC {self.pc - 1}")
        
        # If no explicit return, return top of stack or None
        if self.stack:
            return self.pop()
        return self.return_value


def execute_bytecode(bytecode: bytes, builtins: Optional[Dict[str, callable]] = None) -> Any:
    """Execute bytecode and return result."""
    vm = JockyVM(bytecode, builtins)
    return vm.execute()


def execute_encrypted(encrypted: bytes, agent_token: str, builtins: Optional[Dict[str, callable]] = None) -> Any:
    """Decrypt and execute .jxp bytecode."""
    from jocky.compiler import decrypt_jxp
    bytecode = decrypt_jxp(encrypted, agent_token)
    return execute_bytecode(bytecode, builtins)
