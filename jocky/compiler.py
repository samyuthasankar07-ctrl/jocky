"""
jocky/compiler.py - JOCKY compiler
Compiles AST to .jcx bytecode with NOP sled obfuscation and random constant-pool shuffling.
Supports encrypted .jxp output via AES-256-GCM with HKDF key derivation.
"""

import struct
import random
import os
from typing import Dict, List, Tuple, Optional
from io import BytesIO
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jocky.parser import (
    Program, ASTNode, IntLiteral, StrLiteral, BoolLiteral, ListLiteral,
    Identifier, BinOp, UnaryOp, Assign, FuncCall, MethodCall, IfStmt,
    ForStmt, ReturnStmt, FuncDef, IndexAccess
)


# ────────────────────────────────────────────────────────────────────────────
# Opcode definitions
# ────────────────────────────────────────────────────────────────────────────

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


class Compiler:
    def __init__(self, agent_token: Optional[str] = None):
        """Initialize compiler with optional agent token for .jxp encryption."""
        self.agent_token = agent_token
        self.constants: List = []
        self.const_map: Dict = {}
        self.bytecode: List[int] = []
        self.labels: Dict[str, int] = {}
        self.pending_jumps: List[Tuple[int, str]] = []
        self.variables: Dict[str, int] = {}
        self.var_counter = 0
    
    def add_const(self, value) -> int:
        """Add a constant to the pool and return its index."""
        key = (type(value), value)
        if key not in self.const_map:
            idx = len(self.constants)
            self.constants.append(value)
            self.const_map[key] = idx
            return idx
        return self.const_map[key]
    
    def get_var_index(self, name: str) -> int:
        """Get or create a variable index."""
        if name not in self.variables:
            self.variables[name] = self.var_counter
            self.var_counter += 1
        return self.variables[name]
    
    def emit(self, opcode: int, *args):
        """Emit an opcode and arguments."""
        self.bytecode.append(opcode)
        for arg in args:
            if isinstance(arg, int):
                self.bytecode.extend(struct.pack("<I", arg))
            else:
                raise ValueError(f"Expected int, got {type(arg)}")
    
    def emit_u16(self, value: int):
        """Emit a 16-bit unsigned integer."""
        self.bytecode.extend(struct.pack("<H", value))
    
    def create_label(self, name: str) -> str:
        """Create a label for jumps."""
        label = f"_label_{name}_{random.randint(0, 999999)}"
        return label
    
    def mark_label(self, label: str):
        """Mark the current position as a label."""
        self.labels[label] = len(self.bytecode)
    
    def emit_jump(self, label: str):
        """Emit a jump to a label (backpatch later)."""
        self.pending_jumps.append((len(self.bytecode), label))
        self.bytecode.append(0)  # placeholder
        self.bytecode.extend([0, 0, 0, 0])  # 4-byte offset placeholder
    
    def backpatch_jumps(self):
        """Resolve pending jumps."""
        for jump_pos, label in self.pending_jumps:
            if label not in self.labels:
                raise RuntimeError(f"Undefined label: {label}")
            target = self.labels[label]
            # Store the absolute target offset
            offset_bytes = struct.pack("<I", target)
            for i, b in enumerate(offset_bytes):
                self.bytecode[jump_pos + 1 + i] = b
    
    def emit_nop_sled(self, min_nops: int = 1, max_nops: int = 5):
        """Emit random NOPs for obfuscation."""
        count = random.randint(min_nops, max_nops)
        for _ in range(count):
            self.emit(Opcode.NOP)
    
    def compile(self, ast: Program) -> bytes:
        """Compile the AST to bytecode."""
        # Compile all statements
        for stmt in ast.statements:
            self.compile_stmt(stmt)
        
        # Backpatch jumps
        self.backpatch_jumps()
        
        # Shuffle constant pool for obfuscation
        shuffled_consts = list(range(len(self.constants)))
        random.shuffle(shuffled_consts)
        const_remap = {old: new for new, old in enumerate(shuffled_consts)}
        
        # Remap all LOAD_CONST instructions
        remapped_bytecode = []
        i = 0
        while i < len(self.bytecode):
            if self.bytecode[i] == Opcode.LOAD_CONST:
                remapped_bytecode.append(self.bytecode[i])
                old_idx = struct.unpack("<I", bytes(self.bytecode[i+1:i+5]))[0]
                new_idx = const_remap[old_idx]
                remapped_bytecode.extend(struct.pack("<I", new_idx))
                i += 5
            elif self.bytecode[i] == Opcode.NOP:
                remapped_bytecode.append(self.bytecode[i])
                i += 1
            elif self.bytecode[i] in (Opcode.JUMP, Opcode.JUMP_IF_FALSE):
                remapped_bytecode.append(self.bytecode[i])
                remapped_bytecode.extend(self.bytecode[i+1:i+5])
                i += 5
            elif self.bytecode[i] in (
                Opcode.LOAD_VAR, Opcode.STORE_VAR, Opcode.CALL_BUILTIN,
                Opcode.CALL_FUNC, Opcode.BUILD_LIST, Opcode.ITER_NEXT
            ):
                remapped_bytecode.append(self.bytecode[i])
                remapped_bytecode.extend(self.bytecode[i+1:i+5])
                i += 5
            elif self.bytecode[i] in (Opcode.BINARY_OP, Opcode.UNARY_OP):
                remapped_bytecode.append(self.bytecode[i])
                remapped_bytecode.extend(self.bytecode[i+1:i+5])
                i += 5
            elif self.bytecode[i] == Opcode.RETURN:
                remapped_bytecode.append(self.bytecode[i])
                i += 1
            elif self.bytecode[i] == Opcode.INDEX_ACCESS:
                remapped_bytecode.append(self.bytecode[i])
                i += 1
            else:
                remapped_bytecode.append(self.bytecode[i])
                i += 1
        
        # Reorder constants
        reordered_consts = [self.constants[i] for i in shuffled_consts]
        
        # Build the final bytecode with magic header
        output = BytesIO()
        output.write(b"JCX\x01")  # Magic number + version
        output.write(struct.pack("<H", len(reordered_consts)))  # Const pool size
        
        # Serialize constants
        for const in reordered_consts:
            if isinstance(const, int):
                output.write(b"I")  # type byte
                output.write(struct.pack("<q", const))
            elif isinstance(const, str):
                output.write(b"S")  # type byte
                encoded = const.encode("utf-8")
                output.write(struct.pack("<I", len(encoded)))
                output.write(encoded)
            elif isinstance(const, bool):
                output.write(b"B")  # type byte
                output.write(b"\x01" if const else b"\x00")
            else:
                output.write(b"N")  # null
        
        # Serialize bytecode
        output.write(struct.pack("<I", len(remapped_bytecode)))
        for byte in remapped_bytecode:
            output.write(bytes([byte]))
        
        return output.getvalue()
    
    def compile_stmt(self, stmt: ASTNode):
        """Compile a statement."""
        if isinstance(stmt, Program):
            for s in stmt.statements:
                self.compile_stmt(s)
        elif isinstance(stmt, Assign):
            self.compile_expr(stmt.value)
            idx = self.get_var_index(stmt.target)
            self.emit(Opcode.STORE_VAR, idx)
            self.emit_nop_sled()
        elif isinstance(stmt, IfStmt):
            self.compile_if_stmt(stmt)
        elif isinstance(stmt, ForStmt):
            self.compile_for_stmt(stmt)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value:
                self.compile_expr(stmt.value)
            self.emit(Opcode.RETURN)
            self.emit_nop_sled()
        elif isinstance(stmt, FuncDef):
            # For now, skip function definitions
            pass
        else:
            self.compile_expr(stmt)
    
    def compile_expr(self, expr: ASTNode):
        """Compile an expression."""
        if isinstance(expr, IntLiteral):
            idx = self.add_const(expr.value)
            self.emit(Opcode.LOAD_CONST, idx)
        elif isinstance(expr, StrLiteral):
            idx = self.add_const(expr.value)
            self.emit(Opcode.LOAD_CONST, idx)
        elif isinstance(expr, BoolLiteral):
            idx = self.add_const(expr.value)
            self.emit(Opcode.LOAD_CONST, idx)
        elif isinstance(expr, ListLiteral):
            for elem in expr.elements:
                self.compile_expr(elem)
            self.emit(Opcode.BUILD_LIST, len(expr.elements))
        elif isinstance(expr, Identifier):
            idx = self.get_var_index(expr.name)
            self.emit(Opcode.LOAD_VAR, idx)
        elif isinstance(expr, BinOp):
            self.compile_expr(expr.left)
            self.compile_expr(expr.right)
            op_idx = self.add_const(expr.op)
            self.emit(Opcode.BINARY_OP, op_idx)
        elif isinstance(expr, UnaryOp):
            self.compile_expr(expr.operand)
            op_idx = self.add_const(expr.op)
            self.emit(Opcode.UNARY_OP, op_idx)
        elif isinstance(expr, FuncCall):
            for arg in expr.args:
                self.compile_expr(arg)
            name_idx = self.add_const(expr.name)
            self.emit(Opcode.CALL_BUILTIN, name_idx, len(expr.args))
        elif isinstance(expr, MethodCall):
            self.compile_expr(expr.obj)
            for arg in expr.args:
                self.compile_expr(arg)
            method_idx = self.add_const(expr.method)
            self.emit(Opcode.CALL_BUILTIN, method_idx, len(expr.args))
        elif isinstance(expr, IndexAccess):
            self.compile_expr(expr.obj)
            self.compile_expr(expr.index)
            self.emit(Opcode.INDEX_ACCESS)
    
    def compile_if_stmt(self, stmt: IfStmt):
        """Compile an if statement."""
        self.compile_expr(stmt.condition)
        else_label = self.create_label("else")
        self.emit(Opcode.JUMP_IF_FALSE)
        # Need to emit placeholder for jump offset
        jump_pos = len(self.bytecode) - 1
        self.pending_jumps.append((jump_pos, else_label))
        
        for s in stmt.then_body:
            self.compile_stmt(s)
        
        if stmt.else_body:
            end_label = self.create_label("endif")
            self.emit(Opcode.JUMP)
            jump_pos = len(self.bytecode) - 1
            self.pending_jumps.append((jump_pos, end_label))
            
            self.mark_label(else_label)
            for s in stmt.else_body:
                self.compile_stmt(s)
            
            self.mark_label(end_label)
        else:
            self.mark_label(else_label)
    
    def compile_for_stmt(self, stmt: ForStmt):
        """Compile a for loop."""
        self.compile_expr(stmt.iterable)
        loop_start = self.create_label("loop_start")
        loop_end = self.create_label("loop_end")
        
        self.mark_label(loop_start)
        var_idx = self.get_var_index(stmt.var)
        self.emit(Opcode.ITER_NEXT)
        self.emit(Opcode.JUMP_IF_FALSE)
        self.pending_jumps.append((len(self.bytecode) - 1, loop_end))
        
        for s in stmt.body:
            self.compile_stmt(s)
        
        self.emit(Opcode.JUMP)
        self.pending_jumps.append((len(self.bytecode) - 1, loop_start))
        
        self.mark_label(loop_end)


def compile_jck(source: str, agent_token: Optional[str] = None) -> bytes:
    """Compile JOCKY source code to .jcx bytecode."""
    from jocky.parser import parse
    ast = parse(source)
    compiler = Compiler(agent_token)
    return compiler.compile(ast)


def encrypt_jxp(bytecode: bytes, agent_token: str) -> bytes:
    """Encrypt .jcx bytecode to .jxp using AES-256-GCM."""
    # Derive 32-byte key from agent token using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"jocky_jxp",
        info=b"encryption",
    )
    key = hkdf.derive(agent_token.encode())
    
    # Generate random 12-byte nonce
    nonce = os.urandom(12)
    
    # Encrypt with AES-256-GCM
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, bytecode, None)
    
    # Return magic + nonce + ciphertext
    return b"JXP\x01" + nonce + ciphertext


def decrypt_jxp(encrypted: bytes, agent_token: str) -> bytes:
    """Decrypt .jxp bytecode."""
    if encrypted[:4] != b"JXP\x01":
        raise ValueError("Invalid .jxp file")
    
    nonce = encrypted[4:16]
    ciphertext = encrypted[16:]
    
    # Derive key from agent token
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"jocky_jxp",
        info=b"encryption",
    )
    key = hkdf.derive(agent_token.encode())
    
    # Decrypt
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)
