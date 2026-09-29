"""
jocky - JOCKY scripting language and VM for forensic automation
"""

from jocky.lexer import Lexer, Token, TokenType
from jocky.parser import parse, Program
from jocky.compiler import compile_jck, encrypt_jxp, decrypt_jxp, Compiler
from jocky.vm import JockyVM, execute_bytecode, execute_encrypted

__version__ = "1.0.0"
__all__ = [
    "Lexer",
    "Token",
    "TokenType",
    "parse",
    "Program",
    "compile_jck",
    "encrypt_jxp",
    "decrypt_jxp",
    "Compiler",
    "JockyVM",
    "execute_bytecode",
    "execute_encrypted"
]
