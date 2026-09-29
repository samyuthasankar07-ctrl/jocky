"""
jocky/lexer.py - JOCKY scripting language lexer
Tokenizes .jck source code into a stream of tokens for the parser.
"""

import re
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Optional, Iterator


class TokenType(Enum):
    # Literals
    INT = auto()
    STR = auto()
    BOOL = auto()
    
    # Keywords
    IF = auto()
    ELSE = auto()
    FOR = auto()
    IN = auto()
    DEF = auto()
    RETURN = auto()
    TRUE = auto()
    FALSE = auto()
    
    # Identifiers and operators
    IDENT = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACE = auto()
    RBRACE = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    COLON = auto()
    SEMICOLON = auto()
    COMMA = auto()
    DOT = auto()
    ASSIGN = auto()
    EQ = auto()      # ==
    NE = auto()      # !=
    LT = auto()      # <
    LE = auto()      # <=
    GT = auto()      # >
    GE = auto()      # >=
    PLUS = auto()
    MINUS = auto()
    STAR = auto()
    SLASH = auto()
    PERCENT = auto()
    AND = auto()     # and
    OR = auto()      # or
    NOT = auto()     # not
    
    # Special
    EOF = auto()
    NEWLINE = auto()


@dataclass
class Token:
    type: TokenType
    value: any
    line: int
    col: int


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: List[Token] = []
        
        self.keywords = {
            "if": TokenType.IF,
            "else": TokenType.ELSE,
            "for": TokenType.FOR,
            "in": TokenType.IN,
            "def": TokenType.DEF,
            "return": TokenType.RETURN,
            "True": TokenType.TRUE,
            "False": TokenType.FALSE,
            "and": TokenType.AND,
            "or": TokenType.OR,
            "not": TokenType.NOT,
        }
    
    def current_char(self) -> Optional[str]:
        """Get current character or None if EOF."""
        if self.pos >= len(self.source):
            return None
        return self.source[self.pos]
    
    def peek_char(self, offset: int = 1) -> Optional[str]:
        """Peek ahead n characters."""
        p = self.pos + offset
        if p >= len(self.source):
            return None
        return self.source[p]
    
    def advance(self) -> Optional[str]:
        """Move to next character and return it."""
        if self.pos >= len(self.source):
            return None
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch
    
    def skip_whitespace(self):
        """Skip spaces and tabs but not newlines."""
        while self.current_char() in (' ', '\t'):
            self.advance()
    
    def skip_comment(self):
        """Skip Python-style comments."""
        if self.current_char() == '#':
            while self.current_char() and self.current_char() != '\n':
                self.advance()
    
    def read_string(self, quote: str) -> str:
        """Read a string literal."""
        self.advance()  # skip opening quote
        result = []
        while self.current_char() and self.current_char() != quote:
            if self.current_char() == '\\':
                self.advance()
                ch = self.current_char()
                if ch == 'n':
                    result.append('\n')
                elif ch == 't':
                    result.append('\t')
                elif ch == 'r':
                    result.append('\r')
                elif ch == '\\':
                    result.append('\\')
                elif ch == quote:
                    result.append(quote)
                else:
                    result.append(ch)
                self.advance()
            else:
                result.append(self.current_char())
                self.advance()
        if self.current_char() == quote:
            self.advance()  # skip closing quote
        return ''.join(result)
    
    def read_number(self) -> int:
        """Read an integer literal."""
        result = []
        while self.current_char() and self.current_char().isdigit():
            result.append(self.current_char())
            self.advance()
        return int(''.join(result))
    
    def read_ident(self) -> str:
        """Read an identifier or keyword."""
        result = []
        while self.current_char() and (self.current_char().isalnum() or self.current_char() in '_'):
            result.append(self.current_char())
            self.advance()
        return ''.join(result)
    
    def tokenize(self) -> List[Token]:
        """Tokenize the source code into a list of tokens."""
        while self.pos < len(self.source):
            self.skip_whitespace()
            
            if not self.current_char():
                break
            
            # Comments
            if self.current_char() == '#':
                self.skip_comment()
                continue
            
            line_start = self.line
            col_start = self.col
            ch = self.current_char()
            
            # Newline
            if ch == '\n':
                self.tokens.append(Token(TokenType.NEWLINE, '\n', line_start, col_start))
                self.advance()
                continue
            
            # Strings
            if ch in ('"', "'"):
                value = self.read_string(ch)
                self.tokens.append(Token(TokenType.STR, value, line_start, col_start))
                continue
            
            # Numbers
            if ch.isdigit():
                value = self.read_number()
                self.tokens.append(Token(TokenType.INT, value, line_start, col_start))
                continue
            
            # Identifiers and keywords
            if ch.isalpha() or ch == '_':
                ident = self.read_ident()
                token_type = self.keywords.get(ident, TokenType.IDENT)
                value = True if token_type == TokenType.TRUE else False if token_type == TokenType.FALSE else ident
                self.tokens.append(Token(token_type, value, line_start, col_start))
                continue
            
            # Two-character operators
            next_ch = self.peek_char()
            two_char = ch + (next_ch or '')
            
            if two_char == '==':
                self.tokens.append(Token(TokenType.EQ, '==', line_start, col_start))
                self.advance()
                self.advance()
                continue
            elif two_char == '!=':
                self.tokens.append(Token(TokenType.NE, '!=', line_start, col_start))
                self.advance()
                self.advance()
                continue
            elif two_char == '<=':
                self.tokens.append(Token(TokenType.LE, '<=', line_start, col_start))
                self.advance()
                self.advance()
                continue
            elif two_char == '>=':
                self.tokens.append(Token(TokenType.GE, '>=', line_start, col_start))
                self.advance()
                self.advance()
                continue
            
            # Single-character operators
            single_ops = {
                '(': TokenType.LPAREN,
                ')': TokenType.RPAREN,
                '{': TokenType.LBRACE,
                '}': TokenType.RBRACE,
                '[': TokenType.LBRACKET,
                ']': TokenType.RBRACKET,
                ':': TokenType.COLON,
                ';': TokenType.SEMICOLON,
                ',': TokenType.COMMA,
                '.': TokenType.DOT,
                '=': TokenType.ASSIGN,
                '<': TokenType.LT,
                '>': TokenType.GT,
                '+': TokenType.PLUS,
                '-': TokenType.MINUS,
                '*': TokenType.STAR,
                '/': TokenType.SLASH,
                '%': TokenType.PERCENT,
            }
            
            if ch in single_ops:
                self.tokens.append(Token(single_ops[ch], ch, line_start, col_start))
                self.advance()
                continue
            
            # Unknown character - skip
            self.advance()
        
        self.tokens.append(Token(TokenType.EOF, None, self.line, self.col))
        return self.tokens
