"""
jocky/parser.py - JOCKY scripting language parser
Builds an abstract syntax tree (AST) from tokenized source.
"""

from dataclasses import dataclass
from typing import List, Optional, Union
from jocky.lexer import Token, TokenType, Lexer


# ────────────────────────────────────────────────────────────────────────────
# AST Node types
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    pass


@dataclass
class IntLiteral(ASTNode):
    value: int


@dataclass
class StrLiteral(ASTNode):
    value: str


@dataclass
class BoolLiteral(ASTNode):
    value: bool


@dataclass
class ListLiteral(ASTNode):
    elements: List[ASTNode]


@dataclass
class Identifier(ASTNode):
    name: str


@dataclass
class BinOp(ASTNode):
    left: ASTNode
    op: str
    right: ASTNode


@dataclass
class UnaryOp(ASTNode):
    op: str
    operand: ASTNode


@dataclass
class Assign(ASTNode):
    target: str
    value: ASTNode


@dataclass
class FuncCall(ASTNode):
    name: str
    args: List[ASTNode]


@dataclass
class MethodCall(ASTNode):
    obj: ASTNode
    method: str
    args: List[ASTNode]


@dataclass
class IfStmt(ASTNode):
    condition: ASTNode
    then_body: List[ASTNode]
    else_body: Optional[List[ASTNode]] = None


@dataclass
class ForStmt(ASTNode):
    var: str
    iterable: ASTNode
    body: List[ASTNode]


@dataclass
class ReturnStmt(ASTNode):
    value: Optional[ASTNode] = None


@dataclass
class FuncDef(ASTNode):
    name: str
    params: List[str]
    body: List[ASTNode]


@dataclass
class Program(ASTNode):
    statements: List[ASTNode]


@dataclass
class IndexAccess(ASTNode):
    obj: ASTNode
    index: ASTNode


# ────────────────────────────────────────────────────────────────────────────
# Parser class
# ────────────────────────────────────────────────────────────────────────────

class Parser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def current_token(self) -> Token:
        """Get the current token."""
        if self.pos >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[self.pos]
    
    def peek_token(self, offset: int = 1) -> Token:
        """Peek ahead n tokens."""
        p = self.pos + offset
        if p >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[p]
    
    def advance(self) -> Token:
        """Move to next token and return current."""
        token = self.current_token()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return token
    
    def skip_newlines(self):
        """Skip any newline tokens."""
        while self.current_token().type == TokenType.NEWLINE:
            self.advance()
    
    def expect(self, token_type: TokenType) -> Token:
        """Consume a token of the expected type or raise."""
        token = self.current_token()
        if token.type != token_type:
            raise SyntaxError(
                f"Expected {token_type} at line {token.line}, col {token.col}; got {token.type}"
            )
        self.advance()
        return token
    
    def match(self, *token_types: TokenType) -> bool:
        """Check if current token matches any of the given types."""
        return self.current_token().type in token_types
    
    def parse(self) -> Program:
        """Parse the entire program."""
        self.skip_newlines()
        statements = []
        
        while not self.match(TokenType.EOF):
            self.skip_newlines()
            if self.match(TokenType.EOF):
                break
            
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
            
            self.skip_newlines()
        
        return Program(statements=statements)
    
    def parse_statement(self) -> Optional[ASTNode]:
        """Parse a single statement."""
        self.skip_newlines()
        
        if self.match(TokenType.DEF):
            return self.parse_func_def()
        elif self.match(TokenType.IF):
            return self.parse_if_stmt()
        elif self.match(TokenType.FOR):
            return self.parse_for_stmt()
        elif self.match(TokenType.RETURN):
            return self.parse_return_stmt()
        else:
            return self.parse_expr_stmt()
    
    def parse_func_def(self) -> FuncDef:
        """Parse: def name(param1, param2, ...): body"""
        self.expect(TokenType.DEF)
        name_token = self.expect(TokenType.IDENT)
        name = name_token.value
        
        self.expect(TokenType.LPAREN)
        params = []
        if not self.match(TokenType.RPAREN):
            params.append(self.expect(TokenType.IDENT).value)
            while self.match(TokenType.COMMA):
                self.advance()
                params.append(self.expect(TokenType.IDENT).value)
        self.expect(TokenType.RPAREN)
        
        self.expect(TokenType.COLON)
        self.skip_newlines()
        
        if self.match(TokenType.LBRACE):
            self.advance()
            self.skip_newlines()
            body = []
            while not self.match(TokenType.RBRACE):
                stmt = self.parse_statement()
                if stmt:
                    body.append(stmt)
                self.skip_newlines()
            self.expect(TokenType.RBRACE)
        else:
            body = [self.parse_statement()]
        
        return FuncDef(name=name, params=params, body=body)
    
    def parse_if_stmt(self) -> IfStmt:
        """Parse: if condition: body [else: body]"""
        self.expect(TokenType.IF)
        condition = self.parse_expression()
        self.expect(TokenType.COLON)
        self.skip_newlines()
        
        if self.match(TokenType.LBRACE):
            self.advance()
            self.skip_newlines()
            then_body = []
            while not self.match(TokenType.RBRACE):
                stmt = self.parse_statement()
                if stmt:
                    then_body.append(stmt)
                self.skip_newlines()
            self.expect(TokenType.RBRACE)
        else:
            then_body = [self.parse_statement()]
        
        else_body = None
        if self.match(TokenType.ELSE):
            self.advance()
            self.expect(TokenType.COLON)
            self.skip_newlines()
            
            if self.match(TokenType.LBRACE):
                self.advance()
                self.skip_newlines()
                else_body = []
                while not self.match(TokenType.RBRACE):
                    stmt = self.parse_statement()
                    if stmt:
                        else_body.append(stmt)
                    self.skip_newlines()
                self.expect(TokenType.RBRACE)
            else:
                else_body = [self.parse_statement()]
        
        return IfStmt(condition=condition, then_body=then_body, else_body=else_body)
    
    def parse_for_stmt(self) -> ForStmt:
        """Parse: for var in iterable: body"""
        self.expect(TokenType.FOR)
        var_token = self.expect(TokenType.IDENT)
        var = var_token.value
        
        self.expect(TokenType.IN)
        iterable = self.parse_expression()
        self.expect(TokenType.COLON)
        self.skip_newlines()
        
        if self.match(TokenType.LBRACE):
            self.advance()
            self.skip_newlines()
            body = []
            while not self.match(TokenType.RBRACE):
                stmt = self.parse_statement()
                if stmt:
                    body.append(stmt)
                self.skip_newlines()
            self.expect(TokenType.RBRACE)
        else:
            body = [self.parse_statement()]
        
        return ForStmt(var=var, iterable=iterable, body=body)
    
    def parse_return_stmt(self) -> ReturnStmt:
        """Parse: return [expr]"""
        self.expect(TokenType.RETURN)
        value = None
        if not self.match(TokenType.NEWLINE, TokenType.SEMICOLON, TokenType.EOF, TokenType.RBRACE):
            value = self.parse_expression()
        return ReturnStmt(value=value)
    
    def parse_expr_stmt(self) -> Optional[ASTNode]:
        """Parse an expression statement."""
        return self.parse_expression()
    
    def parse_expression(self) -> ASTNode:
        """Parse an assignment or lower-precedence expression."""
        expr = self.parse_or()
        
        if self.match(TokenType.ASSIGN):
            if isinstance(expr, Identifier):
                self.advance()
                value = self.parse_expression()
                return Assign(target=expr.name, value=value)
            else:
                raise SyntaxError("Invalid assignment target")
        
        return expr
    
    def parse_or(self) -> ASTNode:
        """Parse: expr or expr"""
        left = self.parse_and()
        
        while self.match(TokenType.OR):
            op = self.advance().value
            right = self.parse_and()
            left = BinOp(left=left, op=op, right=right)
        
        return left
    
    def parse_and(self) -> ASTNode:
        """Parse: expr and expr"""
        left = self.parse_not()
        
        while self.match(TokenType.AND):
            op = self.advance().value
            right = self.parse_not()
            left = BinOp(left=left, op=op, right=right)
        
        return left
    
    def parse_not(self) -> ASTNode:
        """Parse: not expr"""
        if self.match(TokenType.NOT):
            op = self.advance().value
            operand = self.parse_not()
            return UnaryOp(op=op, operand=operand)
        
        return self.parse_comparison()
    
    def parse_comparison(self) -> ASTNode:
        """Parse: expr (== | != | < | <= | > | >=) expr"""
        left = self.parse_additive()
        
        while self.match(TokenType.EQ, TokenType.NE, TokenType.LT, TokenType.LE, TokenType.GT, TokenType.GE):
            op = self.advance().value
            right = self.parse_additive()
            left = BinOp(left=left, op=op, right=right)
        
        return left
    
    def parse_additive(self) -> ASTNode:
        """Parse: expr (+ | -) expr"""
        left = self.parse_multiplicative()
        
        while self.match(TokenType.PLUS, TokenType.MINUS):
            op = self.advance().value
            right = self.parse_multiplicative()
            left = BinOp(left=left, op=op, right=right)
        
        return left
    
    def parse_multiplicative(self) -> ASTNode:
        """Parse: expr (* | / | %) expr"""
        left = self.parse_unary()
        
        while self.match(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op = self.advance().value
            right = self.parse_unary()
            left = BinOp(left=left, op=op, right=right)
        
        return left
    
    def parse_unary(self) -> ASTNode:
        """Parse: (+ | -) expr"""
        if self.match(TokenType.PLUS, TokenType.MINUS):
            op = self.advance().value
            operand = self.parse_unary()
            return UnaryOp(op=op, operand=operand)
        
        return self.parse_postfix()
    
    def parse_postfix(self) -> ASTNode:
        """Parse: primary [call | index | member]*"""
        expr = self.parse_primary()
        
        while True:
            if self.match(TokenType.LPAREN):
                # Function call
                self.advance()
                args = []
                if not self.match(TokenType.RPAREN):
                    args.append(self.parse_expression())
                    while self.match(TokenType.COMMA):
                        self.advance()
                        args.append(self.parse_expression())
                self.expect(TokenType.RPAREN)
                
                if isinstance(expr, Identifier):
                    expr = FuncCall(name=expr.name, args=args)
                else:
                    raise SyntaxError("Cannot call non-identifier")
            
            elif self.match(TokenType.LBRACKET):
                # Index access
                self.advance()
                index = self.parse_expression()
                self.expect(TokenType.RBRACKET)
                expr = IndexAccess(obj=expr, index=index)
            
            elif self.match(TokenType.DOT):
                # Member access (method call only)
                self.advance()
                method_token = self.expect(TokenType.IDENT)
                method = method_token.value
                
                if self.match(TokenType.LPAREN):
                    self.advance()
                    args = []
                    if not self.match(TokenType.RPAREN):
                        args.append(self.parse_expression())
                        while self.match(TokenType.COMMA):
                            self.advance()
                            args.append(self.parse_expression())
                    self.expect(TokenType.RPAREN)
                    expr = MethodCall(obj=expr, method=method, args=args)
                else:
                    raise SyntaxError("Member access without call not supported")
            
            else:
                break
        
        return expr
    
    def parse_primary(self) -> ASTNode:
        """Parse: literal | identifier | ( expr ) | [ list ]"""
        token = self.current_token()
        
        if self.match(TokenType.INT):
            self.advance()
            return IntLiteral(value=token.value)
        
        elif self.match(TokenType.STR):
            self.advance()
            return StrLiteral(value=token.value)
        
        elif self.match(TokenType.TRUE, TokenType.FALSE):
            self.advance()
            return BoolLiteral(value=token.value)
        
        elif self.match(TokenType.IDENT):
            self.advance()
            return Identifier(name=token.value)
        
        elif self.match(TokenType.LPAREN):
            self.advance()
            expr = self.parse_expression()
            self.expect(TokenType.RPAREN)
            return expr
        
        elif self.match(TokenType.LBRACKET):
            self.advance()
            elements = []
            if not self.match(TokenType.RBRACKET):
                elements.append(self.parse_expression())
                while self.match(TokenType.COMMA):
                    self.advance()
                    if self.match(TokenType.RBRACKET):
                        break
                    elements.append(self.parse_expression())
            self.expect(TokenType.RBRACKET)
            return ListLiteral(elements=elements)
        
        else:
            raise SyntaxError(f"Unexpected token: {token.type} at line {token.line}")


def parse(source: str) -> Program:
    """Parse JOCKY source code and return the AST."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    return parser.parse()
