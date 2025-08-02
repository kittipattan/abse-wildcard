import pathlib, time, re, ast, operator
from typing import Callable, Any, List

base_path = pathlib.Path(__file__).parent.parent.parent / "files"

def print_header(text: str, length: int):
    side = '='*length
    print(f'{side} {text} {side}')

def measure_computation_time(fn: Callable[..., Any], *args, iterations: int = 10000) -> None:
    total_time = 0.0
    for _ in range(iterations):
        start_time = time.time()
        fn(*args)
        end_time = time.time()
        total_time += (end_time - start_time)
    avg_time_ms = total_time / iterations * 1000
    print(f"    Average time over {iterations} iterations: {avg_time_ms} ms")

OPS = {
    ast.And: all,
    ast.Or: any,
    ast.Not: operator.not_
}

def __eval_expr(node, symbols):
    if isinstance(node, ast.BoolOp):
        op_func = OPS[type(node.op)]
        return op_func([__eval_expr(v, symbols) for v in node.values])
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return operator.not_(__eval_expr(node.operand, symbols))
    elif isinstance(node, ast.Constant):
        return node.value in symbols
    elif isinstance(node, ast.Expr):
        return __eval_expr(node.value, symbols)
    else:
        raise ValueError("Unsupported expression node:", node)

def __quote_attributes(policy_str):
    pattern = re.compile(r'\b(?!and\b|or\b|not\b)[a-zA-Z0-9_]+\b')
    return pattern.sub(lambda m: f'"{m.group(0)}"', policy_str)

def eval_policy(access_policy: str, attrs: List[str]) -> bool:
    try:
        access_policy = __quote_attributes(access_policy)
        expr_ast = ast.parse(access_policy, mode='eval')
        return __eval_expr(expr_ast.body, attrs)
    except Exception as e:
        print("Error:", e)
        return False