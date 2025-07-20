import pathlib, time
from typing import Callable, Any

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