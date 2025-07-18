from typing import Callable, Any
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
import hmac
import hashlib
import os
import random
import time

def measure_computation_time(fn: Callable[..., Any], *args, iterations: int = 10000) -> None:
    total_time = 0.0
    for _ in range(iterations):
        start_time = time.time()
        fn(*args)
        end_time = time.time()
        total_time += (end_time - start_time)
    avg_time_ms = total_time / iterations * 1000
    print(f"    Average time over {iterations} iterations: {avg_time_ms} ms")


if __name__ == "__main__":
    group = PairingGroup('SS512')   # supersingular elliptic curve / Type-A / symmetric
    g0 = group.random(G1)
    g1 = group.random(GT)
    a = group.random(ZR)
    b = group.random(ZR)

    key = os.urandom(32)
    message = random.randbytes(100)
    
    print('a: ', a)
    print('b: ', b)
    print('g0: ', g0)
    print('g1: ', g1)

    print("Modular Exponentiation: ")
    measure_computation_time(lambda: a**b, iterations=10000)

    print("Exponentiation of group G0: ")
    measure_computation_time(lambda: g0**a, iterations=10000)

    print("Exponentiation of group G1: ")
    measure_computation_time(lambda: g1**a, iterations=10000)

    print("Bilinear pairing: ")
    measure_computation_time(lambda: group.pair_prod(g0, g0), iterations=10000)

    print("Hash function to group elements:")
    measure_computation_time(lambda: group.hash('keyword', G1), iterations=1000)

    print("HMAC:")
    measure_computation_time(lambda: hmac.new(key, message, hashlib.sha256).digest(), iterations=10000)
