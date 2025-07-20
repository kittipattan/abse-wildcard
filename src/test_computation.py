from typing import Callable, Any
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from utils.misc import measure_computation_time
import hmac, hashlib, os, random, time

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
