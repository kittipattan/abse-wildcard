from typing import Callable, Any, List, Tuple
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from utils.misc import measure_computation_time
from utils.mac import HomomorphicMAC
import hmac, hashlib, os, random, time

def test_homomac(mac: HomomorphicMAC, group: PairingGroup, tag_count: int) -> Tuple[List, List]:
    messages = []
    tags = []
    for _ in range(tag_count):
        m = group.hash("A"*1000, ZR)    # Transform message into integer
        messages.append(m)
        tags.append(mac.sign(m))

    return tags, messages

def test_homomac_time(mac: HomomorphicMAC, tags: List, hashes: List):
    agg_tag = mac.aggregate_tags(tags)
    hs_sum = sum(hashes)
    mac.verify(hs_sum, agg_tag)

if __name__ == "__main__":
    group = PairingGroup('SS512')   # supersingular elliptic curve / Type-A / symmetric
    g0 = group.random(G1)
    g1 = group.random(GT)
    a = group.random(ZR)
    b = group.random(ZR)

    key = os.urandom(32)
    message = random.randbytes(100)

    mac = HomomorphicMAC(group, group.random(ZR))
    print("HomoMAC:")
    for count in [10,20,30,40]:
        tags, hashes = test_homomac(mac, group, count)
        print(f"{count} tags", end="\t")
        measure_computation_time(test_homomac_time, mac, tags, hashes, iterations=5000)

    # print(f'Verification of aggregated tag is {"successful" if valid else "unsuccessful"}')

    # print('a: ', a)
    # print('b: ', b)
    # print('g0: ', g0)
    # print('g1: ', g1)

    print("Modular Exponentiation: ")
    measure_computation_time(lambda: a**b, iterations=10000)

    print("Exponentiation of group G0: ")
    measure_computation_time(lambda: g0**a, iterations=10000)

    print("Exponentiation of group G1: ")
    measure_computation_time(lambda: g1**a, iterations=10000)

    print("Bilinear pairing: ")
    measure_computation_time(lambda: group.pair_prod(g0, g0), iterations=10000)

    # print("Hash function to group elements:")
    # measure_computation_time(lambda: group.hash('keyword', G1), iterations=1000)

    print("HMAC:")
    measure_computation_time(lambda: hmac.new(key, message, hashlib.sha256).digest(), iterations=10000)
