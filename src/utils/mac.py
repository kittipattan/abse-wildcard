import hmac, hashlib, re
from charm.toolbox.pairinggroup import G1, G2

def prf(key: bytes, message: str | bytes) -> int:
    if (type(message) == str):
        message = message.encode()
    output = hmac.new(key, message, hashlib.sha256).digest()
    return int.from_bytes(output)

def mac_linear(key: int, message: str | bytes) -> int:  # wtf is this shit
    message = int.from_bytes(message.encode() if type(message) == str else message)
    return (key * message)

def gen_pseudo_attr(key: bytes, attribute: str) -> str:
    return hmac.new(key, attribute.lower().encode(), hashlib.sha256).hexdigest().upper()

def gen_pseudo_policy(key: bytes, policy: str):
    items = set(re.findall(r'\b\w+\b', policy))
    operators = {'and', 'or', 'not'}
    attributes = items - operators
    pseudo_mapping = {attr: gen_pseudo_attr(key, attr) for attr in attributes}

    def replace_attr(match):
        word = match.group(0)
        return pseudo_mapping.get(word, word)
    
    pseudoed = re.sub(r'\b\w+\b', replace_attr, policy)
    return pseudoed

# BY CHATGPT
class HomomorphicMAC:
    def __init__(self, group_obj, secret_key):
        self.group = group_obj
        self.g = self.group.random(G1)
        self.h = self.group.random(G2)
        self.sk = secret_key
        self.vk = self.h ** self.sk      # verification key

    def sign(self, m):
        # m is an integer message (you can hash your data to int)
        tag = self.g ** (m * self.sk)
        return tag

    def aggregate_tags(self, tags):
        agg_tag = 1
        for i, tag in enumerate(tags):
            # print(f'{i}: {tag}')
            agg_tag *= tag
        # print(agg_tag)
        return agg_tag

    def verify(self, m_sum, tag):
        # Checks e(tag, h) == e(g, vk)^m_sum
        left = self.group.pair_prod(tag, self.h)
        right = self.group.pair_prod(self.g, self.vk) ** m_sum
        return left == right
    