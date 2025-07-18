import math
import mmh3

class BloomFilter:
    """Simple Bloom filter implementation using multiple hash functions."""
    
    def __init__(self, capacity: int = 1000, error_rate: float = 0.01):
        self.capacity = capacity
        self.error_rate = error_rate
        
        # Calculate optimal bit array size and number of hash functions
        self.bit_array_size = self._calculate_bit_array_size()
        self.hash_count = self._calculate_hash_count()
        
        # Initialize bit array
        self.bit_array = [False] * self.bit_array_size
        
    def _calculate_bit_array_size(self) -> int:
        """Calculate optimal bit array size based on capacity and error rate."""
        return int(-(self.capacity * math.log(self.error_rate)) / (math.log(2) ** 2))
    
    def _calculate_hash_count(self) -> int:
        """Calculate optimal number of hash functions."""
        return int((self.bit_array_size / self.capacity) * math.log(2))
    
    def _hash(self, item: str, seed: int) -> int:
        """Generate hash value for an item with given seed."""
        return mmh3.hash(item, seed) % self.bit_array_size
    
    def add(self, item: str):
        """Add an item to the Bloom filter."""
        for i in range(self.hash_count):
            index = self._hash(item, i)
            self.bit_array[index] = True
    
    def contains(self, item: str) -> bool:
        """Check if an item might be in the set (no false negatives, possible false positives)."""
        for i in range(self.hash_count):
            index = self._hash(item, i)
            if not self.bit_array[index]:
                return False
        return True