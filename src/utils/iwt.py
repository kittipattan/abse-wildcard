from typing import Set, List, Optional, Dict, Tuple
from collections import defaultdict
from utils.bloom import BloomFilter

# BY CLAUDE AI
class TrieNode:
    """Node in the prefix trie with Bloom filter and file references."""
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end_of_word = False
        self.bloom_filter = BloomFilter(capacity=1000, error_rate=0.01)
        self.file_references: Set[str] = set()
        
    def add_word_to_subtree(self, word: List[str]):
        """Add a word to the Bloom filter representing all words in this subtree."""
        self.bloom_filter.add(word[-1])
    
    def add_file_reference(self, filename: str):
        """Add a file reference to this node."""
        self.file_references.add(filename)
    
    def might_contain_word(self, word: List[str]) -> bool:
        """Check if the subtree rooted at this node might contain the word."""
        return self.bloom_filter.contains(word[-1])

class IndexWildcardTree:
    """Prefix trie implementation with Bloom filters for efficient word lookups."""
    
    def __init__(self):
        self.root = TrieNode()
        self.word_to_files: Dict[str, Set[str]] = defaultdict(set)
    
    def insert(self, word: List[str], filename: str):
        """Insert a word into the trie with its associated file reference."""
        if not word:
            return
        
        # Add word to all nodes along the path (for Bloom filters)
        current = self.root
        current.add_word_to_subtree(word)
        for char in word:
            if char not in current.children:
                current.children[char] = TrieNode()
            current = current.children[char]
        
        # Mark end of word and add file reference
        current.is_end_of_word = True
        current.add_file_reference(filename)
        
        # Update word-to-files mapping
        self.word_to_files[word[-1]].add(filename)
    
    def search(self, word: List[str]) -> Optional[Set[str]]:
        """Search for a word and return the files that contain it."""
        if not word:
            return None
            
        node = self.root
        
        # Traverse the trie
        for char in word:
            if char not in node.children:   # Change to Bloom filter?
                return None
            node = node.children[char]
        
        # Check if it's a complete word
        if node.is_end_of_word:
            return node.file_references.copy()
        
        return None
    
    def starts_with(self, prefix: str) -> List[str]:
        """Find all words that start with the given prefix."""
        if not prefix:
            return []
            
        prefix = prefix.lower()
        node = self.root
        
        # Navigate to the prefix node
        for char in prefix:
            if char not in node.children:
                return []
            node = node.children[char]
        
        # Collect all words from this node
        words = []
        self._collect_words(node, prefix, words)
        return words
    
    def _collect_words(self, node: TrieNode, prefix: str, words: List[List[str]]):
        """Helper method to collect all words from a given node."""
        if node.is_end_of_word:
            words.append(prefix)
        
        for char, child_node in node.children.items():
            self._collect_words(child_node, prefix + char, words)
    
    def might_have_word_with_prefix(self, prefix: str, target_word: str) -> bool:
        """
        Check if there might be a word 'target_word' that starts with 'prefix'
        using the Bloom filter for fast probabilistic checking.
        """
        if not prefix:
            return self.root.might_contain_word(target_word)
            
        prefix = prefix.lower()
        target_word = target_word.lower()
        node = self.root
        
        # Navigate to the prefix node
        for char in prefix:
            if char not in node.children:
                return False
            node = node.children[char]
        
        # Check if the subtree might contain the target word
        return node.might_contain_word(target_word)
    
    def get_files_for_prefix(self, prefix: str) -> Set[str]:
        """Get all files that contain words starting with the given prefix."""
        if not prefix:
            return set()
            
        prefix = prefix.lower()
        node = self.root
        
        # Navigate to the prefix node
        for char in prefix:
            if char not in node.children:
                return set()
            node = node.children[char]
        
        # Collect all file references from this subtree
        files = set()
        self._collect_files(node, files)
        return files
    
    def _collect_files(self, node: TrieNode, files: Set[str]):
        """Helper method to collect all file references from a subtree."""
        files.update(node.file_references)
        
        for child_node in node.children.values():
            self._collect_files(child_node, files)
    
    def get_word_files_mapping(self) -> Dict[str, Set[str]]:
        """Get the complete mapping of words to files."""
        return dict(self.word_to_files)
    
    def wildcard_search(self, pattern: List[str]) -> Dict[str, Set[str]]:
        """
        Search for words matching a wildcard pattern.
        * matches zero or more characters
        ? matches exactly one character
        Returns a dictionary mapping matching words to their file references.
        """
        if not pattern:
            return {}
            
        results = {}
        self._wildcard_search_helper(self.root, pattern, 0, [], results)
        return results
    
    def _wildcard_search_helper(self, node: TrieNode, pattern: List[str], pattern_idx: int, 
                               current_word: List[str], results: Dict[str, Set[str]]):
        """
        Helper method for wildcard search using backtracking.
        """
        # Base case: we've processed the entire pattern
        if pattern_idx == len(pattern):
            if node.is_end_of_word:
                results[current_word[-1]] = node.file_references.copy()
            return
        
        char = pattern[pattern_idx]
        
        if char == '*':
            # '*' can match zero characters (skip the *)
            self._wildcard_search_helper(node, pattern, pattern_idx + 1, current_word, results)
            
            # '*' can match one or more characters
            for child_char, child_node in node.children.items():
                # Try matching one character and continue with *
                self._wildcard_search_helper(child_node, pattern, pattern_idx, 
                                           current_word + [child_char], results)
        
        elif char == '?':
            # '?' matches exactly one character
            for child_char, child_node in node.children.items():
                self._wildcard_search_helper(child_node, pattern, pattern_idx + 1,
                                           current_word + [child_char], results)
        
        else:
            # Regular character matching
            if char in node.children:   # Change to Bloom filter?
                self._wildcard_search_helper(node.children[char], pattern, pattern_idx + 1,
                                           current_word + [char], results)
    
    def bloom_optimized_exact_search(self, word: str) -> bool:
        """
        This is where Bloom filters actually help - for exact word searches.
        We can quickly check if a word might exist before doing expensive trie traversal.
        """
        if not word:
            return False
        
        word = word.lower()
        
        # Use root's Bloom filter to quickly check if word might exist
        if not self.root.might_contain_word(word):
            return False
        
        # If Bloom filter says it might exist, do the actual search
        return self.search(word) is not None
    
    def bloom_optimized_prefix_search(self, prefix: str) -> List[str]:
        """
        Optimized prefix search using Bloom filters.
        We can check candidate words against Bloom filters before traversing.
        """
        if not prefix:
            return []
        
        prefix = prefix.lower()
        
        # First get all words with this prefix using regular method
        words = self.starts_with(prefix)
        
        # This is where we could add additional optimizations
        # For example, if we had a set of candidate words to check against
        return words
    
    def _matches_pattern(self, word: str, pattern: str) -> bool:
        """
        Check if a word matches a wildcard pattern.
        This is separate from trie traversal - just string matching.
        """
        return self._pattern_match_helper(word, 0, pattern, 0)
    
    def _pattern_match_helper(self, word: str, word_idx: int, pattern: str, pattern_idx: int) -> bool:
        """Helper for pattern matching."""
        # Base cases
        if pattern_idx == len(pattern):
            return word_idx == len(word)
        
        if word_idx == len(word):
            # Check if remaining pattern is all '*'
            return all(c == '*' for c in pattern[pattern_idx:])
        
        char = pattern[pattern_idx]
        
        if char == '*':
            # Try matching zero characters
            if self._pattern_match_helper(word, word_idx, pattern, pattern_idx + 1):
                return True
            # Try matching one character
            return self._pattern_match_helper(word, word_idx + 1, pattern, pattern_idx)
        
        elif char == '?':
            # Match exactly one character
            return self._pattern_match_helper(word, word_idx + 1, pattern, pattern_idx + 1)
        
        else:
            # Exact character match
            if word[word_idx] == char:
                return self._pattern_match_helper(word, word_idx + 1, pattern, pattern_idx + 1)
            return False
    
    # MAIN ONE
    def wildcard_files_only(self, 
                            pattern: List[str]):
        """
        Get only the files that contain words matching the wildcard pattern.
        More efficient when you only need file references, not the actual words.
        """
        if not pattern:
            return set()
            
        files = set()
        self._wildcard_files_helper(self.root, pattern, 0, files)
        return files
    
    def _wildcard_files_helper(self, node: TrieNode, pattern: List[str], pattern_idx: int, 
                              files: Set[str]):
        """Helper method to collect only file references from wildcard matches."""
        if pattern_idx == len(pattern):
            if node.is_end_of_word:
                # print(f"\nCS found {node.file_references}")
                files.update(node.file_references)
            return
        
        char = pattern[pattern_idx]
        
        if char == '*':
            # '*' can match zero characters
            self._wildcard_files_helper(node, pattern, pattern_idx + 1, files)
            
            # '*' can match one or more characters
            for child_node in node.children.values():
                self._wildcard_files_helper(child_node, pattern, pattern_idx, files)
        
        elif char == '?':
            # '?' matches exactly one character
            for child_node in node.children.values():
                self._wildcard_files_helper(child_node, pattern, pattern_idx + 1, files)
        
        else:
            # Regular character matching
            if char in node.children:
                self._wildcard_files_helper(node.children[char], pattern, pattern_idx + 1, files)

# Example usage and testing
if __name__ == "__main__":
    # Create the trie
    trie = IndexWildcardTree()
    
    # Sample data: words and their associated files
    sample_data = [
        ("apple", "fruits.txt"),
        ("application", "software.txt"),
        ("apply", "verbs.txt"),
        ("applied", "verbs.txt"),
        ("banana", "fruits.txt"),
        ("band", "music.txt"),
        ("bandana", "clothing.txt"),
        ("app", "software.txt"),
        ("appreciate", "emotions.txt"),
        ("approach", "methods.txt")
    ]
    
    # Insert sample data
    print("Inserting sample data...")
    for word, filename in sample_data:
        trie.insert(word, filename)
    
    # Test exact word search
    print("\n=== Exact Word Search ===")
    test_words = ["apple", "app", "application", "xyz"]
    for word in test_words:
        files = trie.search(word)
        print(f"'{word}': {files if files else 'Not found'}")
    
    # Test prefix search
    print("\n=== Prefix Search ===")
    test_prefixes = ["app", "ban", "ap"]
    for prefix in test_prefixes:
        words = trie.starts_with(prefix)
        print(f"Words starting with '{prefix}': {words}")
    
    # Test Bloom filter functionality
    print("\n=== Bloom Filter Test ===")
    test_cases = [
        ("app", "application"),  # Should return True
        ("ban", "bandana"),      # Should return True
        ("xyz", "application"),  # Should return False
        ("app", "banana")        # Should return False (probably)
    ]
    
    for prefix, target_word in test_cases:
        result = trie.might_have_word_with_prefix(prefix, target_word)
        print(f"Prefix '{prefix}' might lead to '{target_word}': {result}")
    
    # Test file retrieval for prefix
    print("\n=== Files for Prefix ===")
    for prefix in ["app", "ban"]:
        files = trie.get_files_for_prefix(prefix)
        print(f"Files containing words with prefix '{prefix}': {files}")
    
    # Test wildcard search
    print("\n=== Wildcard Search ===")
    wildcard_patterns = [
        "app*",      # Words starting with "app"
        "*ana",      # Words ending with "ana"
        "?pp*",      # Words with 'pp' at positions 2-3
        "a??*",      # Words starting with 'a' and at least 3 chars long
        "ban*a",     # Words starting with "ban" and ending with "a"
        "*p*",       # Words containing 'p'
        "a*e",       # Words starting with 'a' and ending with 'e'
        "???",       # Exactly 3 character words
        "*"          # All words
    ]
    
    for pattern in wildcard_patterns:
        matches = trie.wildcard_search(pattern)
        print(f"Pattern '{pattern}': {dict(matches) if matches else 'No matches'}")
    
    # Test Bloom filter for exact searches
    print("\n=== Bloom Filter Exact Search ===")
    test_words = ["apple", "application", "nonexistent", "app"]
    for word in test_words:
        exists = trie.bloom_optimized_exact_search(word)
        print(f"Bloom check for '{word}': {exists}")
    
    # Test wildcard files only
    print("\n=== Wildcard Files Only ===")
    for pattern in ["app*", "*ana", "a*e"]:
        files = trie.wildcard_files_only(pattern)
        print(f"Files for pattern '{pattern}': {files}")
    
    # Add more test data for better wildcard demonstration
    print("\n=== Adding More Test Data ===")
    additional_data = [
        ("cat", "animals.txt"),
        ("car", "vehicles.txt"),
        ("card", "games.txt"),
        ("care", "emotions.txt"),
        ("carpet", "home.txt"),
        ("cape", "clothing.txt"),
        ("tape", "office.txt"),
        ("grape", "fruits.txt"),
        ("shape", "geometry.txt"),
        ("escape", "verbs.txt")
    ]
    
    for word, filename in additional_data:
        trie.insert(word, filename)
    
    # Test more complex wildcard patterns
    print("\n=== Complex Wildcard Patterns ===")
    complex_patterns = [
        "c*e",       # Words starting with 'c' and ending with 'e'
        "*ap*",      # Words containing 'ap'
        "?a?e",      # 4-letter words with 'a' as 2nd char and 'e' as 4th
        "c??",       # 3-letter words starting with 'c'
        "*r*",       # Words containing 'r'
        "??pe",      # 4-letter words ending with 'pe'
    ]
    
    for pattern in complex_patterns:
        matches = trie.wildcard_search(pattern)
        print(f"Pattern '{pattern}': {list(matches.keys()) if matches else 'No matches'}")
    
    # Show complete word-to-files mapping
    print("\n=== Complete Word-to-Files Mapping ===")
    mapping = trie.get_word_files_mapping()
    for word, files in sorted(mapping.items()):
        print(f"'{word}': {files}")