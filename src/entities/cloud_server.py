from typing import List, Set, Dict, Tuple
from utils.iwt import IndexWildcardTree
import pprint

class CloudServer():
    def __init__(self, iwt, ta_pubkey):
        self.__iwt: IndexWildcardTree = iwt
        self.ta_publickey = ta_pubkey

    def search(self, query: List[str]) -> Set[str]:
        files = self.__iwt.search(query)
        pprint.pprint(f"'{query[0]}': {files if files else 'Not found'}")
        return files
    
    def wildcard_search(self, query: List[str], attribute_cert: Tuple[List[str], bytes], debug: bool = False) -> Dict[str, Set[str]] | Set[str]:
        if debug:
            files = self.__iwt.wildcard_search(query)
            print(f"'{query[0]}': {files if files else 'Not found'}")
        else:
            files = self.__iwt.wildcard_files_only(query, attribute_cert, self.ta_publickey)
            # pprint.pprint(f"{files if files else 'Not found'}")

        return files
    
    def proceed_queries(self, queries: List[List[str]], attribute_cert: Tuple[List[str], bytes]) -> Set[str]:
        files = set()
        for query in queries:
            files.update(self.wildcard_search(query, attribute_cert))
        return files