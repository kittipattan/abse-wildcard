from entities.trusted_authority import TrustedAuthority
from entities.data_user import DataUser
from entities.data_owner import DataOwner
from entities.cloud_server import CloudServer
from utils.misc import print_header, measure_computation_time
import string, secrets, random, math

def wildcard_suffix(keyword: str, percentage: int) -> str:
    if not 0 <= percentage <= 100:
        raise ValueError("Percentage must be between 0 and 100")
    
    length = len(keyword)
    num_to_replace = max(1, math.floor(length * percentage / 100))
    cut_off = length - num_to_replace

    return keyword[:cut_off] + "*"

def run_scheme(round_num, attribute_count, keyword_length, 
               keyword_in_tree_count, query_count, wildcard_percentage):
    
    print_header(f"ROUND {round_num}", 40)

    print(f'''
Attribute count:\t{attribute_count}
Keyword length:\t\t{keyword_length}
Keyword count in IWT:\t{keyword_in_tree_count}
Query count:\t\t{query_count}
Wildcard percentage:\t{wildcard_percentage}
          ''')
    
    # random keywords
    keywords = [''.join(secrets.choice(string.ascii_lowercase) 
                        for _ in range(keyword_length)) 
                        for _ in range(keyword_in_tree_count)] 

    attributes = {str(i): str(i) for i in range(attribute_count)}
    ACCESS_POLICY = '((' + ' or '.join(attributes.values()) + '))'

    TA = TrustedAuthority()
    DO = DataOwner(TA.master_public_key, TA.group)
    DU_test = DataUser(attributes, TA.master_public_key, TA.group)

    # Phase 1: Setup Phase =================================================
    TA.send_publicparams([DU_test, DO])

    # Phase 2: Key Generation ==============================================
    TA.send_secretkey_and_cert([DU_test])
    print("KeyGen:")
    measure_computation_time(TA.gen_sk, DU_test.attributes, iterations=100)
    DO.pseudo_key = TA.pseudo_key

    # Phase 3: Encryption and Index Generation =============================
    print("Encrypt:")
    measure_computation_time(DO.encrypt_ehr, 'test_ehr_1.txt', ACCESS_POLICY, iterations=100)

    ct_ref, idx = DO.encrypt_ehr('test_ehr_1.txt', ACCESS_POLICY)

    # Phase 4: Trapdoor Generation and Query ===============================

    # kwfile_map = [
    #     ('diabetes', ct_ref),
    #     ('hypertension', ct_ref),
    #     ('chronic_conditions', ct_ref),
    #     ('coronary_artery_disease', ct_ref),
    #     ('keyword_05', ct_ref),
    #     ('keyword_06', ct_ref),
    #     ('keyword_07', ct_ref),
    #     ('keyword_08', ct_ref),
    #     ('keyword_09', ct_ref),
    #     ('keyword_10', ct_ref)
    # ]

    kwfile_map =[(keyword, ct_ref) for keyword in keywords]

    DO.construct_iwt(kwfile_map)    
    DO.send_enc_trapdoor_key([DU_test])  
    CS = CloudServer(DO.iwt, TA.public_key)        

    # randomly choose keyword to query
    wildcard_queries = [random.choice(keywords) if wildcard_percentage <= 0
                        else wildcard_suffix(random.choice(keywords), wildcard_percentage) 
                        for _ in range(query_count)]
    # print(wildcard_queries)

    # Query
    queries = DU_test.query(wildcard_queries)

    print("Trapdoor:")
    measure_computation_time(DU_test.query, wildcard_queries, iterations=1000)

    # Search
    print("Search:")
    measure_computation_time(CS.proceed_queries, queries, DU_test.attribute_cert, iterations=1000)

    enc_file_names = CS.proceed_queries(queries, DU_test.attribute_cert)

    # Decrypt
    print("Decrypt:")
    measure_computation_time(DU_test.decrypt_ehrs, enc_file_names, iterations=1000)

    filepaths = DU_test.decrypt_ehrs(enc_file_names)
    
    print()

if __name__ == "__main__":
    ATTRIBUTE_COUNTS = [5, 10, 25, 50]  # attributes
    KEYWORD_LENGTHS = [8, 16, 32, 64]   # characters
    KEYWORD_IN_TREE_COUNTS = [5, 10, 15, 20]    # keywords
    QUERY_COUNTS = [1, 2, 3, 4]         # queries
    WILDCARD_PERCENTAGES = [10, 20, 30] # percent

    to_run_test = {
        "attribute_counts": 1,
        "keyword_lengths": 0,
        "keyword_in_tree_counts": 0,
        "query_counts": 0,
        "wildcard_percentages": 0
    }

    # Attribute counts dependent
    if (to_run_test["attribute_counts"]):
        print_header("ATTRIBUTE COUNTS", 40)
        for i, attribute_count in enumerate(ATTRIBUTE_COUNTS):
            run_scheme(i, attribute_count, 16, 5, 1, 0)

    # Keyword lengths dependent
    if (to_run_test["keyword_lengths"]):
        print_header("KEYWORD LENGTHS", 40)
        for i, keyword_len in enumerate(KEYWORD_LENGTHS):
            run_scheme(i, 10, keyword_len, 5, 1, 0)

    # Keyword counts in IWT dependent
    if (to_run_test["keyword_in_tree_counts"]):
        print_header("KEYWORDS IN IWT", 40)
        for i, keyword_in_tree_count in enumerate(KEYWORD_IN_TREE_COUNTS):
            run_scheme(i, 10, 16, keyword_in_tree_count, 1, 0)

    # Query counts dependent
    if (to_run_test["query_counts"]):
        print_header("QUERIES", 40)
        for i, query_count in enumerate(QUERY_COUNTS):
            run_scheme(i, 10, 16, 5, query_count, 0)

    if (to_run_test["wildcard_percentages"]):
        print_header("WILDCARD PERCENTAGES", 40)
        for i, wildcard_percent in enumerate(WILDCARD_PERCENTAGES):
            run_scheme(i, 10, 16, 5, 1, wildcard_percent)