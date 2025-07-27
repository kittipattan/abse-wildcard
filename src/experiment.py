from entities.trusted_authority import TrustedAuthority
from entities.data_user import DataUser
from entities.data_owner import DataOwner
from entities.cloud_server import CloudServer
from utils.misc import print_header, measure_computation_time

ATTRIBUTE_COUNTS = [5, 10, 25, 50]

def run_scheme(attribute_count):
    print_header(f"{attr_count} ATTRIBUTES", 40)

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
    measure_computation_time(TA.gen_sk, DU_test.attributes, iterations=1000)
    DO.pseudo_key = TA.pseudo_key

    # Phase 3: Encryption and Index Generation =============================
    print("Encrypt:")
    measure_computation_time(DO.encrypt_ehr, 'test_ehr_1.txt', ACCESS_POLICY, iterations=1000)

    ct_ref, idx = DO.encrypt_ehr('test_ehr_1.txt', ACCESS_POLICY)

    # Phase 4: Trapdoor Generation and Query ===============================
    # Add more keywords-to-file here
    kwfile_map = [
        ('diabetes', ct_ref),
        ('hypertension', ct_ref),
        ('chronic_conditions', ct_ref),
        ('coronary_artery_disease', ct_ref),
        ('keyword_05', ct_ref),
        ('keyword_06', ct_ref),
        ('keyword_07', ct_ref),
        ('keyword_08', ct_ref),
        ('keyword_09', ct_ref),
        ('keyword_10', ct_ref)
    ]

    DO.construct_iwt(kwfile_map)    
    DO.send_enc_trapdoor_key([DU_test])  
    CS = CloudServer(DO.iwt, TA.public_key)        

    wildcard_queries = ["diabetes"]

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

if __name__ == "__main__":
    for attr_count in ATTRIBUTE_COUNTS:
        run_scheme(attr_count)