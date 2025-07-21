from entities.trusted_authority import TrustedAuthority
from entities.data_user import DataUser
from entities.data_owner import DataOwner
from entities.cloud_server import CloudServer
from utils.misc import print_header, measure_computation_time

TA = TrustedAuthority()
DO = DataOwner(TA.master_public_key, TA.group)
DUs = [DataUser(attr, TA.master_public_key, TA.group, i) for i, attr in enumerate(TA.get_du_attributes())]

# Phase 1: Setup Phase =================================================
print_header("PHASE 1", 50)
    # TA setup public parameters and sends them to DUs and DO
TA.send_publicparams(DUs + [DO])

# Phase 2: Key Generation ==============================================
print_header("PHASE 2", 50)
    # TA generates secret keys according to each DU's attributes
    # TA generates attribute certificate according to each DU's attributes
    # and securely sends attribute certs and secret keys to the corresponding DU
TA.send_secretkey_and_cert(DUs)
print("KeyGen:")
measure_computation_time(TA.gen_sk, DUs[0].attributes, iterations=1000)

    # TA sends symmetric key used to create pseudo-attributes to DO (assumed via secure channel)
    # so DO can use it to create pseudo-policy
DO.pseudo_key = TA.pseudo_key

# Phase 3: Encryption and Index Generation =============================
print_header("PHASE 3", 50)
print("Encrypt:")
measure_computation_time(DO.encrypt_ehr, 'test_ehr_1.txt',  '((doctor))', iterations=1000)
measure_computation_time(DO.encrypt_ehr, 'test_ehr_1.txt', '((doctor or (researcher and neurology)))', iterations=1000)
measure_computation_time(DO.encrypt_ehr, 'test_ehr_1.txt', '((doctor or (researcher and neurology and biology)))', iterations=1000)

# cts = [
#     DO.encrypt_ehr('test_ehr_1.txt', ['diabetes', 'hypertension', 'chronic_conditions'], '((doctor or researcher))'), 
#     DO.encrypt_ehr('test_ehr_2.txt', ['diabetes', 'coronary_artery_disease'], '((researcher and biology))')
# ] # return [(ct_ref, idk), ...]

# Add more files to encrypt and their access policies here
cts = [
    DO.encrypt_ehr('test_ehr_1.txt', '((doctor or researcher))'), 
    DO.encrypt_ehr('test_ehr_2.txt', '((researcher and biology))')
] # return [(ct_ref, idk), ...]

# Phase 4: Trapdoor Generation and Query ===============================
print_header("PHASE 4", 50)

# Add more keywords-to-file here
kwfile_map = [
    ('diabetes', cts[0][0]),
    ('hypertension', cts[0][0]),
    ('chronic_conditions', cts[0][0]),
    ('coronary_artery_disease', cts[1][0])
    ('keyword_5', cts[1][0]),
    ('keyword_6', cts[1][0]),
    ('keyword_7', cts[1][0])
]

DO.construct_iwt(kwfile_map)    
DO.send_enc_trapdoor_key(DUs)   # DO sends key for generating trapdoors to DUs
CS = CloudServer(DO.iwt, TA.public_key)        # DO sends IWT to Cloud Server
                                # Assume that encrypted files are also sent

# print(f"\nDU queries")
exact_queries = ["diabetes", "hypertension", "chronic_conditions", "coronary_artery_disease", "xyz"]

wildcard_queries = ["diabetes", "hypertension"] # Modify keywords to query here

# Query
queries = DUs[0].query(wildcard_queries)

print("Trapdoor:")
measure_computation_time(DUs[0].query, wildcard_queries, iterations=1000)

# Search
print("Search:")
measure_computation_time(CS.proceed_queries, queries, DUs[0].attribute_cert, iterations=1000)

enc_file_names = CS.proceed_queries(queries, DUs[0].attribute_cert)

# print(f"\nCS sends {enc_file_names} to DU")
# Decrypt
print("Decrypt:")
measure_computation_time(DUs[0].decrypt_ehrs, enc_file_names, iterations=1000)

filepaths = DUs[0].decrypt_ehrs(enc_file_names)
# print("\nDecryption successful")
# print("\tFiles located at:")
for fp in filepaths:
    print(f"\t\t{fp}")
