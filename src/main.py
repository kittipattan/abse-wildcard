from entities.trusted_authority import TrustedAuthority
from entities.data_user import DataUser
from entities.data_owner import DataOwner
from entities.cloud_server import CloudServer
from utils.misc import print_header

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
    # TA sends symmetric key used to create pseudo-attributes to DO (assumed via secure channel)
    # so DO can use it to create pseudo-policy
DO.pseudo_key = TA.pseudo_key

# Phase 3: Encryption and Index Generation =============================
print_header("PHASE 3", 50)
    # Need to convert into pseudo-attributes and pseudo-policy before encrypt with CP-ABE
    # TODO
cts = [
    DO.encrypt_ehr('test_ehr_1.txt', ['diabetes', 'hypertension', 'chronic_conditions'], '((doctor or researcher))'), 
    DO.encrypt_ehr('test_ehr_2.txt', ['diabetes', 'coronary_artery_disease'], '((researcher and biology))')
] # return [(ct_ref, idk), ...]

# Phase 4: Trapdoor Generation and Query ===============================
print_header("PHASE 4", 50)
kwfile_map = [
    ('diabetes', cts[0][0]),
    ('hypertension', cts[0][0]),
    ('chronic_conditions', cts[0][0]),
    ('diabetes', cts[1][0]),
    ('coronary_artery_disease', cts[1][0]),
]
DO.construct_iwt(kwfile_map)    
DO.send_enc_trapdoor_key(DUs)   # DO sends key for generating trapdoors to DUs
CS = CloudServer(DO.iwt, TA.public_key)        # DO sends IWT to Cloud Server
                                # Assume that encrypted files are also sent

print(f"\nDU queries")
exact_queries = ["diabetes", "hypertension", "chronic_conditions", "coronary_artery_disease", "xyz"]
wildcard_queries = ["dia*", "chro?"]

# Query
queries = DUs[0].query(wildcard_queries)
# Search
enc_file_names = CS.proceed_queries(queries, DUs[0].attribute_cert)

print(f"\nCS sends {enc_file_names} to DU")
# Decrypt
filepaths = DUs[0].decrypt_ehrs(enc_file_names)
print("\nDecryption successful")
print("\tFiles located at:")
for fp in filepaths:
    print(f"\t\t{fp}")
