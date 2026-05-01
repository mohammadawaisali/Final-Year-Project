# test_vt.py  — run from project root with venv active
import sys
sys.path.insert(0, "src")
from hash_verifier import HashVerifier

hv = HashVerifier()

# EICAR test hash — safe, standard AV test string, always in VT
EICAR_SHA256 = ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

print("Testing _query_virustotal() directly…")
result = hv._query_virustotal(EICAR_SHA256)

print(f"Verdict : {result['vt_verdict']}")
print(f"Ratio   : {result['vt_detection_ratio']}")
print(f"Threats : {result['vt_threat_names']}")
print(f"Link    : {result['vt_link']}")