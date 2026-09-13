"""Quick functionality tests"""
from phishing_detector import PhishingDetector
from blockchain_voting import BlockchainVotingSystem

# Test phishing detector
pd = PhishingDetector()
result = pd.detect_phishing('http://example.com', deep_analysis=False)
print(f'Phishing test: Risk level = {result["risk_level"]}')

# Test blockchain voting
vs = BlockchainVotingSystem()
vs.register_voter('voter1')
result = vs.cast_vote('voter1', 'CandidateA')
print(f'Voting test: {result["message"]}')

print('Quick tests passed!')
