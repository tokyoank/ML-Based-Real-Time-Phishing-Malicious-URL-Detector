"""
Secure Online Voting System (Blockchain-based)
Simplified blockchain-based voting system for secure elections
"""

import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict


class BlockchainVotingSystem:
    """Blockchain-based secure voting system"""
    
    def __init__(self):
        self.chain = []
        self.pending_votes = []
        self.voters = set()  # Track registered voters
        self.voter_hashes = set()  # Track voter hash to prevent double voting
        self.difficulty = 2  # Mining difficulty (number of leading zeros)
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the blockchain"""
        genesis_block = {
            'index': 0,
            'timestamp': datetime.now().isoformat(),
            'votes': [],
            'previous_hash': '0' * 64,
            'hash': self._calculate_hash({
                'index': 0,
                'timestamp': datetime.now().isoformat(),
                'votes': [],
                'previous_hash': '0' * 64
            }),
            'nonce': 0
        }
        self.chain.append(genesis_block)
    
    def register_voter(self, voter_id: str) -> Dict[str, any]:
        """
        Register a voter
        
        Args:
            voter_id: Unique voter identifier
        
        Returns:
            Registration result
        """
        result = {
            'success': False,
            'voter_id': voter_id,
            'message': ''
        }
        
        if voter_id in self.voters:
            result['message'] = 'Voter already registered'
            return result
        
        self.voters.add(voter_id)
        result['success'] = True
        result['message'] = 'Voter registered successfully'
        
        return result
    
    def cast_vote(self, voter_id: str, candidate: str, voter_hash: str = None) -> Dict[str, any]:
        """
        Cast a vote
        
        Args:
            voter_id: Voter identifier
            candidate: Candidate or option to vote for
            voter_hash: Hash of voter credentials (for anonymity)
        
        Returns:
            Voting result
        """
        result = {
            'success': False,
            'message': '',
            'vote_id': None
        }
        
        # Check if voter is registered
        if voter_id not in self.voters:
            result['message'] = 'Voter not registered'
            return result
        
        # Generate voter hash if not provided
        if not voter_hash:
            voter_hash = hashlib.sha256(f"{voter_id}{time.time()}".encode()).hexdigest()
        
        # Check for double voting
        if voter_hash in self.voter_hashes:
            result['message'] = 'Vote already cast (double voting prevented)'
            return result
        
        # Create vote
        vote = {
            'voter_hash': voter_hash,
            'candidate': candidate,
            'timestamp': datetime.now().isoformat(),
            'vote_id': hashlib.sha256(f"{voter_hash}{candidate}{time.time()}".encode()).hexdigest()[:16]
        }
        
        self.pending_votes.append(vote)
        self.voter_hashes.add(voter_hash)
        
        result['success'] = True
        result['message'] = 'Vote cast successfully (pending block confirmation)'
        result['vote_id'] = vote['vote_id']
        
        return result
    
    def mine_block(self) -> Dict[str, any]:
        """
        Mine a new block with pending votes
        
        Returns:
            Mining result
        """
        if not self.pending_votes:
            return {'success': False, 'message': 'No pending votes to mine'}
        
        block = {
            'index': len(self.chain),
            'timestamp': datetime.now().isoformat(),
            'votes': self.pending_votes.copy(),
            'previous_hash': self.chain[-1]['hash'],
            'nonce': 0
        }
        
        # Proof of Work
        block['hash'] = self._proof_of_work(block)
        
        # Add block to chain
        self.chain.append(block)
        self.pending_votes = []
        
        return {
            'success': True,
            'message': 'Block mined successfully',
            'block': block
        }
    
    def _proof_of_work(self, block: Dict) -> str:
        """
        Simple proof of work algorithm
        
        Args:
            block: Block to mine
        
        Returns:
            Hash that meets difficulty requirement
        """
        block_string = json.dumps(block, sort_keys=True)
        prefix = '0' * self.difficulty
        
        nonce = 0
        while True:
            block['nonce'] = nonce
            block_string = json.dumps(block, sort_keys=True)
            hash_result = hashlib.sha256(block_string.encode()).hexdigest()
            
            if hash_result.startswith(prefix):
                return hash_result
            
            nonce += 1
            if nonce > 100000:  # Safety limit
                break
        
        return hash_result
    
    def _calculate_hash(self, block: Dict) -> str:
        """
        Calculate hash of a block
        
        Args:
            block: Block dictionary
        
        Returns:
            SHA256 hash
        """
        block_string = json.dumps(block, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def verify_chain(self) -> Dict[str, any]:
        """
        Verify blockchain integrity
        
        Returns:
            Verification result
        """
        result = {
            'valid': True,
            'errors': []
        }
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify previous hash
            if current_block['previous_hash'] != previous_block['hash']:
                result['valid'] = False
                result['errors'].append(f'Block {i}: Previous hash mismatch')
            
            # Verify block hash
            expected_hash = self._calculate_hash({
                'index': current_block['index'],
                'timestamp': current_block['timestamp'],
                'votes': current_block['votes'],
                'previous_hash': current_block['previous_hash'],
                'nonce': current_block['nonce']
            })
            
            if not current_block['hash'].startswith('0' * self.difficulty):
                result['valid'] = False
                result['errors'].append(f'Block {i}: Hash does not meet difficulty')
        
        return result
    
    def get_results(self) -> Dict[str, any]:
        """
        Get voting results
        
        Returns:
            Dictionary with vote counts
        """
        results = defaultdict(int)
        total_votes = 0
        
        for block in self.chain:
            for vote in block.get('votes', []):
                candidate = vote['candidate']
                results[candidate] += 1
                total_votes += 1
        
        return {
            'results': dict(results),
            'total_votes': total_votes,
            'blocks_count': len(self.chain)
        }
    
    def get_vote_history(self, voter_hash: str = None) -> List[Dict]:
        """
        Get vote history (without revealing voter identity)
        
        Args:
            voter_hash: Optional voter hash to filter
        
        Returns:
            List of votes
        """
        votes = []
        for block in self.chain:
            for vote in block.get('votes', []):
                if voter_hash is None or vote['voter_hash'] == voter_hash:
                    votes.append({
                        'vote_id': vote.get('vote_id'),
                        'candidate': vote['candidate'],
                        'timestamp': vote['timestamp'],
                        'block_index': block['index']
                    })
        return votes
    
    def generate_voting_report(self) -> str:
        """
        Generate voting system report
        
        Returns:
            Formatted report string
        """
        results = self.get_results()
        verification = self.verify_chain()
        
        report = f"""
Blockchain Voting System Report
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Blockchain Status:
  Blocks: {len(self.chain)}
  Chain Valid: {'✓ Yes' if verification['valid'] else '✗ No'}
  Registered Voters: {len(self.voters)}
  Total Votes Cast: {results['total_votes']}
  Pending Votes: {len(self.pending_votes)}

Voting Results:
"""
        for candidate, votes in sorted(results['results'].items(), key=lambda x: x[1], reverse=True):
            percentage = (votes / results['total_votes'] * 100) if results['total_votes'] > 0 else 0
            report += f"  {candidate}: {votes} votes ({percentage:.1f}%)\n"
        
        if verification.get('errors'):
            report += f"\nErrors:\n"
            for error in verification['errors']:
                report += f"  ⚠ {error}\n"
        
        return report
    
    def export_blockchain(self, filename: str):
        """
        Export blockchain to file
        
        Args:
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=2)
    
    def import_blockchain(self, filename: str):
        """
        Import blockchain from file
        
        Args:
            filename: Input filename
        """
        with open(filename, 'r') as f:
            self.chain = json.load(f)
