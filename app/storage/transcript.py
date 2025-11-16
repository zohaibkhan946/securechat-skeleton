"""Append-only transcript + TranscriptHash helpers."""

import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime


class TranscriptLogger:
    """Manages append-only transcript logs for non-repudiation."""
    
    def __init__(self, session_id: str, transcript_dir: str = "transcripts"):
        """Initialize transcript logger.
        
        Args:
            session_id: Unique session identifier
            transcript_dir: Directory to store transcripts
        """
        self.session_id = session_id
        self.transcript_dir = Path(transcript_dir)
        self.transcript_dir.mkdir(parents=True, exist_ok=True)
        
        # Transcript file path
        self.transcript_file = self.transcript_dir / f"session_{session_id}.txt"
        
        # Initialize transcript file
        if not self.transcript_file.exists():
            with open(self.transcript_file, "w") as f:
                f.write(f"# Session Transcript: {session_id}\n")
                f.write(f"# Started: {datetime.utcnow().isoformat()}\n\n")
        
        self.lines = []
    
    def append(self, seqno: int, timestamp: int, ciphertext: str, signature: str, peer_cert_fingerprint: str):
        """Append a message entry to the transcript.
        
        Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64 encoded ciphertext
            signature: Base64 encoded signature
            peer_cert_fingerprint: SHA-256 fingerprint of peer's certificate
        """
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
        
        # Append to file
        with open(self.transcript_file, "a") as f:
            f.write(line)
        
        # Keep in memory for hash computation
        self.lines.append(line.rstrip('\n'))
    
    def compute_transcript_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript.
        
        TranscriptHash = SHA256(concatenation of all log lines)
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        # Read all lines from file (in case of file system issues)
        try:
            with open(self.transcript_file, "r") as f:
                lines = [line.rstrip('\n') for line in f.readlines() if not line.startswith('#')]
        except FileNotFoundError:
            # Fall back to in-memory lines
            lines = self.lines
        
        # Concatenate all non-comment lines
        transcript_content = '\n'.join(lines)
        
        # Compute SHA-256 hash
        transcript_hash = hashlib.sha256(transcript_content.encode('utf-8')).hexdigest()
        
        return transcript_hash
    
    def get_transcript_file_path(self) -> Path:
        """Get path to transcript file.
        
        Returns:
            Path to transcript file
        """
        return self.transcript_file
    
    def get_first_seqno(self) -> Optional[int]:
        """Get first sequence number in transcript.
        
        Returns:
            First sequence number or None if transcript is empty
        """
        try:
            with open(self.transcript_file, "r") as f:
                for line in f:
                    if not line.startswith('#') and line.strip():
                        parts = line.split('|')
                        if parts:
                            return int(parts[0])
        except (FileNotFoundError, ValueError, IndexError):
            pass
        return None
    
    def get_last_seqno(self) -> Optional[int]:
        """Get last sequence number in transcript.
        
        Returns:
            Last sequence number or None if transcript is empty
        """
        try:
            with open(self.transcript_file, "r") as f:
                last_seqno = None
                for line in f:
                    if not line.startswith('#') and line.strip():
                        parts = line.split('|')
                        if parts:
                            last_seqno = int(parts[0])
                return last_seqno
        except (FileNotFoundError, ValueError, IndexError):
            pass
        return None
    
    def close(self):
        """Close transcript file and add footer."""
        with open(self.transcript_file, "a") as f:
            f.write(f"\n# Session ended: {datetime.utcnow().isoformat()}\n")