"""
CAPTCHA Challenge Module for WAF
Provides challenge pages for suspicious but not definitively malicious requests
"""
import os
import time
import random
import string
import hashlib
from typing import Optional, Tuple, Dict
from dataclasses import dataclass


@dataclass
class ChallengeToken:
    """Challenge token for verification"""
    token: str
    answer: str
    created_at: float
    ip: str
    expires_at: float


class CaptchaChallenge:
    """
    Simple math-based CAPTCHA challenge system
    No external dependencies required
    """
    
    def __init__(self, storage, token_ttl: int = 300):
        """
        Initialize CAPTCHA challenge system
        
        Args:
            storage: Storage backend for token persistence
            token_ttl: Token time-to-live in seconds (default: 5 minutes)
        """
        self.storage = storage
        self.token_ttl = token_ttl
        self._challenges: Dict[str, ChallengeToken] = {}
    
    def _generate_token(self) -> str:
        """Generate a unique token"""
        return hashlib.sha256(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:32]
    
    def _generate_math_challenge(self) -> Tuple[str, str]:
        """
        Generate a simple math challenge
        Returns (question, answer)
        """
        operators = ['+', '-', '*']
        op = random.choice(operators)
        
        if op == '+':
            a, b = random.randint(1, 20), random.randint(1, 20)
            answer = a + b
        elif op == '-':
            a, b = random.randint(10, 30), random.randint(1, 10)
            answer = a - b
        else:  # '*'
            a, b = random.randint(2, 10), random.randint(2, 10)
            answer = a * b
        
        question = f"What is {a} {op} {b}?"
        return question, str(answer)
    
    def create_challenge(self, ip: str) -> Tuple[str, str]:
        """
        Create a new challenge for an IP
        Returns (token, question)
        """
        token = self._generate_token()
        question, answer = self._generate_math_challenge()
        
        self._challenges[token] = ChallengeToken(
            token=token,
            answer=answer,
            created_at=time.time(),
            ip=ip,
            expires_at=time.time() + self.token_ttl
        )
        
        return token, question
    
    def verify_challenge(self, token: str, answer: str, ip: str) -> Tuple[bool, str]:
        """
        Verify a challenge response
        Returns (success, message)
        """
        if token not in self._challenges:
            return False, "Invalid or expired challenge"
        
        challenge = self._challenges[token]
        
        # Check expiration
        if time.time() > challenge.expires_at:
            del self._challenges[token]
            return False, "Challenge expired"
        
        # Check IP match
        if challenge.ip != ip:
            return False, "IP mismatch"
        
        # Check answer
        if answer.strip() == challenge.answer:
            # Success - remove challenge and mark IP as verified
            del self._challenges[token]
            return True, "Challenge passed"
        else:
            return False, "Incorrect answer"
    
    def cleanup_expired(self):
        """Remove expired challenges"""
        current_time = time.time()
        expired = [
            token for token, challenge in self._challenges.items()
            if current_time > challenge.expires_at
        ]
        for token in expired:
            del self._challenges[token]
    
    def get_challenge_html(self, token: str, question: str, error: str = None) -> str:
        """Generate HTML for challenge page"""
        error_html = f'<div class="error">{error}</div>' if error else ''
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Challenge</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 400px;
            width: 90%;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}
        .shield {{
            font-size: 60px;
            margin-bottom: 20px;
        }}
        h1 {{
            font-size: 24px;
            margin-bottom: 10px;
        }}
        p {{
            color: #b0b0b0;
            margin-bottom: 30px;
            line-height: 1.6;
        }}
        .question {{
            background: rgba(0, 0, 0, 0.2);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 20px;
            font-weight: bold;
        }}
        .error {{
            background: rgba(255, 0, 0, 0.2);
            border: 1px solid rgba(255, 0, 0, 0.5);
            color: #ff6b6b;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        form {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        input[type="text"] {{
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            text-align: center;
            background: rgba(255, 255, 255, 0.9);
            color: #333;
        }}
        input[type="text"]:focus {{
            outline: 2px solid #4CAF50;
        }}
        button {{
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
        }}
        .footer {{
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Security Challenge</h1>
        <p>Please complete this challenge to verify you're not a bot.</p>
        
        {error_html}
        
        <div class="question">{question}</div>
        
        <form method="POST" action="">
            <input type="hidden" name="challenge_token" value="{token}">
            <input type="text" name="challenge_answer" placeholder="Enter your answer" 
                   required autofocus autocomplete="off">
            <button type="submit">Verify</button>
        </form>
        
        <p class="footer">Protected by Web Application Firewall</p>
    </div>
</body>
</html>'''


class SuspicionTracker:
    """
    Tracks suspicious activity to determine when to show CAPTCHA
    Uses a scoring system to avoid false positives
    """
    
    # Suspicion score thresholds
    CAPTCHA_THRESHOLD = 50  # Show CAPTCHA at this score
    BLOCK_THRESHOLD = 100   # Block at this score
    
    # Score decay (points removed per minute)
    SCORE_DECAY_RATE = 5
    
    # Suspicion indicators and their scores
    INDICATORS = {
        'unusual_user_agent': 10,
        'missing_headers': 5,
        'rapid_requests': 15,
        'probe_paths': 20,
        'encoded_chars': 10,
        'long_query_string': 5,
        'unusual_method': 15,
        'invalid_encoding': 20,
    }
    
    def __init__(self):
        self._scores: Dict[str, Dict] = {}
    
    def add_suspicion(self, ip: str, indicator: str) -> int:
        """
        Add suspicion score for an IP
        Returns the new total score
        """
        if ip not in self._scores:
            self._scores[ip] = {'score': 0, 'last_update': time.time(), 'indicators': []}
        
        # Apply decay based on time since last update
        self._apply_decay(ip)
        
        # Add new score
        points = self.INDICATORS.get(indicator, 10)
        self._scores[ip]['score'] += points
        self._scores[ip]['indicators'].append({
            'indicator': indicator,
            'points': points,
            'time': time.time()
        })
        self._scores[ip]['last_update'] = time.time()
        
        return self._scores[ip]['score']
    
    def _apply_decay(self, ip: str):
        """Apply score decay based on time"""
        if ip not in self._scores:
            return
        
        minutes_elapsed = (time.time() - self._scores[ip]['last_update']) / 60
        decay = int(minutes_elapsed * self.SCORE_DECAY_RATE)
        
        self._scores[ip]['score'] = max(0, self._scores[ip]['score'] - decay)
        self._scores[ip]['last_update'] = time.time()
    
    def get_score(self, ip: str) -> int:
        """Get current suspicion score for an IP"""
        if ip not in self._scores:
            return 0
        self._apply_decay(ip)
        return self._scores[ip]['score']
    
    def should_challenge(self, ip: str) -> bool:
        """Check if IP should be shown CAPTCHA"""
        score = self.get_score(ip)
        return self.CAPTCHA_THRESHOLD <= score < self.BLOCK_THRESHOLD
    
    def should_block(self, ip: str) -> bool:
        """Check if IP should be blocked"""
        return self.get_score(ip) >= self.BLOCK_THRESHOLD
    
    def clear(self, ip: str):
        """Clear suspicion for an IP (after successful challenge)"""
        if ip in self._scores:
            del self._scores[ip]
    
    def cleanup_expired(self, max_age_minutes: int = 60):
        """Remove old entries"""
        cutoff = time.time() - (max_age_minutes * 60)
        expired = [
            ip for ip, data in self._scores.items()
            if data['last_update'] < cutoff
        ]
        for ip in expired:
            del self._scores[ip]


# Track IPs that have passed challenges (session-like)
class ChallengeSession:
    """Tracks IPs that have successfully passed challenges"""
    
    def __init__(self, session_duration: int = 3600):
        """
        Args:
            session_duration: How long a passed challenge is valid (default: 1 hour)
        """
        self.session_duration = session_duration
        self._verified: Dict[str, float] = {}
    
    def mark_verified(self, ip: str):
        """Mark an IP as having passed the challenge"""
        self._verified[ip] = time.time() + self.session_duration
    
    def is_verified(self, ip: str) -> bool:
        """Check if an IP has a valid challenge session"""
        if ip not in self._verified:
            return False
        
        if time.time() > self._verified[ip]:
            del self._verified[ip]
            return False
        
        return True
    
    def cleanup_expired(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired = [ip for ip, expires in self._verified.items() if current_time > expires]
        for ip in expired:
            del self._verified[ip]
