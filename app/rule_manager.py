"""
Dynamic Rule Manager v1.0
=========================
Manages WAF detection rules with:
- Hot-reload without restart (API trigger + file watcher)
- Rule validation before application (regex compilation check)
- Thread-safe atomic rule swapping
- Rule versioning with rollback
- Rule statistics (hit count per rule)

Architecture:
    RuleManager owns the rules. WAFEngine queries RuleManager for
    compiled patterns instead of loading them directly.
"""
import os
import re
import json
import time
import hashlib
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field


@dataclass
class Rule:
    """A single detection rule with metadata"""
    id: str
    category: str
    pattern: str
    compiled: Optional[re.Pattern] = None
    enabled: bool = True
    severity: str = "medium"
    confidence: float = 0.9
    description: str = ""
    tags: List[str] = field(default_factory=list)
    action: str = "block"  # block, challenge, log
    hit_count: int = 0

    def compile(self) -> bool:
        """Attempt to compile the regex pattern. Returns True on success."""
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
            return True
        except re.error:
            return False


@dataclass
class RuleSet:
    """A versioned collection of rules"""
    version: str
    loaded_at: float
    rules_by_category: Dict[str, List[Rule]] = field(default_factory=dict)
    compiled_patterns: Dict[str, List[re.Pattern]] = field(default_factory=dict)
    file_hash: str = ""
    total_rules: int = 0

    def get_categories(self) -> List[str]:
        return list(self.rules_by_category.keys())


class RuleValidationError(Exception):
    """Raised when rule validation fails"""
    pass


class RuleManager:
    """
    Thread-safe rule manager with hot-reload and validation.

    Usage:
        manager = RuleManager(rules_path="app/rules.json")
        manager.load_rules()

        # Get compiled patterns for a category
        patterns = manager.get_patterns("sql_injection")

        # Hot-reload
        success, errors = manager.reload_rules()

        # Rollback
        manager.rollback()
    """

    MAX_VERSIONS = 5  # Keep this many old versions for rollback

    def __init__(
        self,
        rules_path: str = None,
        on_reload: Optional[Callable] = None,
        auto_watch: bool = False,
        watch_interval: float = 5.0,
    ):
        """
        Args:
            rules_path: Path to rules.json
            on_reload: Callback function called after successful reload
            auto_watch: Enable file-system watcher for auto-reload
            watch_interval: Seconds between file change checks
        """
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        self.rules_path = rules_path
        self._on_reload = on_reload
        self._lock = threading.RLock()

        # Current active ruleset (atomic reference)
        self._active: Optional[RuleSet] = None

        # Version history for rollback
        self._history: List[RuleSet] = []

        # Rule hit counts (survives reloads)
        self._hit_counts: Dict[str, int] = {}

        # File watcher
        self._watcher_thread: Optional[threading.Thread] = None
        self._watcher_stop = threading.Event()
        self._watch_interval = watch_interval

        if auto_watch:
            self.start_watcher()

    # =========================================================================
    # Rule Loading
    # =========================================================================

    def load_rules(self) -> RuleSet:
        """
        Load rules from the JSON file. Called at startup.
        Raises FileNotFoundError or RuleValidationError on failure.
        """
        raw_data = self._read_rules_file()
        ruleset = self._parse_and_validate(raw_data)

        with self._lock:
            self._active = ruleset

        return ruleset

    def reload_rules(self) -> tuple:
        """
        Hot-reload rules from disk.
        Validates before swapping to prevent bad rules from taking effect.

        Returns:
            (success: bool, errors: List[str])
        """
        try:
            raw_data = self._read_rules_file()
        except Exception as e:
            return False, [f"Failed to read rules file: {e}"]

        # Check if file actually changed
        new_hash = self._compute_hash(json.dumps(raw_data, sort_keys=True))
        if self._active and self._active.file_hash == new_hash:
            return True, ["No changes detected"]

        try:
            new_ruleset = self._parse_and_validate(raw_data)
        except RuleValidationError as e:
            return False, [str(e)]

        with self._lock:
            # Save current to history for rollback
            if self._active:
                self._history.append(self._active)
                # Trim history
                if len(self._history) > self.MAX_VERSIONS:
                    self._history = self._history[-self.MAX_VERSIONS:]
            self._active = new_ruleset

        # Notify callback
        if self._on_reload:
            try:
                self._on_reload(new_ruleset)
            except Exception:
                pass

        return True, [
            f"Reloaded {new_ruleset.total_rules} rules "
            f"(v{new_ruleset.version})"
        ]

    def rollback(self) -> bool:
        """
        Rollback to the previous rule version.
        Returns True if rollback succeeded.
        """
        with self._lock:
            if not self._history:
                return False
            self._active = self._history.pop()
            return True

    # =========================================================================
    # Rule Access (thread-safe reads)
    # =========================================================================

    def get_patterns(self, category: str) -> List[re.Pattern]:
        """Get compiled patterns for a category"""
        ruleset = self._active  # atomic read
        if ruleset is None:
            return []
        return ruleset.compiled_patterns.get(category, [])

    def get_rules(self, category: str) -> List[Rule]:
        """Get rules for a category"""
        ruleset = self._active
        if ruleset is None:
            return []
        return ruleset.rules_by_category.get(category, [])

    def get_all_categories(self) -> List[str]:
        """Get all active rule categories"""
        ruleset = self._active
        if ruleset is None:
            return []
        return ruleset.get_categories()

    def get_scanner_patterns(self) -> List[re.Pattern]:
        """Get compiled scanner user-agent patterns"""
        ruleset = self._active
        if ruleset is None:
            return []
        return ruleset.compiled_patterns.get("scanner_user_agents", [])

    def record_hit(self, category: str, pattern: str):
        """Record a rule hit for statistics"""
        key = f"{category}:{pattern[:50]}"
        self._hit_counts[key] = self._hit_counts.get(key, 0) + 1

    def is_category_enabled(self, category: str) -> bool:
        """Check if a rule category is enabled"""
        ruleset = self._active
        if ruleset is None:
            return False
        rules = ruleset.rules_by_category.get(category, [])
        return len(rules) > 0

    # =========================================================================
    # Status & Info
    # =========================================================================

    def get_status(self) -> Dict[str, Any]:
        """Get current rule manager status"""
        ruleset = self._active
        return {
            "loaded": ruleset is not None,
            "version": ruleset.version if ruleset else None,
            "loaded_at": ruleset.loaded_at if ruleset else None,
            "total_rules": ruleset.total_rules if ruleset else 0,
            "categories": ruleset.get_categories() if ruleset else [],
            "history_depth": len(self._history),
            "file_path": self.rules_path,
            "watcher_active": (
                self._watcher_thread is not None
                and self._watcher_thread.is_alive()
            ),
            "top_hit_rules": dict(
                sorted(
                    self._hit_counts.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10]
            ),
        }

    # =========================================================================
    # File Watcher
    # =========================================================================

    def start_watcher(self):
        """Start background file watcher for auto-reload"""
        if self._watcher_thread and self._watcher_thread.is_alive():
            return

        self._watcher_stop.clear()
        self._watcher_thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="rule-watcher"
        )
        self._watcher_thread.start()

    def stop_watcher(self):
        """Stop the file watcher"""
        self._watcher_stop.set()
        if self._watcher_thread:
            self._watcher_thread.join(timeout=10)

    def _watch_loop(self):
        """Background loop checking for file changes"""
        last_mtime = 0.0
        try:
            last_mtime = os.path.getmtime(self.rules_path)
        except OSError:
            pass

        while not self._watcher_stop.is_set():
            self._watcher_stop.wait(self._watch_interval)
            if self._watcher_stop.is_set():
                break

            try:
                current_mtime = os.path.getmtime(self.rules_path)
                if current_mtime > last_mtime:
                    last_mtime = current_mtime
                    success, messages = self.reload_rules()
                    if success:
                        print(f"[RuleManager] Auto-reloaded: {messages}")
                    else:
                        print(f"[RuleManager] Auto-reload failed: {messages}")
            except OSError:
                pass

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _read_rules_file(self) -> Dict:
        """Read and parse the rules JSON file"""
        if not os.path.exists(self.rules_path):
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with open(self.rules_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _parse_and_validate(self, raw_data: Dict) -> RuleSet:
        """
        Parse raw JSON into a validated RuleSet.
        Compiles all regex patterns and rejects invalid ones.
        """
        version = raw_data.get("version", "unknown")
        file_hash = self._compute_hash(json.dumps(raw_data, sort_keys=True))

        ruleset = RuleSet(
            version=version,
            loaded_at=time.time(),
            file_hash=file_hash,
        )

        errors = []
        total_count = 0

        for category, data in raw_data.items():
            # Skip metadata fields
            if category in ("version", "last_updated", "metadata"):
                continue

            if not isinstance(data, dict):
                continue

            if not data.get("enabled", True):
                continue

            rules = []
            patterns = data.get("patterns", [])
            user_agents = data.get("user_agents", [])

            # Process regular patterns
            for i, pattern_str in enumerate(patterns):
                rule = Rule(
                    id=f"{category}_{i}",
                    category=category,
                    pattern=pattern_str,
                    severity=data.get("severity", "medium"),
                    confidence=data.get("confidence", 0.9),
                    description=data.get("description", ""),
                    tags=data.get("tags", []),
                )

                if rule.compile():
                    rules.append(rule)
                    total_count += 1
                else:
                    errors.append(
                        f"Invalid regex in {category}[{i}]: {pattern_str[:50]}"
                    )

            if rules:
                ruleset.rules_by_category[category] = rules
                ruleset.compiled_patterns[category] = [
                    r.compiled for r in rules if r.compiled
                ]

            # Process user agents (scanner detection)
            if user_agents:
                ua_patterns = []
                for ua in user_agents:
                    try:
                        compiled = re.compile(ua, re.IGNORECASE)
                        ua_patterns.append(compiled)
                        total_count += 1
                    except re.error:
                        errors.append(
                            f"Invalid UA pattern: {ua[:50]}"
                        )

                if ua_patterns:
                    ruleset.compiled_patterns["scanner_user_agents"] = ua_patterns

        if errors:
            print(
                f"[RuleManager] {len(errors)} pattern errors during load: "
                f"{errors[:3]}"
            )

        ruleset.total_rules = total_count
        return ruleset

    @staticmethod
    def _compute_hash(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:16]
