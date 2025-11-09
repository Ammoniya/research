#!/usr/bin/env python3
"""
Enhanced Pattern Detection for WordPress Vulnerabilities

Improvements over basic approach:
1. Context-aware detection (checks if patterns are in same code block)
2. Separates primary vs incidental fixes
3. Better handling of multi-vulnerability scenarios
4. Reduces false positives
"""

import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

@dataclass
class EnhancedPattern:
    """Pattern with context information"""
    category: str
    function_name: str
    line_number: int
    context_lines: List[str]
    confidence: float  # 0.0 to 1.0

class EnhancedSignatureExtractor:
    """
    Improved signature extraction with better accuracy
    """

    def detect_patterns_with_context(self, diff_block: Dict) -> List[EnhancedPattern]:
        """
        Detect patterns with context awareness

        Returns patterns with confidence scores to reduce false positives
        """
        before_lines = diff_block['before'].split('\n')
        after_lines = diff_block['after'].split('\n')

        patterns = []

        # Analyze each line in the patched code
        for i, line in enumerate(after_lines):
            # Skip if line existed in before (not a new addition)
            if line.strip() in [l.strip() for l in before_lines]:
                continue

            # Check if it's actual code (not comment or string)
            if self._is_actual_code(line):
                detected = self._check_line_for_patterns(line, i, after_lines)
                patterns.extend(detected)

        return patterns

    def _is_actual_code(self, line: str) -> bool:
        """
        Check if line is actual code, not comment or string literal

        Reduces false positives from patterns in comments
        """
        stripped = line.strip()

        # Skip comments
        if stripped.startswith('//'):
            return False
        if stripped.startswith('*'):
            return False
        if stripped.startswith('/*'):
            return False

        # Skip obvious string literals (basic check)
        if stripped.startswith('"') and stripped.endswith('"'):
            return False
        if stripped.startswith("'") and stripped.endswith("'"):
            return False

        return True

    def _check_line_for_patterns(self, line: str, line_num: int,
                                  all_lines: List[str]) -> List[EnhancedPattern]:
        """
        Check a single line for security patterns

        Returns patterns with confidence scores
        """
        patterns = []

        # Authentication patterns
        if re.search(r'wp_verify_nonce\s*\(', line):
            # Higher confidence if it's in a conditional
            confidence = 0.9 if 'if' in line else 0.7
            patterns.append(EnhancedPattern(
                category='AUTH',
                function_name='wp_verify_nonce',
                line_number=line_num,
                context_lines=self._get_context(all_lines, line_num, 2),
                confidence=confidence
            ))

        if re.search(r'current_user_can\s*\(', line):
            confidence = 0.9 if 'if' in line or 'return' in line else 0.6
            patterns.append(EnhancedPattern(
                category='AUTH',
                function_name='current_user_can',
                line_number=line_num,
                context_lines=self._get_context(all_lines, line_num, 2),
                confidence=confidence
            ))

        # Sanitization patterns
        if re.search(r'sanitize_text_field\s*\(', line):
            # Higher confidence if assigned to variable
            confidence = 0.9 if '=' in line else 0.7
            patterns.append(EnhancedPattern(
                category='SANITIZE',
                function_name='sanitize_text_field',
                line_number=line_num,
                context_lines=self._get_context(all_lines, line_num, 2),
                confidence=confidence
            ))

        # Output escaping
        if re.search(r'esc_html\s*\(', line):
            # Higher confidence if in echo/print statement
            confidence = 0.9 if ('echo' in line or 'print' in line) else 0.7
            patterns.append(EnhancedPattern(
                category='OUTPUT_ESC',
                function_name='esc_html',
                line_number=line_num,
                context_lines=self._get_context(all_lines, line_num, 2),
                confidence=confidence
            ))

        # SQL security
        if re.search(r'\$wpdb->prepare\s*\(', line):
            confidence = 0.95  # Very reliable indicator
            patterns.append(EnhancedPattern(
                category='SQL_SECURITY',
                function_name='$wpdb->prepare',
                line_number=line_num,
                context_lines=self._get_context(all_lines, line_num, 2),
                confidence=confidence
            ))

        return patterns

    def _get_context(self, lines: List[str], target_line: int,
                     context_size: int) -> List[str]:
        """Get surrounding lines for context"""
        start = max(0, target_line - context_size)
        end = min(len(lines), target_line + context_size + 1)
        return lines[start:end]

    def categorize_fixes(self, patterns: List[EnhancedPattern],
                        vuln_type: str) -> Dict[str, List[EnhancedPattern]]:
        """
        Separate primary fixes from incidental fixes

        Primary = patterns that match the vulnerability type
        Incidental = other security improvements found
        """
        primary = []
        incidental = []

        # Define which patterns match which vulnerability types
        vuln_pattern_map = {
            'CSRF': ['AUTH'],
            'Missing Authorization': ['AUTH', 'CAPABILITY'],
            'Cross-Site Scripting': ['SANITIZE', 'OUTPUT_ESC'],
            'XSS': ['SANITIZE', 'OUTPUT_ESC'],
            'SQL Injection': ['SQL_SECURITY'],
            'Path Traversal': ['FILE_SECURITY'],
        }

        # Find expected categories for this vulnerability type
        expected_categories = []
        for vuln_keyword, categories in vuln_pattern_map.items():
            if vuln_keyword in vuln_type:
                expected_categories.extend(categories)

        # Categorize patterns
        for pattern in patterns:
            if pattern.category in expected_categories:
                primary.append(pattern)
            else:
                incidental.append(pattern)

        return {
            'primary': primary,
            'incidental': incidental
        }

    def generate_enhanced_signature(self, diff_blocks: List[Dict],
                                    vuln_type: str) -> Dict:
        """
        Generate signature with primary and incidental fixes separated
        """
        all_patterns = []

        for block in diff_blocks:
            patterns = self.detect_patterns_with_context(block)
            all_patterns.extend(patterns)

        # Filter low-confidence patterns
        high_confidence = [p for p in all_patterns if p.confidence >= 0.7]

        # Categorize
        categorized = self.categorize_fixes(high_confidence, vuln_type)

        return {
            'primary_fixes': [
                f"{p.category}:{p.function_name}"
                for p in categorized['primary']
            ],
            'incidental_fixes': [
                f"{p.category}:{p.function_name}"
                for p in categorized['incidental']
            ],
            'confidence_scores': {
                f"{p.category}:{p.function_name}": p.confidence
                for p in high_confidence
            },
            'all_patterns': [
                f"{p.category}:{p.function_name}"
                for p in high_confidence
            ]
        }


# Example usage demonstration
def demonstrate_enhanced_detection():
    """Show how enhanced detection works"""

    extractor = EnhancedSignatureExtractor()

    # Example 1: Pure CSRF fix
    diff_block_csrf = {
        'file': 'admin.php',
        'before': '''
function delete_user() {
    $user_id = $_POST['user_id'];
    wp_delete_user($user_id);
}
        ''',
        'after': '''
function delete_user() {
    if (!wp_verify_nonce($_POST['nonce'], 'delete_user')) {
        die('Security check failed');
    }
    $user_id = $_POST['user_id'];
    wp_delete_user($user_id);
}
        '''
    }

    result1 = extractor.generate_enhanced_signature(
        [diff_block_csrf],
        "Cross-Site Request Forgery (CSRF)"
    )

    print("Example 1: Pure CSRF Fix")
    print(f"  Primary fixes: {result1['primary_fixes']}")
    print(f"  Incidental fixes: {result1['incidental_fixes']}")
    print()

    # Example 2: CSRF + XSS fixed together
    diff_block_mixed = {
        'file': 'display.php',
        'before': '''
function show_message() {
    $msg = $_POST['message'];
    echo "<div>$msg</div>";
}
        ''',
        'after': '''
function show_message() {
    if (!wp_verify_nonce($_POST['nonce'], 'show_msg')) {
        die('Security check failed');
    }
    $msg = sanitize_text_field($_POST['message']);
    echo "<div>" . esc_html($msg) . "</div>";
}
        '''
    }

    result2 = extractor.generate_enhanced_signature(
        [diff_block_mixed],
        "Cross-Site Request Forgery (CSRF)"
    )

    print("Example 2: CSRF vulnerability, but XSS also fixed")
    print(f"  Primary fixes: {result2['primary_fixes']}")
    print(f"  Incidental fixes: {result2['incidental_fixes']}")
    print(f"  Confidence scores: {result2['confidence_scores']}")
    print()

    # Example 3: Same patch, classified as XSS
    result3 = extractor.generate_enhanced_signature(
        [diff_block_mixed],
        "Cross-Site Scripting (XSS)"
    )

    print("Example 3: Same patch, but vulnerability type is XSS")
    print(f"  Primary fixes: {result3['primary_fixes']}")
    print(f"  Incidental fixes: {result3['incidental_fixes']}")
    print()


if __name__ == "__main__":
    demonstrate_enhanced_detection()
