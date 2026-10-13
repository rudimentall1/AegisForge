from __future__ import annotations

import unittest

from tools.evm_key_forensics.independent_source_body_review import (
    FUNCTION_SIGNATURE,
    ReviewError,
    extract_function,
)


class IndependentSourceBodyReviewTests(unittest.TestCase):
    def test_ignores_braces_in_comments_and_quoted_literals(self):
        source = (
            b"prefix "
            + FUNCTION_SIGNATURE
            + b" /* declaration note { */ { "
            + b'const char *s = "quoted } and { \\\""; '
            + b"char c = '}'; // ignored } {\n"
            + b"/* ignored { nested-looking } */ if (ready) { run(); } "
            + b"} trailing"
        )
        body = extract_function(source)
        marker = b" /* declaration note { */ "
        opening = source.index(b"{", source.index(marker) + len(marker))
        self.assertEqual(body, source[opening:source.index(b"} trailing") + 1])
        self.assertTrue(body.startswith(b"{"))
        self.assertTrue(body.endswith(b"}"))
        self.assertIn(b"if (ready) { run(); }", body)

    def test_signature_inside_comment_is_not_treated_as_function(self):
        commented = b"/* " + FUNCTION_SIGNATURE + b" { fake } */"
        with self.assertRaisesRegex(ReviewError, "createSeed_signature_not_found"):
            extract_function(commented)

    def test_skips_comment_signature_and_finds_real_function(self):
        source = (
            b"// " + FUNCTION_SIGNATURE + b" { fake }\n"
            + FUNCTION_SIGNATURE + b" { return value; }"
        )
        self.assertEqual(extract_function(source), b"{ return value; }")

    def test_signature_inside_string_is_not_treated_as_function(self):
        source = b'const char *s = "' + FUNCTION_SIGNATURE + b' { fake }";'
        with self.assertRaisesRegex(ReviewError, "createSeed_signature_not_found"):
            extract_function(source)

    def test_signature_without_opening_brace_fails_closed(self):
        with self.assertRaisesRegex(ReviewError, "createSeed_opening_brace_not_found"):
            extract_function(FUNCTION_SIGNATURE + b" // no body { hidden")

    def test_unbalanced_body_fails_closed(self):
        with self.assertRaisesRegex(ReviewError, "createSeed_unbalanced_braces"):
            extract_function(FUNCTION_SIGNATURE + b" { if (ready) { run(); }")


if __name__ == "__main__":
    unittest.main()
