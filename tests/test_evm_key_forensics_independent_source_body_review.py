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

    def test_signature_embedded_in_identifier_is_not_treated_as_function(self):
        decoy = b"fake" + FUNCTION_SIGNATURE + b" { decoy }"
        with self.assertRaisesRegex(ReviewError, "createSeed_signature_not_found"):
            extract_function(decoy)

    def test_ignores_braces_and_signature_inside_raw_string(self):
        raw = b'R"tag( } { ' + FUNCTION_SIGNATURE + b' { decoy } )tag"'
        source = FUNCTION_SIGNATURE + b" { const char *s = " + raw + b"; return 1; }"
        self.assertEqual(
            extract_function(source),
            b"{ const char *s = " + raw + b"; return 1; }",
        )

    def test_unterminated_raw_string_fails_closed(self):
        source = FUNCTION_SIGNATURE + b' { const char *s = R"tag( { }'
        with self.assertRaisesRegex(ReviewError, "unterminated_raw_string_literal"):
            extract_function(source)

    def test_raw_string_signature_decoy_is_skipped_before_real_function(self):
        decoy = b'u8R"tag( ' + FUNCTION_SIGNATURE + b' { decoy } )tag"'
        source = b'const char *s = ' + decoy + b';\n' + FUNCTION_SIGNATURE + b' { return 7; }'
        self.assertEqual(extract_function(source), b"{ return 7; }")

    def test_raw_string_prefix_inside_identifier_does_not_hide_later_code(self):
        # The R in this identifier is not a raw-string token prefix.
        decoy = b'const char *s = fooR"tag( decoy )tag";\n'
        source = decoy + FUNCTION_SIGNATURE + b" { return 9; }"
        self.assertEqual(extract_function(source), b"{ return 9; }")

    def test_signature_without_opening_brace_fails_closed(self):
        with self.assertRaisesRegex(ReviewError, "createSeed_opening_brace_not_found"):
            extract_function(FUNCTION_SIGNATURE + b" // no body { hidden")

    def test_unbalanced_body_fails_closed(self):
        with self.assertRaisesRegex(ReviewError, "createSeed_unbalanced_braces"):
            extract_function(FUNCTION_SIGNATURE + b" { if (ready) { run(); }")


    def test_duplicate_code_signatures_fail_closed(self):
        source = (
            FUNCTION_SIGNATURE + b" { return 1; }\n"
            + FUNCTION_SIGNATURE + b" { return 2; }\n"
        )
        with self.assertRaisesRegex(ReviewError, "createSeed_signature_ambiguous"):
            extract_function(source)


if __name__ == "__main__":
    unittest.main()
