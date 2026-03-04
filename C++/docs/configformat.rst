================================================================================
POLICY CONFIGURATION FORMAT SPECIFICATION
================================================================================

SYNTAX
------

config      ::= section+

section     ::= api_section | rules_section

api_section ::= "API_URL:" whitespace? url
              | "API_HEADER:" whitespace? header

rules_section ::= rule+

rule        ::= command ":" whitespace? argument

command     ::= "D" | "E" | "IF" | "EE" | "ES"

argument    ::= path | list | extension | suffix

path        ::= absolute_path
list        ::= item ("," item)*
extension   ::= "." extension_name
suffix      ::= suffix_name

absolute_path must start with "/"
whitespace after colon is optional


API CONFIGURATION
-----------------

API_URL: <url>
    Endpoint used for sending policy results, reports, or telemetry.

API_HEADER: <key>=<value>
    HTTP header included in API requests.
    Multiple headers may be specified using multiple API_HEADER entries.


RULE COMMANDS
-------------

D: <path>
    Include directory (recursive) or include a single file.

E: <path>
    Exclude directory (recursive). Entire subtree skipped during traversal.

IF: <path>
    Force include file or directory. Overrides all exclusions.

EE: <ext>
    Exclude file extensions (must include dot, e.g. ".log").

ES: <suffix>
    Exclude filename suffixes before extension (no dot).


PRECEDENCE
----------

IF > E > EE > ES > D > default(exclude)

Evaluation terminates on the first match within each precedence level.


API HEADER FORMAT
-----------------

Header syntax:

API_HEADER: Header-Name=Header-Value

Examples:

API_HEADER: Authorization=Bearer abc123
API_HEADER: Content-Type=application/json
API_HEADER: X-Agent-ID=node-01


EXAMPLE
-------

API_URL: https://security.example.com/v1/policy/report
API_HEADER: Authorization=Bearer abc123
API_HEADER: Content-Type=application/json
API_HEADER: X-Agent-ID=host-01

D: /opt/app
E: /opt/app/cache
EE: .log
ES: _old
IF: /opt/app/cache/critical.log


PROCESSING ORDER
----------------

1. Load API configuration (URL and headers).
2. Parse rule entries sequentially.
3. Apply rule precedence during filesystem evaluation.
4. Send results to API endpoint using configured headers.


NOTES
-----

- Unknown commands must be rejected during parsing.
- Paths must be absolute.
- Extension rules require a leading dot.
- Suffix rules must not contain dots.
- Multiple API headers are allowed.
- Duplicate rules should be resolved based on precedence.

================================================================================
END OF SPECIFICATION
================================================================================