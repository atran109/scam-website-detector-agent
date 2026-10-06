"""Navigator system prompt and goal (DESIGN §5.5 "Goal prompt").

The prompt explains the task; it is not a safety layer. Every rule that matters (no payments, no
signing, same site only, placeholders only) is enforced in policy.py whatever the model writes."""

GOAL = (
    "Reveal every cryptocurrency deposit address this site shows to a registered user "
    "(each coin and network on its deposit page)."
)
