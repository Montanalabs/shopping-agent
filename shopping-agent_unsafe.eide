#! VULNERABLE shopping-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant placeOrder irreversible

let raw = fetch<web>
commit { placeOrder(raw) }  # tainted -> tool: REJECTED
