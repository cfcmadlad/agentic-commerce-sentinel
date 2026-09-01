# What this project actually is

A short, plain-language orientation for anyone opening this repository cold. `README.md` is the full technical writeup; this page exists so you don't have to read all of it just to understand what you're looking at.

## The problem, in one example

Say you tell a shopping app running on your behalf, "spend up to ₹2,000 a month on groceries." Every month it buys groceries, exactly as agreed.

Then one month it spends ₹8,000 on electronics instead.

Nothing about that transaction looks wrong to a normal fraud system. The card is real. The merchant is real. The device is real. No credentials were stolen. Every signal a bank or payments company normally checks comes back clean, because the failure isn't "someone stole your money." It's "the agent you authorized did something you never authorized it to do."

That gap, an AI agent acting for a human and quietly stepping outside the boundaries it was actually given, is what this project checks for. Not "is this transaction fraudulent," but "is this agent still doing what it was told it could do."

## Why this is a new problem, not an old one with a new label

Until recently, a human clicked "buy" on every purchase, so "is this transaction legitimate" and "did a human agree to this" were the same question. Agentic commerce breaks that: Razorpay and NPCI have already launched AI agents that can complete UPI payments without a human confirming each one. Once an agent can spend on its own, "did a human agree to this specific purchase" stops being answerable by watching the card, the device, or the merchant. It requires actually checking the agent's authorization against what it's doing, a question existing fraud infrastructure was never built to ask.

## What's actually built to check this

Every agent action here has to carry a **mandate**, a cryptographically signed record of what a human actually authorized: how much, at which merchants, in which categories, for how long. The system checks a proposed transaction against that mandate through several independent layers, each catching a different way an agent could drift outside what it was given:

- **Is the authorization itself real?** Checks the signature, the expiry, whether it's already been used up.
- **Does this specific transaction fit inside it?** Right amount, right merchant, right category, right time window, checked exactly, with no tolerance band an agent could quietly exploit.
- **If this authorization was handed down from a broader one, did the hand-off stay narrower than what it came from?** A delegated authorization can only shrink what it grants, never grow it, and this is checked explicitly rather than assumed.
- **Does this agent's behavior actually look like the agent it claims to be?** Some violations don't show up in any single rule, like an agent using a genuine, in-scope authorization, just faster and more mechanically than a human-directed one would. A behavioral layer, trained only on the cases the rule-based checks above already miss, exists specifically for this.
- **Are several "independent" agents secretly acting together?** An operator could spread one large, unauthorized action across many small identities so that no single one looks suspicious. This is checked by looking across sessions and agents at once, not just within one.
- **Can some of the rules above be proven correct, not just tested?** For the parts of this system that are pure logic rather than learned behavior, an automated solver checks every possible input in the relevant range, not just the specific cases a test suite happened to think of. The system was deliberately fed a real, plausible bug to confirm the check actually catches something, not just that it stays quiet.

Every decision, allowed or blocked, is written to a record that explains, in plain language, why.

## The part most projects like this would rather not show you

This system was tested against a kind of attack it was deliberately never trained or tuned on, to see how it would actually perform against something genuinely new, and the first version missed nearly all of it. That result, and every other real limitation and boundary condition found while building this, is reported directly rather than smoothed over: see `EXCEPTIONS.md` for the specific, reproducible list, and the `docs/adr/` folder for the reasoning behind each one, including the ones that didn't work as well as hoped on the first attempt.

The instinct on finding a gap like that is to go quietly patch it and never mention it happened. This project's standing rule is the opposite: measure it, report it exactly as measured, and treat closing it as its own deliberate, disclosed piece of work rather than something to paper over before anyone notices.

## Where to go from here

- **`README.md`**, the full technical writeup: architecture, every layer's exact logic, the evaluation methodology, and the complete results.
- **`EXCEPTIONS.md`**, every category of case this system cannot yet confidently classify, named specifically rather than gestured at.
- **`docs/adr/`**, the design decisions that shaped this, including the ones driven by a result that didn't go as expected.
- **The live site**, a hosted, interactive version: real evaluation data, a sandbox to build a mandate and a transaction yourself and see the verdict live, and a walkthrough of what each layer actually does.

Nothing in this repository is real payment infrastructure. Every session, mandate, and signing key here is synthetic, generated for this project alone, and none of it is usable against any real system.
