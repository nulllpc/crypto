# Cryptoy 

*A cypherpunk's playground for learning applied cryptography.*

**Cryptoy** is an educational monorepo dedicated to implementing cryptographic primitives, protocols, and attacks entirely from scratch in Rust (and potentially other languages). This isn't a production library—it's a glass box for breaking down how the math works and, more importantly, how it fails.

## Philosophy

Our development is guided by a strict set of cypherpunk rules (see [`AGENTS.md`](./AGENTS.md)):
1. **Explain, Don't Just Solve:** Focus on the mathematical "why" before the "how".
2. **From Scratch:** No heavy-duty cryptographic dependencies for core logic. We forge it ourselves.
3. **The Auditor Mindset:** Implement the algorithm, then attack it. We explicitly explore the gap between toy implementations and production-ready code by analyzing side-channels, padding oracles, and mathematical loopholes.
4. **Test-Driven:** We verify our raw implementations against standard test vectors.

## Projects

*   **`cryptopal/`**: Working through the Cryptopals Crypto Challenges in Rust.

## Disclaimer
> [!CAUTION]
> **DO NOT USE THIS CODE IN PRODUCTION.** 
> All code in this repository is strictly for educational purposes. The implementations are explicitly designed as "toys" to learn from and may intentionally or unintentionally lack constant-time execution, proper entropy, and protection against side-channel attacks.