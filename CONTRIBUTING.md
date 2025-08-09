# Contributing to HTX

Thank you for your interest in contributing to HTX! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- A GitHub account

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/[your-username]/htx
   cd htx
   ```

2. **Install Rust** (if not already installed)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. **Install Nightly** (for fuzz testing)
   ```bash
   rustup install nightly
   ```

4. **Run Tests**
   ```bash
   cargo test
   cargo test --test integration
   ```

5. **Check Code Quality**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   ```

## 📋 Development Workflow

### Branch Naming
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `test/description` - Test improvements

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new access ticket carrier type
fix: resolve race condition in flow control
docs: update API documentation
test: add integration test for noise handshake
```

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write code following project conventions
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Thoroughly**
   ```bash
   # Unit tests
   cargo test

   # Integration tests
   cargo test --test integration

   # Fuzz tests (if applicable)
   cargo +nightly fuzz run fuzz_frame_parsing -- -max_total_time=60
   ```

4. **Format and Lint**
   ```bash
   cargo fmt
   cargo clippy --fix
   ```

5. **Commit and Push**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   git push origin feature/your-feature-name
   ```

6. **Open Pull Request**
   - Provide clear description of changes
   - Link any related issues
   - Request review from maintainers

## 🧪 Testing Guidelines

### Types of Tests

1. **Unit Tests**: Test individual functions and modules
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;

       #[test]
       fn test_feature() {
           // Test implementation
       }
   }
   ```

2. **Integration Tests**: Test complete workflows
   ```rust
   #[tokio::test]
   async fn test_client_server_integration() {
       // Integration test implementation
   }
   ```

3. **Fuzz Tests**: Test edge cases and robustness
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;

   fuzz_target!(|data: &[u8]| {
       // Fuzz test implementation
   });
   ```

### Test Requirements

- All new features must include tests
- Bug fixes must include regression tests
- Tests should cover both success and error cases
- Integration tests for API changes
- Fuzz tests for parsing/serialization code

## 📝 Code Style

### Rust Guidelines

Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

- Use `rustfmt` for formatting
- Follow naming conventions (`snake_case`, `PascalCase`)
- Document public APIs with `///` comments
- Use `#[must_use]` for important return values
- Handle errors explicitly

### Documentation

- All public APIs must be documented
- Include examples in documentation
- Update README.md for new features
- Add inline comments for complex logic

### Example Documentation

```rust
/// Creates a new HTX client with the specified configuration.
///
/// # Arguments
///
/// * `config` - The client configuration
///
/// # Returns
///
/// Returns a `Result<HtxClient, HtxError>` containing the client or an error.
///
/// # Examples
///
/// ```rust
/// use htx::{HtxClient, Config};
///
/// # #[tokio::main]
/// # async fn main() -> htx::Result<()> {
/// let config = Config::default();
/// let client = HtxClient::new(config).await?;
/// # Ok(())
/// # }
/// ```
pub async fn new(config: Config) -> Result<Self> {
    // Implementation
}
```

## 🔒 Security Considerations

### Cryptographic Code

- Never implement custom cryptography
- Use well-established libraries (ring, rustls, snow)
- Follow secure coding practices
- Test for timing attacks where applicable
- Use constant-time operations for sensitive comparisons

### Error Handling

- Don't leak sensitive information in error messages
- Use proper error types with context
- Log security events appropriately
- Handle all edge cases

### Dependencies

- Keep dependencies minimal and up-to-date
- Review security advisories regularly
- Use `cargo audit` to check for vulnerabilities

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Clear Description**: What happened vs. what was expected
2. **Reproduction Steps**: Minimal example to reproduce the bug
3. **Environment**: OS, Rust version, crate version
4. **Logs**: Relevant log output with `RUST_LOG=debug`
5. **Impact**: How the bug affects functionality

### Bug Report Template

```markdown
## Bug Description
Brief description of the bug.

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- OS: [e.g., Linux, macOS, Windows]
- Rust version: [e.g., 1.70.0]
- HTX version: [e.g., 1.1.0]

## Additional Context
Any other context about the problem.
```

## 💡 Feature Requests

For new features:

1. **Search Existing Issues**: Check if already requested
2. **Describe Use Case**: Explain the problem you're solving
3. **Propose Solution**: Suggest implementation approach
4. **Consider Alternatives**: What other solutions exist?
5. **Breaking Changes**: Note any compatibility concerns

## 📚 Resources

### Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [Async Rust](https://rust-lang.github.io/async-book/)
- [Betanet Specification](https://ravendevteam.org/betanet/)

### Tools
- [rustfmt](https://github.com/rust-lang/rustfmt) - Code formatting
- [clippy](https://github.com/rust-lang/rust-clippy) - Linting
- [cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit) - Security auditing
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) - Fuzz testing

## 🙏 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes for significant contributions
- GitHub repository insights

## 📞 Questions?

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and ideas
- **Discord**: Join the [Betanet Discord](https://discord.gg/H7gdjZjVeH)

---

Thank you for contributing to HTX and the Betanet ecosystem! 🎉
