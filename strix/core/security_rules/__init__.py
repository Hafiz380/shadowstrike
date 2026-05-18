"""
Multi-Language Security Rules
==============================
Inspired by ECC's rules system. Provides security-focused coding rules
for 12+ languages that guide code analysis agents.

Each rule set covers:
- Language-specific security patterns
- Common vulnerability patterns
- Secure coding best practices
- Framework-specific rules (FastAPI, Django, Spring Boot, etc.)
"""

RULES = {
    "common": {
        "secrets_management": [
            "Never hardcode API keys, tokens, or passwords in source code",
            "Use environment variables or secret managers for all credentials",
            "Rotate secrets regularly and audit access logs",
            "Never log or expose secrets in error messages",
            "Use .env files for local development, never commit them",
        ],
        "input_validation": [
            "Validate ALL user input at the boundary (API gateway, controller)",
            "Use allowlists over denylists for validation",
            "Validate type, length, range, and format",
            "Sanitize input before rendering in HTML context",
            "Use parameterized queries for ALL database operations",
        ],
        "authentication": [
            "Use established auth frameworks (OAuth2, OIDC, SAML)",
            "Implement MFA for sensitive operations",
            "Use bcrypt/argon2id for password hashing, never MD5/SHA1",
            "Implement rate limiting on auth endpoints",
            "Use short-lived tokens with refresh mechanism",
        ],
        "authorization": [
            "Check authorization at every access point, not just the gateway",
            "Use RBAC/ABAC consistently across all endpoints",
            "Never rely on client-side authorization checks",
            "Validate object-level permissions (IDOR prevention)",
            "Log all authorization failures for audit",
        ],
        "error_handling": [
            "Never expose internal error details to users",
            "Use generic error messages for client-facing errors",
            "Log detailed errors server-side with correlation IDs",
            "Implement proper error boundaries in frontend",
            "Handle all exceptions explicitly, never swallow errors",
        ],
    },
    "python": {
        "patterns": [
            "Use `secrets` module for cryptographic operations, not `random`",
            "Use `defusedxml` for XML parsing to prevent XXE",
            "Use `bleach` or `markupsafe` for HTML sanitization",
            "Use `shlex.quote()` for shell command arguments",
            "Use parameterized queries with SQLAlchemy/psycopg2, never string formatting",
            "Use `subprocess.run()` with `shell=False` and list arguments",
            "Validate file paths with `os.path.realpath()` and check prefix",
            "Use `hmac.compare_digest()` for timing-safe string comparison",
        ],
        "django": [
            "Use Django's ORM for database queries (auto-parameterized)",
            "Use `{% autoescape %}` in templates (enabled by default)",
            "Use `@login_required` and `@permission_required` decorators",
            "Set `SECURE_*` settings for production (HSTS, cookies, etc.)",
            "Use Django's `UserCreationForm` for registration (validates properly)",
        ],
        "fastapi": [
            "Use Pydantic models for ALL request/response validation",
            "Use `Depends()` for authentication and authorization",
            "Use async database clients from async endpoints",
            "Never create sessions inside route handlers",
            "Use `HTTPBearer` or `OAuth2PasswordBearer` for auth",
        ],
        "flask": [
            "Use Flask-WTF for form validation and CSRF protection",
            "Use `flask-login` or `flask-jwt-extended` for auth",
            "Set `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`",
            "Use `werkzeug.security` for password hashing",
            "Use parameterized queries with Flask-SQLAlchemy",
        ],
    },
    "javascript": {
        "patterns": [
            "Use `textContent` instead of `innerHTML` for user data",
            "Use DOMPurify for HTML sanitization",
            "Use parameterized queries with ORM (Prisma, Sequelize, TypeORM)",
            "Use `helmet` middleware for security headers in Express",
            "Use `express-rate-limit` for rate limiting",
            "Validate input with `zod`, `joi`, or `yup`",
            "Use `crypto.timingSafeEqual()` for string comparison",
            "Set `httpOnly`, `secure`, `sameSite` on cookies",
        ],
        "react": [
            "Never use `dangerouslySetInnerHTML` with user data",
            "Use React's auto-escaping (JSX handles XSS by default)",
            "Validate props with PropTypes or TypeScript",
            "Use `encodeURIComponent` for URL parameters",
            "Implement CSP headers for XSS mitigation",
        ],
        "nextjs": [
            "Use Server Components for sensitive data (never exposed to client)",
            "Use `next-auth` for authentication",
            "Validate API routes with zod schemas",
            "Use `headers()` for security header management",
            "Use middleware for auth checks on protected routes",
        ],
    },
    "typescript": {
        "patterns": [
            "Use TypeScript strict mode (`strict: true` in tsconfig)",
            "Use branded types for sensitive data (IDs, tokens)",
            "Use `zod` for runtime validation alongside TypeScript types",
            "Never use `as any` or type assertions for security-critical code",
            "Use `Readonly<T>` for immutable data structures",
        ],
    },
    "java": {
        "patterns": [
            "Use PreparedStatement for ALL SQL queries",
            "Use Spring Security for authentication/authorization",
            "Use `@Valid` annotation for request validation",
            "Use OWASP Java Encoder for output encoding",
            "Use `java.security.SecureRandom` for random generation",
            "Set `HttpOnly`, `Secure` flags on session cookies",
            "Use Jackson with `FAIL_ON_UNKNOWN_PROPERTIES` enabled",
        ],
        "springboot": [
            "Use `@PreAuthorize` or `@Secured` for method-level security",
            "Use Spring Security's CSRF protection (enabled by default)",
            "Use `@Validated` on controller parameters",
            "Configure security headers via `SecurityFilterChain`",
            "Use `BCryptPasswordEncoder` for password hashing",
        ],
    },
    "go": {
        "patterns": [
            "Use `html/template` for HTML rendering (auto-escaping)",
            "Use parameterized queries with `database/sql`",
            "Use `crypto/rand` for random generation, not `math/rand`",
            "Validate file paths with `filepath.Clean()` and check prefix",
            "Use `gorilla/csrf` for CSRF protection",
            "Set appropriate timeouts on HTTP clients and servers",
            "Use `golang.org/x/crypto/bcrypt` for password hashing",
        ],
    },
    "php": {
        "patterns": [
            "Use PDO with prepared statements for ALL database queries",
            "Use `htmlspecialchars()` for output encoding",
            "Use `filter_input()` for input validation",
            "Use `password_hash()` and `password_verify()` for passwords",
            "Set `session.cookie_httponly` and `session.cookie_secure`",
            "Use `random_bytes()` for random generation",
            "Never use `eval()`, `exec()`, `system()`, `shell_exec()` with user input",
        ],
        "laravel": [
            "Use Eloquent ORM for database queries (auto-parameterized)",
            "Use Blade's `{{ }}` for auto-escaping (not `{!! !!}`)",
            "Use Laravel's built-in validation (`$request->validate()`)",
            "Use `bcrypt()` or `Hash::make()` for passwords",
            "Use Laravel Sanctum or Passport for API auth",
        ],
    },
    "rust": {
        "patterns": [
            "Use `serde` with `#[deny_unknown_fields)]` for deserialization",
            "Use `sqlx` with compile-time checked queries",
            "Use `ring` or `rustls` for cryptographic operations",
            "Validate all external input at system boundaries",
            "Use `std::time::Instant` for timing, not system time",
        ],
    },
    "ruby": {
        "patterns": [
            "Use ActiveRecord's parameterized queries (auto-sanitized)",
            "Use ERB's `<%= %>` for auto-escaping (not `<%== %>`)",
            "Use `strong_parameters` in Rails controllers",
            "Use `bcrypt` gem for password hashing",
            "Use `brakeman` for static security analysis",
            "Set `secure`, `httponly`, `same_site` on cookies",
        ],
    },
}


def get_rules(language: str = None) -> dict:
    """Get security rules for a language (or all if None)."""
    if language:
        return {language: RULES.get(language, {}), "common": RULES.get("common", {})}
    return RULES


def list_languages() -> list[str]:
    """List all supported languages."""
    return [k for k in RULES.keys() if k != "common"]


def get_patterns_for_file(file_path: str) -> list[str]:
    """Get relevant security patterns based on file extension."""
    ext_to_lang = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".go": "go",
        ".php": "php",
        ".rs": "rust",
        ".rb": "ruby",
    }

    from pathlib import Path

    ext = Path(file_path).suffix
    lang = ext_to_lang.get(ext, "common")

    rules = RULES.get(lang, {})
    common = RULES.get("common", {})

    patterns = []
    for category, items in rules.items():
        if isinstance(items, list):
            patterns.extend(items)
    for category, items in common.items():
        if isinstance(items, list):
            patterns.extend(items)

    return patterns
