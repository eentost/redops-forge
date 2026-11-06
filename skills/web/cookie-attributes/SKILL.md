# Cookie Attribute Review
Status: active · Mode: passive · Risk: low

Inspect Set-Cookie metadata for Secure (when HTTPS), HttpOnly and SameSite. Do not retain cookie values, session tokens, or raw Set-Cookie header strings. Record cookie name and missing attributes only. Treat findings as configuration observations requiring application-context review.
