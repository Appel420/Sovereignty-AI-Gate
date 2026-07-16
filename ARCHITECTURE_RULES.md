1. Authority originates only in user identity.
2. Protected operations require verified capability.
3. Policy evaluation is mandatory.
4. Memory is data, not authority.
5. Providers are delegates.
6. Protected operations produce evidence.
7. Delegated capabilities cannot exceed issuer scope.
8. Provider Invocation Boundary: a provider invocation is an authority-controlled
   operation. Application code, plugins, and provider drivers must not directly
   instantiate or invoke a provider driver; all provider execution goes through
   `SovereignAuthority.call_provider_authorized()`. This boundary is enforced by
   runtime guards and conformance tests.
