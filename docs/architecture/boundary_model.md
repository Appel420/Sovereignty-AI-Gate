# Boundary Model

A boundary is the fundamental unit of authority in SIA. It defines what a model is
permitted to do and who owns that permission grant.

## Boundary Types

| Type | Description |
|------|-------------|
| `creator` | The model that created the boundary; root of a trust sub-tree |
| `transformer` | May transform data within its scope; cannot create sub-boundaries |
| `reader` | Read-only access to scoped resources |
| `delegate` | Receives delegated authority from a parent boundary |

## Immutability Rules

1. `creator_id` is set at registration and NEVER changes.
2. `boundary_type` is set at registration and CANNOT be converted.
3. `boundary_id` is unique within a registry and CANNOT be reused after deactivation.

## Scope

A scope is a list of action strings. Wildcards (`*`) match any action. Delegated scope
MUST be a strict subset of the delegating boundary's scope.
