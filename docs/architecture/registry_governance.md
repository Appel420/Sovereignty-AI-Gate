# Registry Governance

The `BoundaryRegistry` is the authoritative source of truth for active model boundaries.

## Governance Rules

1. **No conversion.** A boundary's type cannot change after registration.
2. **Creator lock.** A boundary's `creator_id` cannot change after registration.
3. **Unique IDs.** `boundary_id` values are unique within a registry.
4. **Deactivation.** Boundaries can be deactivated but not deleted.

## Snapshot

The registry exposes a `snapshot()` method that returns a serializable list of all
records. This snapshot can be included in an export bundle.
