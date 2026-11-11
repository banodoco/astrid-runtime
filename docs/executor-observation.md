# Executor observation authority

`GET /v1/executors/{executor_id}` returns the existing complete registration
observation to an authenticated owner actor with `admin` scope, or to an
authenticated actor whose name exactly matches `executor_id` and whose scopes
explicitly include `worker:execute`. An unrelated administrator has no access.
The worker's access does not grant administrator authority or access to other
executors.
