# `:live_native` tests call a real model provider and cost real money. They are excluded
# from `mix test` and run only when asked for by name:
#
#     OUROBOROS_NATIVE_MODEL=anthropic:claude-sonnet-5 mix test --include live_native
#
# The tests themselves are only defined when that variable is set, so an operator who
# keeps it exported still does not pay for a plain `mix test`.
ExUnit.start(exclude: [:live_native])
