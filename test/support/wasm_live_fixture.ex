defmodule Ouroboros.Wasm.LiveFixture do
  @moduledoc """
  Whether this machine has the two built things the lane-W acceptance suites need — the
  `ouro-wasm` helper and the acceptance guest — and what a suite should do when it does not.

  Two answers, because there are two kinds of machine:

    * A **developer's**, where `make wasm` is an opt-in and a green run that skipped the
      acceptance tests is the honest outcome. The skip carries the reason and the `make`
      target, so a run that did not check the real wire says so.
    * **CI**, where a skip is the failure. The Elixir job builds both halves and sets
      `OUROBOROS_REQUIRE_WASM=1`; under it a missing helper or guest is a build that did not
      happen, and a suite that skipped it green is a suite that would have kept skipping
      after somebody deleted the build step. It did: twenty-five acceptance tests skipped on
      every hosted run of this workflow, and nothing said so.

  ## Why this is a function and not a `cond` in a module attribute

  Each suite computed its own tag inside a compile-time `cond`. That is evaluated when the
  `.exs` is loaded, which is once per `mix test` run — so it was never actually stale — but
  it *reads* as a compile-time decision, it is duplicated three times, and there is nowhere
  in it to put the "and in CI this is a failure" half. `tag/1` answers when it is asked;
  `ensure!/1` is the half a `setup_all` runs, after the skip decision, to turn a missing
  build into a failure with the same sentence on it.
  """

  @require "OUROBOROS_REQUIRE_WASM"

  @doc """
  The `@tag` an acceptance test should carry: `[]` to run, `[skip: reason]` to skip.

  `guest` is the path to the built acceptance component, or `nil` for a suite that needs
  only the helper. Never `[skip: …]` when the run requires a live helper — there the tests
  run and `ensure!/1` fails them, which is the difference between "we did not check" and
  "this run was supposed to check and could not".
  """
  @spec tag(String.t() | nil) :: keyword()
  def tag(guest \\ nil) do
    case missing(guest) do
      nil -> []
      reason -> if required?(), do: [], else: [skip: reason]
    end
  end

  @doc """
  Raises when this run requires a live helper and does not have one. `:ok` otherwise.

  Called from `setup_all`, so the failure lands on the suite that could not run rather than
  on the loading of a file — every other suite still runs, and the reason is the same
  sentence a developer's machine would have printed as a skip.
  """
  @spec ensure!(String.t() | nil) :: :ok
  def ensure!(guest \\ nil) do
    case missing(guest) do
      nil -> :ok
      reason -> if required?(), do: raise(reason), else: :ok
    end
  end

  @doc "Whether this run treats a missing helper or guest as a failure."
  @spec required?() :: boolean()
  def required? do
    case System.get_env(@require) do
      value when is_binary(value) -> String.trim(value) not in ["", "0", "false", "no"]
      nil -> false
    end
  end

  # The first thing that is not there, said the way the operator has to fix it.
  defp missing(guest) do
    cond do
      not Ouroboros.Wasm.available?() ->
        "no ouro-wasm at #{Ouroboros.Wasm.helper_path()}; run `make wasm` to check the " <>
          "real wire rather than a fake helper"

      is_binary(guest) and not File.regular?(guest) ->
        "no acceptance guest at #{guest}; run `make wasm-guest` (it needs " <>
          "`rustup target add wasm32-wasip2`) to check a real component rather than a " <>
          "scripted reply"

      true ->
        nil
    end
  end
end
