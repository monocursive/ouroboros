defmodule Ouroboros.Test.SessionTransport do
  @moduledoc """
  Deterministic interactive session transport that declares steering support.

  The transport `Ouroboros.Test.HarnessAdapter` declares. A session started on it accepts
  a steer without any provider process: the session worker itself appends the synchronous
  `input_accepted` event, so everything downstream of acceptance is real. It also answers
  an approval, because a transport with no approvals channel cannot be started under the
  plane's default `approval_mode: :prompt`.

  Turn mechanics delegate to `Jido.Harness.SessionAdapters.Managed`, so one emit/finish
  controller drives every session in the suite (`test_pid` receives the started adapter).
  """

  @behaviour Jido.Harness.SessionAdapter

  @impl true
  defdelegate open(request, context), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate send(handle, request, turn_id), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate interrupt(handle, turn_id), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  defdelegate close(handle), to: Jido.Harness.SessionAdapters.Managed

  @impl true
  def configure(handle, changes),
    do: Jido.Harness.SessionAdapters.Managed.configure(handle, changes)

  # A real provider transport would forward the steered text to its process here. The
  # worker has already recorded acceptance, which is the part these tests observe.
  @impl true
  def steer(_handle, _request, _request_id), do: :ok

  # Declared for the same reason as `steer/3`: a transport with no approvals channel is
  # refused under the plane's default `approval_mode: :prompt`, because it would accept
  # the option and then have nobody to ask.
  @impl true
  def respond_approval(_handle, _request_id, _response), do: :ok
end
