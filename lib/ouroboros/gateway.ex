defmodule Ouroboros.Gateway do
  @moduledoc """
  The operator surface: a token-authenticated, loopback-default line protocol over TCP.

  This is not "an observer". It is the seam a terminal client attaches to, and Slice 2
  gives it mutating verbs, so it is described the way an operator console is described
  and configured the way one should be: off unless asked for, refusing to start without a
  credential, and on this host unless someone typed otherwise.

  ## Fail closed at init

  `init/1` builds an `Ouroboros.Gateway.Config` before it names a single child. A gateway
  that was enabled without a token source, or without `OUROBOROS_DATA_DIR`, or bound off
  this host without `OUROBOROS_GATEWAY_ALLOW_REMOTE=1`, raises here with the variable
  named — the same posture `Ouroboros.Upgrade.Signing.Service` takes toward a signer node
  with no key. A listener that starts anyway and refuses per connection looks, from the
  outside, exactly like a listener that is deliberately refusing, and those two need very
  different operator responses.

  ## Shape

      Ouroboros.Gateway                (rest_for_one)
      ├─ Task.Supervisor               request handlers, one task per in-flight call
      ├─ DynamicSupervisor             one Conn per connection, capped
      └─ Gateway.Listener              binds, publishes gateway.json, accepts

  `rest_for_one`, in that order, because a `Conn` needs both supervisors to exist before
  a socket can be handed to it: losing either one has to stop the listener rather than
  leave it accepting sockets it cannot place.

  ## Placement

  Started only on a `:core` node in the independent surface subtree. Nothing rebuilds
  durable state from it, so replacing it after its restart budget is exhausted leaves
  unrelated helpers alive. `:builder` and `:signer` nodes never run it.

  ## Honest limits

  The token is transport authentication, not a sandbox. Loopback is the boundary that
  does the real work, and remote attach is meant to be an SSH tunnel; the cleartext
  override exists and says so in its own refusal message. Payloads carry whatever the
  planes carry — workspace paths, objectives, provider names — which is the operator's
  own trust domain, and no more redacted here than it is there. This is a single-node
  view: it reports the node it runs on plus whatever `Ouroboros.status/0` knows about the
  cluster.
  """

  use Supervisor

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Listener

  # A terminal client opens one connection. This bounds what an unauthenticated peer can
  # cost before the handshake deadline reaps it, which the token cannot.
  @max_connections 64

  @doc """
  Starts the gateway.

  Options are for tests and for an operator supplying configuration another way:
  `:name`, `:config`, `:listener`, `:conn_supervisor`, `:task_supervisor`. The application
  passes `:ready_application` to defer handshakes until OTP completes startup. Configuration
  omitted here comes from application environment, which `config/runtime.exs` writes.
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(opts) do
    config = Keyword.get_lazy(opts, :config, &Config.load!/0)
    conn_supervisor = Keyword.get(opts, :conn_supervisor, __MODULE__.ConnSupervisor)
    task_supervisor = Keyword.get(opts, :task_supervisor, __MODULE__.TaskSupervisor)

    children = [
      {Task.Supervisor, name: task_supervisor},
      {DynamicSupervisor,
       strategy: :one_for_one, name: conn_supervisor, max_children: @max_connections},
      {Listener,
       name: Keyword.get(opts, :listener, Listener),
       ready_application: Keyword.get(opts, :ready_application),
       config: config,
       conn_supervisor: conn_supervisor,
       task_supervisor: task_supervisor}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end
end
