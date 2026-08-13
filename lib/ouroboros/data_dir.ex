defmodule Ouroboros.DataDir do
  @moduledoc """
  Where this node keeps its durable state, decided from the environment alone.

  `config/runtime.exs` calls this and nothing else does, which is why it is a pure
  function over three strings rather than a reader of `System.get_env/1`: the production
  block of a config provider is the one place in this system that a normal test cannot
  enter, so the decision it makes is extracted here and tested directly.

  Nothing here reads application environment, starts a process, or touches another module
  of this application. A config provider runs before this application's modules are
  guaranteed loadable, and a module that pulled in more of the tree would fail a boot
  rather than a compile.

  ## The cross-language contract

  `tui/src/runtime.rs` (`Paths::discover`, `xdg_root`) derives the client's data directory
  from the same two variables, and the two must produce the same path byte for byte: the
  client spawns the daemon and then looks in that directory for the `gateway.json` the
  daemon publishes. A disagreement is not a wrong path, it is a client that starts a
  daemon it can never find.

  Both sides therefore treat a blank or relative `XDG_DATA_HOME` as unset — which is also
  what the XDG basedir specification says to do — and neither expands `~`. The one case
  where they differ is an unset `HOME`: the Rust side falls back to the passwd database,
  and this raises instead, because a config provider that guessed this directory wrong
  would write durable state where nobody looks for it.
  """

  # `ouro` joins the same leaf onto the same root; see `Paths::discover`. Its `--dev` mode
  # uses a different leaf, but that mode runs `mix run` rather than a release, so no
  # production boot ever derives it.
  @leaf "ouroboros"

  @doc """
  Resolves the data directory from `OUROBOROS_DATA_DIR`, `XDG_DATA_HOME`, and `HOME`.

  Each argument is the raw environment value or `nil`. A configured directory is used
  exactly as given and must be absolute: this is the root of every journal on the host,
  and a relative path would name a different directory for every working directory the
  daemon happens to be started from. Otherwise the XDG default applies —
  `$XDG_DATA_HOME/ouroboros` when that variable holds an absolute path, and
  `$HOME/.local/share/ouroboros` when it does not.
  """
  @spec resolve!(String.t() | nil, String.t() | nil, String.t() | nil) :: String.t()
  def resolve!(configured, xdg_data_home, home) do
    case present(configured) do
      nil ->
        default!(present(xdg_data_home), present(home))

      path ->
        unless Path.type(path) == :absolute do
          raise "OUROBOROS_DATA_DIR must be a nonblank absolute durable directory in production"
        end

        path
    end
  end

  defp default!(xdg, home) do
    cond do
      is_binary(xdg) and Path.type(xdg) == :absolute ->
        Path.join(xdg, @leaf)

      is_nil(home) ->
        raise "OUROBOROS_DATA_DIR is unset and so is HOME, so there is nowhere to keep this " <>
                "node's durable state. Set OUROBOROS_DATA_DIR to an absolute path, or run " <>
                "this release with a home directory."

      Path.type(home) != :absolute ->
        raise "OUROBOROS_DATA_DIR is unset and HOME=#{home} is not an absolute path, so the " <>
                "default data directory cannot be derived. Set OUROBOROS_DATA_DIR to an " <>
                "absolute path."

      true ->
        Path.join([home, ".local", "share", @leaf])
    end
  end

  defp present(nil), do: nil

  defp present(value) when is_binary(value) do
    if String.trim(value) == "", do: nil, else: value
  end
end
