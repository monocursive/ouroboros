defmodule Ouroboros.CodeIntel.Handle do
  @moduledoc """
  A ref-counted claim on one pooled language server.

  A handle is held by a process, not by a session: the pool monitors the owner and
  releases the claim when it dies, so a crashed session can never leave a server pinned.
  It carries no pid, because the server behind a key is replaced on restart and a handle
  that named a dead process would be a lie.

  `id` embeds `node()` because the pool is per-host and its status is projected across
  the fleet — two nodes can both hold a server for the same path, and they are not the
  same server.
  """

  @enforce_keys [:ref, :id, :node, :root, :server_id, :owner]
  defstruct [:ref, :id, :node, :root, :server_id, :owner]

  @type t :: %__MODULE__{
          ref: reference(),
          id: String.t(),
          node: node(),
          root: String.t(),
          server_id: String.t(),
          owner: pid()
        }

  @doc "The pool key a handle refers to."
  @spec key(t()) :: {String.t(), String.t()}
  def key(%__MODULE__{root: root, server_id: server_id}), do: {root, server_id}

  @doc "The cluster-visible identity of one server on one host."
  @spec id(node(), String.t(), String.t()) :: String.t()
  def id(node, root, server_id), do: "#{node}:#{server_id}:#{root}"
end
