defmodule Ouroboros.Provider.Native.Tools.Write do
  @moduledoc """
  Create or replace a file, whole.

  Refused under `sandbox_mode: :read_only`. Missing parent directories are created,
  because the path has already been proven to be inside the workspace before this tool
  runs — `Ouroboros.Provider.Native.Paths.resolve/2` canonicalizes through every symlink
  on the way, so a parent that resolves inside the boundary really is inside it. The
  write itself is `SafeWrite`: the proof is re-checked around the rename, because
  resolve and the write are two moments and the filesystem can move between them.

  The previous content is read first so the emitted `file_change` carries a real
  unified diff rather than "a file changed", and so a later checkpoint slice has
  something to restore from.
  """

  use Jido.Action,
    name: "write",
    description:
      "Write a file in the workspace, replacing it if it exists. Prefer `edit` for a " <>
        "change to an existing file.",
    schema: [
      path: [
        type: :string,
        required: true,
        doc: "Absolute path, or a path relative to the workspace root."
      ],
      content: [type: :string, required: true, doc: "The complete new file content."]
    ]

  alias Ouroboros.Provider.Native.Diff
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.{Read, SafeWrite}

  @impl true
  def run(params, context) do
    with :ok <- writable(context.scope),
         {:ok, path} <- Paths.resolve(params.path, context.scope),
         {:ok, previous} <- previous(path),
         :ok <- SafeWrite.write(path, params.content, context.scope),
         {:ok, fingerprint} <- Read.fingerprint(path) do
      relative = Path.relative_to(path, context.scope.root)
      kind = if is_nil(previous), do: :add, else: :modify

      {:ok,
       %{
         output: "Wrote #{relative} (#{byte_size(params.content)} bytes).",
         is_error: false,
         reads: %{path => fingerprint},
         changes: [Diff.change(path, relative, previous, params.content, kind)]
       }}
    else
      {:error, reason} -> {:ok, %{output: "write failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp writable(%{sandbox_mode: :read_only}), do: {:error, :read_only_sandbox}
  defp writable(_scope), do: :ok

  defp previous(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, :enoent} -> {:ok, nil}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp describe(:read_only_sandbox),
    do: "this session runs with sandbox_mode: read_only, which refuses every write"

  defp describe({:unreadable, path, reason}), do: "#{path}: #{:file.format_error(reason)}"
  defp describe({:unwritable, _path, _reason} = error), do: SafeWrite.format_reason(error)
  defp describe(reason), do: Paths.describe_error(reason)
end
