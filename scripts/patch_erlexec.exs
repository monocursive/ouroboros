defmodule Ouroboros.Build.ErlexecPatch do
  @moduledoc false

  # Verified against the untouched Hex 2.3.4 tarball pinned in mix.lock. Accept only
  # that source or our exact result: an upgrade must review/remove this workaround.
  @original "bcb6e7aab13d13fad8018af2577d9583c820c18dadb99d584faabe5db0a9273c"
  @patched "f3bcb4e9682363e9fc3e1fcb48cb294581eb70f54234a89ba2b334e028e71d0a"
  @patch Path.expand("../patches/erlexec-2.3.4-macos-setpgid.patch", __DIR__)

  def apply!(deps_path) do
    root = Path.join(deps_path, "erlexec")
    source = Path.join(root, "c_src/exec_impl.cpp")

    case digest!(source) do
      @patched ->
        :unchanged

      @original ->
        case System.cmd("git", ["apply", "--unidiff-zero", @patch],
               cd: root,
               stderr_to_stdout: true
             ) do
          {_output, 0} ->
            if digest!(source) != @patched,
              do:
                Mix.raise(
                  "erlexec patch produced an unexpected source; restore the pinned dependency"
                )

            :patched

          {output, _} ->
            Mix.raise("cannot apply the reviewed erlexec 2.3.4 patch: #{output}")
        end

      actual ->
        Mix.raise(
          "erlexec 2.3.4 patch refused unfamiliar source #{actual} at #{source}; " <>
            "review the dependency upgrade or local changes before updating/removing the patch"
        )
    end
  end

  defp digest!(path) do
    case File.read(path) do
      {:ok, source} ->
        :crypto.hash(:sha256, source) |> Base.encode16(case: :lower)

      {:error, reason} ->
        Mix.raise("erlexec source unavailable at #{path}: #{reason}; run mix deps.get")
    end
  end
end
