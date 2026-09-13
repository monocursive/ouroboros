# Run only via the packaged release's eval in the dedicated Intel CI smoke.
# No model/approval loop: exercise actual compiled Tools.Bash, not a fake backend.
alias Ouroboros.Provider.Native.{Paths, Sandbox}
alias Ouroboros.Provider.Native.Tools.Bash

{:ok, _} = Application.ensure_all_started(:ouroboros)
false = Node.alive?()
[] = Node.list()
{:unix, :darwin} = :os.type()
true = String.starts_with?(to_string(:erlang.system_info(:system_architecture)), "x86_64")
"29" = to_string(:erlang.system_info(:otp_release))
:jit = :erlang.system_info(:emu_flavor)
:sandbox_exec = Sandbox.detect().backend

root = System.fetch_env!("INTEL_SMOKE_ROOT")
workspace = Path.join(root, "workspace")
data = System.fetch_env!("OUROBOROS_DATA_DIR")
File.mkdir_p!(Path.join(workspace, ".git"))
File.mkdir_p!(Path.join(workspace, ".ouroboros"))
File.mkdir_p!(Path.join(root, "session"))

protected = [
  Path.join(root, "outside"),
  Path.join(workspace, ".git/sentinel"),
  Path.join(workspace, ".ouroboros/sentinel"),
  Path.join(workspace, "ouroboros.toml"),
  Path.join(data, "synthetic-control")
]

Enum.each(protected, &File.write!(&1, "unchanged"))
File.write!(Path.join(workspace, "readable"), "existing content")
{:ok, rw} = Paths.scope(workspace, [], :workspace_write)
{:ok, ro} = Paths.scope(workspace, [], :read_only)

call = fn command, scope ->
  {:ok, result} =
    Bash.run(
      %{command: command, timeout_ms: 5_000},
      %{scope: scope, session_dir: Path.join(root, "session"), reads: %{}}
    )

  result
end

read = call.("cat readable", ro)
false = read.is_error
"existing content" = read.output
true = call.("printf forbidden > denied", ro).is_error
false = File.exists?(Path.join(workspace, "denied"))
false = call.("printf allowed > allowed", rw).is_error
"allowed" = File.read!(Path.join(workspace, "allowed"))

Enum.each(protected, fn path ->
  # root comes from a runner-created private directory, not a user shell fragment.
  quoted = "'" <> String.replace(path, "'", "'\\''") <> "'"
  true = call.("printf changed > " <> quoted, rw).is_error
  "unchanged" = File.read!(path)
end)

IO.puts(
  "INTEL_SHELL_SMOKE=" <>
    Jason.encode!(%{
      architecture: to_string(:erlang.system_info(:system_architecture)),
      otp: to_string(:erlang.system_info(:otp_release)),
      erts: to_string(:erlang.system_info(:version)),
      emu: :erlang.system_info(:emu_flavor),
      elixir: System.version(),
      node: node(),
      backend: "sandbox-exec",
      read_only: true,
      workspace_write: true,
      protected_file_controls: length(protected)
    })
)
