defmodule Ouroboros.Cluster.Facts do
  @moduledoc "Advisory fleet inventory. Detection checks presence only; no toolchain is executed."
  @toolchains ~w(xcodebuild xcrun swift docker podman node npm pnpm yarn bun cargo rustc go java gradle adb flutter python3 uv mix elixir git make)

  def local do
    toolchains = Enum.filter(@toolchains, &System.find_executable/1)

    tag_facts =
      case Ouroboros.Cluster.Monitor.fleet_profile_storage() do
        {:ok, _, profile, _} -> Map.get(profile, :tag_facts, %{tags: []})
        :ephemeral -> %{tags: []}
        {:error, reason} -> %{tags: [], tags_error: inspect(reason)}
      end

    os =
      case :os.type() do
        {:unix, :darwin} -> "macos"
        {_, os} -> Atom.to_string(os)
      end

    {:ok, hostname} = :inet.gethostname()

    data_dir = Application.get_env(:ouroboros, :data_dir)

    Map.merge(tag_facts, %{
      os: os,
      arch: :erlang.system_info(:system_architecture) |> to_string() |> String.split("-") |> hd(),
      hostname: to_string(hostname),
      toolchains: toolchains,
      provisionable:
        "git" in toolchains and is_binary(data_dir) and File.dir?(data_dir) and
          Ouroboros.Workspace.Worktree.admissible?()
    })
  end

  def validate_tags(tags) when is_list(tags) and length(tags) <= 32 do
    if Enum.all?(tags, &(is_binary(&1) and String.match?(&1, ~r/\A[a-z0-9][a-z0-9._:-]{0,63}\z/))) do
      %{tags: Enum.uniq(tags)}
    else
      invalid =
        Enum.find(
          tags,
          &(not (is_binary(&1) and String.match?(&1, ~r/\A[a-z0-9][a-z0-9._:-]{0,63}\z/)))
        )

      %{
        tags: [],
        tags_error: "invalid fleet tag: #{inspect(invalid, limit: 5, printable_limit: 80)}"
      }
    end
  end

  def validate_tags(_),
    do: %{tags: [], tags_error: "fleet tags must be a list of at most 32 tags"}

  def tags(machine), do: Map.get(Map.get(machine, :facts) || %{}, :tags, [])
  def matches?(machine, "tag:" <> tag), do: tag in tags(machine)
  def matches?(machine, name), do: to_string(machine.node) == name or machine.machine == name

  def resolve(name, machines) do
    matches =
      machines
      |> Enum.filter(&(&1.state in [:local, :connected] and matches?(&1, name)))
      |> Enum.map(& &1.node)
      |> Enum.uniq()
      |> Enum.sort()

    case matches do
      [target] -> {:ok, target}
      [] -> {:error, :unknown_machine}
      many -> {:error, {:ambiguous_machine, many}}
    end
  end

  def labels(machines),
    do:
      Enum.map_join(
        Enum.take(machines, 64),
        ", ",
        &"#{&1.machine} (#{&1.node}; tags: #{Enum.join(tags(&1), " ")})"
      )
end
