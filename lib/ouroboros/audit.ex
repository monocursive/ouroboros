defmodule Ouroboros.Audit.Unavailable do
  defexception [
    :reason,
    message: "Required audit evidence could not be committed; execution stopped."
  ]
end

defmodule Ouroboros.Audit do
  @moduledoc "Audit admission and recording shared by execution and investigation surfaces."
  alias Ouroboros.Audit.{Config, Store, Unavailable}
  alias Ouroboros.Provider.Native.Journal

  def enabled?, do: Config.enabled?()
  def required?, do: Config.required?()

  def session_path(session_dir) do
    Store.stream_path(Config.current().root, Store.stream_id(session_dir))
  end

  def append(stream, kind, fields) do
    if enabled?() do
      result = safe(fn -> Store.append(stream, kind, fields) end)

      case result do
        {:ok, record} ->
          {:ok, record}

        {:error, reason} ->
          if required?(), do: raise(Unavailable, reason: reason)
          {:error, reason}
      end
    else
      {:ok, nil}
    end
  end

  def administrative(kind, fields) do
    if enabled?(),
      do: append(Journal.digest("ouroboros.audit.administration"), kind, fields),
      else: {:ok, nil}
  end

  def coverage(provider) do
    native = provider in [:native, "native", Ouroboros.Provider.Native]

    %{
      invocation: if(native, do: "runtime_boundary", else: "provider_reported"),
      transport: if(native, do: "serialized_request_before_transport", else: "opaque"),
      downstream: "not_observable_without_instrumentation",
      capture: to_string(Config.current().capture),
      required_supported: native
    }
  end

  # Only request metadata carries runtime attribution. Provider/model options are untrusted.
  def actor_id(request) when is_map(request) do
    metadata = Map.get(request, :metadata) || %{}
    Map.get(metadata, :audit_actor_id) || Map.get(metadata, "audit_actor_id")
  end

  def actor_id(_), do: nil

  def ensure_actor(request) do
    if required?() and Config.current().identities != [] and
         not Ouroboros.Audit.Identity.actor_active?(actor_id(request)),
       do: raise(Unavailable, reason: :execution_identity_revoked_or_missing)

    :ok
  end

  def admission_profile do
    config = Config.current()

    %{
      required: Config.required?(config),
      capture: config.capture,
      organization: config.organization,
      archive_required: config.archive_required
    }
  end

  def admit_remote(target) when target == node(), do: :ok

  def admit_remote(target) do
    if required?() do
      local = admission_profile()
      remote = :erpc.call(target, __MODULE__, :admission_profile, [], 5_000)

      if remote.required and remote.capture == local.capture and
           remote.organization == local.organization and
           (not local.archive_required or remote.archive_required),
         do: :ok,
         else: {:error, :remote_audit_policy_insufficient}
    else
      :ok
    end
  catch
    _, _ -> {:error, :remote_audit_policy_unavailable}
  end

  def admit_provider(provider) do
    if required?() and not coverage(provider).required_supported,
      do: {:error, :provider_audit_coverage_insufficient},
      else: :ok
  end

  def admit_scope(scope) do
    if enabled?() and Enum.any?(Map.get(scope, :roots, [scope.root]), &overlaps_protected?/1),
      do: {:error, :audit_storage_overlaps_workspace},
      else: :ok
  end

  def protected_roots do
    config = Config.current()

    [
      config.root,
      config.policy_file,
      config.archive && Map.get(config.archive, :token_file),
      Application.get_env(:ouroboros, :data_dir),
      Application.get_env(:ouroboros, :native_data_dir),
      Path.join(System.get_env("XDG_CONFIG_HOME") || Path.expand("~/.config"), "ouroboros")
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&Path.expand/1)
  end

  def overlaps_protected?(root),
    do: enabled?() and Enum.any?(protected_roots(), &(inside?(root, &1) or inside?(&1, root)))

  def protected_path?(path), do: enabled?() and Enum.any?(protected_roots(), &inside?(path, &1))

  # Opaque in-process and vendor adapters need their own isolation/instrumentation
  # before they can execute under the required policy. Local mode records their boundary.
  def tool_supported?(name) do
    not required?() or
      name in ~w(read write edit apply_patch bash grep glob ls web_fetch ask_user agent agent_result skill plan)
  end

  defp inside?(path, root), do: path == root or String.starts_with?(path, root <> "/")

  def with_execution(context, fun) do
    old = Process.get({__MODULE__, :execution})
    Process.put({__MODULE__, :execution}, context)

    try do
      fun.()
    after
      Process.put({__MODULE__, :execution}, old)
    end
  end

  def execution(kind, fields) do
    case Process.get({__MODULE__, :execution}) do
      %{stream: stream, fields: context} ->
        append(stream, kind, Map.merge(context, fields))

      _ ->
        administrative(
          kind,
          Map.put(fields, "coverage", "runtime_operation_without_session_context")
        )
    end
  end

  def safe(fun) do
    fun.()
  rescue
    _ -> {:error, :audit_service_failed}
  catch
    :exit, _ -> {:error, :audit_service_unavailable}
  end
end
