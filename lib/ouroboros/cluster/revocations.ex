defmodule Ouroboros.Cluster.Revocations do
  @moduledoc """
  Permanent, CA-attested machine revocations, enforced at the TLS certificate boundary.

  Each revocation is an immutable file keyed by node identity. Concurrent imports cannot
  overwrite a newer policy, and old rosters or invitations cannot undo a revocation.
  The TLS callback registers its actual SSL process before accepting a certificate;
  revocation kills those processes, including handshakes not yet visible in Node.list.
  This protects against reuse of a revoked credential. A compromised distributed VM
  already has authority over its peers; this is not containment of such a compromise.
  """
  use GenServer
  require Record
  import Bitwise

  for {name, record} <- [
        cert: :OTPCertificate,
        tbs: :OTPTBSCertificate,
        spki: :OTPSubjectPublicKeyInfo,
        algorithm: :PublicKeyAlgorithm,
        extension: :Extension,
        attribute: :AttributeTypeAndValue
      ] do
    Record.defrecordp(
      name,
      Record.extract(record, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
    )
  end

  @oid {1, 3, 6, 1, 4, 1, 59_555, 1, 1}
  @connections {__MODULE__, :connections}
  @policy {__MODULE__, :policy}
  @cap 16_384
  @max_entries 4_096

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def install(encoded), do: GenServer.call(__MODULE__, {:install, encoded}, 5_000)
  def snapshot, do: GenServer.call(__MODULE__, :snapshot, 5_000)

  def revoked_nodes(root) do
    case :persistent_term.get(@policy, nil) do
      {^root, nodes} -> nodes
      _ -> MapSet.new()
    end
  end

  def nodes, do: revoked_nodes(policy_root()) |> MapSet.to_list() |> Enum.sort()
  def revoked?(node), do: MapSet.member?(revoked_nodes(policy_root()), to_string(node))

  def distribute(encoded) do
    with {:ok, revoked} <- install(encoded) do
      issuer =
        encoded
        |> JSON.decode!()
        |> Map.fetch!("payload")
        |> JSON.decode!()
        |> Map.fetch!("issuer")

      if issuer == Atom.to_string(node()) do
        broadcast(encoded, revoked)
      else
        # Only the invitation authority has the complete issuance roster. A follower's
        # stale invitation must never turn missing machines into fleet-wide success.
        try do
          :erpc.call(String.to_atom(issuer), __MODULE__, :distribute, [encoded], 10_000)
        catch
          _, _ ->
            {:ok,
             %{
               revoked: revoked,
               acknowledged: [Atom.to_string(node())],
               pending: [issuer],
               complete: false,
               reason: :issuer_unavailable
             }}
        end
      end
    end
  catch
    _, _ -> {:error, :revocation_sync_unavailable}
  end

  defp broadcast(encoded, revoked) do
    with {:ok, _, profile, _} <- Ouroboros.Cluster.Monitor.fleet_profile_storage() do
      # Previously canceled invitations still carry valid credentials. Include those
      # holders in the acknowledgement set as well as active and connected machines.
      roster = Map.values(profile.members) ++ Map.values(profile.tombstones)

      targets =
        (Enum.map(roster, &String.to_atom/1) ++ Node.list(:connected))
        |> Enum.uniq()
        |> Enum.reject(
          &(&1 == node() or MapSet.member?(revoked_nodes(policy_root()), Atom.to_string(&1)))
        )

      results = :erpc.multicall(targets, __MODULE__, :install, [encoded], 5_000)

      {acknowledged, pending} =
        Enum.zip(targets, results)
        |> Enum.split_with(fn {_node, result} -> match?({:ok, {:ok, ^revoked}}, result) end)

      {:ok,
       %{
         revoked: revoked,
         acknowledged: Enum.map(acknowledged, &Atom.to_string(elem(&1, 0))),
         pending: Enum.map(pending, &Atom.to_string(elem(&1, 0))),
         complete: pending == []
       }}
    else
      _ -> {:error, :fleet_issuance_roster_unavailable}
    end
  end

  # Bad certificates always remain bad. Unknown extensions remain OTP's decision.
  def verify(_cert, {:bad_cert, reason}, _path), do: {:fail, reason}
  def verify(_cert, {:extension, _}, path), do: {:unknown, path}
  def verify(_cert, :valid, path), do: {:valid, path}

  def verify(cert, :valid_peer, path) do
    with {:ok, name} <- certificate_node(cert),
         :ok <- GenServer.call(__MODULE__, {:connection, to_string(path), name, self()}, 5_000) do
      {:valid, path}
    else
      _ -> {:fail, :fleet_credential_revoked_or_policy_unavailable}
    end
  rescue
    _ -> {:fail, :fleet_policy_unavailable}
  catch
    _, _ -> {:fail, :fleet_policy_unavailable}
  end

  @impl true
  def init(opts) do
    data = Keyword.get(opts, :data_dir, Application.get_env(:ouroboros, :data_dir))
    tls? = :init.get_argument(:proto_dist) in [{:ok, [[~c"inet_tls"]]}, {:ok, [[~c"inet6_tls"]]}]

    if Keyword.get(opts, :enabled, tls?) and is_binary(data) and
         File.regular?(Path.join([data, "fleet", "profile.json"])) do
      # A killed policy process cannot leave authenticated sockets beside an empty
      # replacement authority. Pids are VM-local and cannot be reused while alive.
      Enum.each(:persistent_term.get(@connections, %{}), fn {pid, _} ->
        Process.exit(pid, :kill)
      end)

      :persistent_term.put(@connections, %{})
      root = Path.join(data, "fleet")

      with {:ok, profile} <- private_json(Path.join(root, "profile.json"), 2 * 1024 * 1024),
           {:ok, ca} <- private_file(Path.join(root, "ca-cert.pem"), @cap),
           {:ok, artifacts} <- read_all(root, profile["fleet_id"], ca) do
        state = %{
          root: root,
          fleet: profile["fleet_id"],
          local: profile["node"],
          ca: ca,
          artifacts: artifacts,
          connections: %{}
        }

        publish(state)
        :net_kernel.monitor_nodes(true, node_type: :all)
        Enum.each(Node.list(:connected), &send(self(), {:nodeup, &1, []}))
        Process.send_after(self(), :refresh, 1_000)
        {:ok, state}
      else
        error -> {:stop, {:invalid_fleet_revocation_policy, error}}
      end
    else
      :ignore
    end
  end

  @impl true
  def handle_call({:connection, root, node, pid}, _from, state) do
    cond do
      root != state.root ->
        {:reply, {:error, :wrong_fleet}, state}

      Map.has_key?(state.artifacts, state.local) ->
        {:reply, {:error, :local_identity_revoked}, state}

      Map.has_key?(state.artifacts, node) ->
        {:reply, {:error, :revoked}, state}

      map_size(state.connections) >= @max_entries ->
        {:reply, {:error, :connection_limit}, state}

      true ->
        Process.monitor(pid)
        connections = Map.put(state.connections, pid, node)
        :persistent_term.put(@connections, connections)
        {:reply, :ok, %{state | connections: connections}}
    end
  end

  def handle_call(:snapshot, _from, state),
    do: {:reply, {:ok, Map.values(state.artifacts)}, state}

  def handle_call({:install, encoded}, _from, state) do
    with {:ok, node} <- validate(encoded, state.fleet, state.ca),
         true <- map_size(state.artifacts) < @max_entries or Map.has_key?(state.artifacts, node) do
      case persist(state.root, node, encoded, state.fleet, state.ca) do
        :ok ->
          next = enforce(%{state | artifacts: Map.put_new(state.artifacts, node, encoded)})
          {:reply, {:ok, node}, next}

        error ->
          {:stop, {:revocation_install_failed, error}, {:error, :revocation_not_acknowledged},
           state}
      end
    else
      _ -> {:reply, {:error, :invalid_signed_revocation}, state}
    end
  end

  @impl true
  def handle_info(:refresh, state) do
    case read_all(state.root, state.fleet, state.ca) do
      {:ok, artifacts} ->
        # A missing record must never un-revoke a machine while this VM is alive.
        next = enforce(%{state | artifacts: Map.merge(artifacts, state.artifacts)})
        Process.send_after(self(), :refresh, 1_000)
        {:noreply, next}

      error ->
        {:stop, {:revocation_policy_unreadable, error}, state}
    end
  end

  def handle_info({:DOWN, _, :process, pid, _}, state) do
    connections = Map.delete(state.connections, pid)
    :persistent_term.put(@connections, connections)
    {:noreply, %{state | connections: connections}}
  end

  def handle_info({:nodeup, target, _}, state) do
    if Map.has_key?(state.artifacts, Atom.to_string(target)) do
      Node.disconnect(target)
    else
      artifacts = Map.values(state.artifacts)

      Task.start(fn ->
        Enum.each(artifacts, fn encoded ->
          try do
            :erpc.call(target, __MODULE__, :install, [encoded], 5_000)
          catch
            _, _ -> :unavailable
          end
        end)
      end)
    end

    {:noreply, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp enforce(state) do
    publish(state)

    Enum.each(state.connections, fn {pid, name} ->
      if Map.has_key?(state.artifacts, name) or Map.has_key?(state.artifacts, state.local),
        do: Process.exit(pid, :kill)
    end)

    Enum.each(Node.list(:connected), fn target ->
      if Map.has_key?(state.artifacts, Atom.to_string(target)) or
           Map.has_key?(state.artifacts, state.local),
         do: Node.disconnect(target)
    end)

    state
  end

  defp publish(state),
    do: :persistent_term.put(@policy, {state.root, MapSet.new(Map.keys(state.artifacts))})

  defp policy_root do
    case :persistent_term.get(@policy, nil) do
      {root, _} -> root
      _ -> nil
    end
  end

  @doc false
  def validate(encoded, fleet, ca) when is_binary(encoded) and byte_size(encoded) <= @cap do
    with {:ok, %{"payload" => payload, "attestation_pem" => pem}} <- JSON.decode(encoded),
         true <- is_binary(payload) and is_binary(pem),
         {:ok, %{"schema" => 1, "fleet_id" => ^fleet, "node" => node, "issuer" => issuer}} <-
           JSON.decode(payload),
         true <-
           is_binary(issuer) and byte_size(issuer) <= 512 and
             String.match?(issuer, ~r/^ouro-[a-zA-Z0-9][a-zA-Z0-9_-]*@[a-zA-Z0-9._-]+$/),
         true <-
           is_binary(node) and byte_size(node) <= 512 and
             String.match?(node, ~r/^ouro-[a-zA-Z0-9][a-zA-Z0-9_-]*@[a-zA-Z0-9._-]+$/),
         [{:Certificate, ca_der, :not_encrypted}] <- :public_key.pem_decode(ca),
         [{:Certificate, der, :not_encrypted}] <- :public_key.pem_decode(pem),
         ca_cert <- :public_key.pkix_decode_cert(ca_der, :otp),
         cert <- :public_key.pkix_decode_cert(der, :otp),
         spki <- tbs(cert(ca_cert, :tbsCertificate), :subjectPublicKeyInfo),
         true <- signed_by_ca?(der, spki),
         extensions <- tbs(cert(cert, :tbsCertificate), :extensions),
         [digest] <-
           for(ext <- extensions, extension(ext, :extnID) == @oid, do: extension(ext, :extnValue)),
         true <- digest == <<4, 32, :crypto.hash(:sha256, payload)::binary>> do
      {:ok, node}
    else
      _ -> {:error, :invalid_signed_revocation}
    end
  rescue
    _ -> {:error, :invalid_signed_revocation}
  catch
    _, _ -> {:error, :invalid_signed_revocation}
  end

  def validate(_, _, _), do: {:error, :revocation_too_large}

  defp signed_by_ca?(der, spki) do
    algorithm = spki(spki, :algorithm)
    public = spki(spki, :subjectPublicKey)
    :public_key.pkix_verify(der, {public, algorithm(algorithm, :parameters)})
  end

  defp certificate_node(cert) do
    {:rdnSequence, names} = tbs(cert(cert, :tbsCertificate), :subject)

    case for(
           name <- List.flatten(names),
           attribute(name, :type) == {2, 5, 4, 3},
           do: attribute(name, :value)
         ) do
      [{_, value}] when is_binary(value) -> {:ok, value}
      [{_, value}] when is_list(value) -> {:ok, to_string(value)}
      _ -> {:error, :missing_machine_identity}
    end
  end

  defp read_all(root, fleet, ca) do
    with {:ok, names} <- File.ls(root) do
      names = Enum.filter(names, &String.starts_with?(&1, "revoke-"))

      if length(names) > @max_entries do
        {:error, :revocation_limit}
      else
        Enum.reduce_while(names, {:ok, %{}}, fn name, {:ok, acc} ->
          with {:ok, encoded} <- private_file(Path.join(root, name), @cap),
               {:ok, node} <- validate(encoded, fleet, ca),
               true <- name == filename(node) do
            {:cont, {:ok, Map.put(acc, node, encoded)}}
          else
            error -> {:halt, {:error, error}}
          end
        end)
      end
    end
  end

  defp persist(root, node, encoded, fleet, ca) do
    path = Path.join(root, filename(node))

    case private_file(path, @cap) do
      {:ok, existing} ->
        with({:ok, ^node} <- validate(existing, fleet, ca), do: sync_directory(root))

      {:error, :enoent} ->
        tmp =
          Path.join(
            root,
            ".revocation-#{Base.encode16(:crypto.strong_rand_bytes(12), case: :lower)}"
          )

        try do
          with {:ok, device} <- :file.open(tmp, [:write, :binary, :exclusive, :raw]) do
            result =
              with :ok <- File.chmod(tmp, 0o600),
                   :ok <- :file.write(device, encoded),
                   :ok <- :file.sync(device),
                   do: :ok

            :file.close(device)

            with :ok <- result,
                 linked when linked in [:ok, {:error, :eexist}] <- File.ln(tmp, path),
                 {:ok, current} <- private_file(path, @cap),
                 {:ok, ^node} <- validate(current, fleet, ca),
                 :ok <- sync_directory(root),
                 do: :ok
          end
        after
          File.rm(tmp)
        end

      error ->
        error
    end
  end

  defp filename(node),
    do: "revoke-#{Base.encode16(:crypto.hash(:sha256, node), case: :lower)}.json"

  defp private_json(path, cap),
    do: with({:ok, text} <- private_file(path, cap), do: JSON.decode(text))

  defp private_file(path, cap) do
    with {:ok, %File.Stat{type: :regular, mode: mode, size: size, uid: uid}} <- File.lstat(path),
         true <- band(mode, 0o777) == 0o600 and size <= cap,
         {:ok, %File.Stat{uid: ^uid}} <- File.stat(Path.dirname(path)),
         {:ok, file} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(file, cap + 1) do
          data when is_binary(data) and byte_size(data) <= cap -> {:ok, data}
          _ -> {:error, :invalid_policy_file}
        end
      after
        File.close(file)
      end
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_policy_file}
    end
  end

  defp sync_directory(root) do
    with {:ok, file} <- :file.open(String.to_charlist(root), [:read, :raw, :directory]) do
      result = :file.sync(file)
      :file.close(file)
      result
    end
  end
end
