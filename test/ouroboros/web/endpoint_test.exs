defmodule Ouroboros.Web.EndpointTest do
  @moduledoc """
  A real socket, a real request, and the file that says where they are.

  Everything else in this directory dispatches conns straight into the endpoint, which is
  faster and proves more about the pipeline. This one binds, because publishing a port is
  something only a bound endpoint can be wrong about.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Endpoint
  alias Ouroboros.Web.Publication

  @token String.duplicate("t", 40)

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-endpoint-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)

    on_exit(fn -> File.rm_rf(dir) end)

    {:ok, config: Config.new!(data_dir: dir, scope: :operate), data_dir: dir, token: token_path}
  end

  describe "booting" do
    test "binds loopback on a kernel-assigned port and serves", %{config: config} do
      start_supervised!({Ouroboros.Web, config: config})

      assert {:ok, {{127, 0, 0, 1}, port}} = Endpoint.bound_address()
      assert port > 0

      {status, body} = request(port, "/")

      assert status == 401
      assert body =~ "ouro web"

      {status, _body} = request(port, "/auth?token=#{@token}")
      assert status == 302
    end

    test "the task supervisor every runtime call goes through is up first", %{config: config} do
      start_supervised!({Ouroboros.Web, config: config})

      assert is_pid(Process.whereis(Ouroboros.Web.TaskSupervisor))
    end
  end

  describe "the publication" do
    test "names the port, the node, and where the credential is — never the credential",
         %{config: config, data_dir: dir, token: token_path} do
      start_supervised!({Ouroboros.Web, config: config})
      {:ok, {_address, port}} = Endpoint.bound_address()

      path = Endpoint.publication_path(dir)
      assert path == Path.join(dir, "web.json")

      raw = File.read!(path)
      published = JSON.decode!(raw)

      assert published["port"] == port
      assert published["protocol"] == 1
      assert published["node"] == Atom.to_string(node())
      assert published["scope"] == "operate"
      assert published["token_file"] == token_path
      assert is_integer(published["pid"]) and published["pid"] > 0

      # Birth is the same claim `gateway.json` publishes, present exactly when
      # `RuntimeOwner` is claiming this VM. A test that starts only the web tree has
      # none; the document tests below pin both shapes without standing that process up.
      if Process.whereis(Ouroboros.RuntimeOwner) do
        assert is_binary(published["birth"]) and published["birth"] != ""
      else
        refute Map.has_key?(published, "birth")
      end

      # The whole point of naming the file rather than the value.
      refute raw =~ @token
    end

    test "is private before it is published", %{config: config, data_dir: dir} do
      start_supervised!({Ouroboros.Web, config: config})

      stat = File.lstat!(Endpoint.publication_path(dir))

      assert stat.type == :regular
      assert Bitwise.band(stat.mode, 0o777) == 0o600
    end

    test "is removed when the surface stops", %{config: config, data_dir: dir} do
      start_supervised!({Ouroboros.Web, config: config})
      path = Endpoint.publication_path(dir)
      assert File.exists?(path)

      stop_supervised!(Ouroboros.Web)

      refute File.exists?(path),
             "a stopped surface left a publication pointing at a port nobody is listening on"
    end

    test "and only when it is still the file this node wrote", %{config: config, data_dir: dir} do
      start_supervised!({Ouroboros.Web, config: config})
      path = Endpoint.publication_path(dir)

      # A second daemon republished over it. That file is theirs now, and deleting
      # somebody else's publication on the way out is worse than leaving a stale one.
      replacement = path <> ".theirs"
      File.write!(replacement, ~s({"port":1,"protocol":1}))
      File.rename!(replacement, path)

      stop_supervised!(Ouroboros.Web)

      assert File.read!(path) == ~s({"port":1,"protocol":1})
    end

    test "says nothing about a token that has no file", %{data_dir: dir} do
      config = Config.new!(data_dir: dir, token: @token <> "-from-the-environment")

      assert config.token_file == nil
      refute Map.has_key?(Publication.document(config, 4560, %{pid: 99}), "token_file")

      assert Publication.document(config, 4560, %{pid: 99}) == %{
               "port" => 4560,
               "protocol" => 1,
               "node" => Atom.to_string(node()),
               "pid" => 99,
               "scope" => "read"
             }
    end

    test "names birth when the owner has one, and omits it when it does not", %{data_dir: dir} do
      config = Config.new!(data_dir: dir, token: @token <> "-from-the-environment")

      with_birth = Publication.document(config, 4560, %{pid: 99, birth: "test:web:99"})
      without_birth = Publication.document(config, 4560, %{pid: 99, birth: nil})

      assert with_birth["birth"] == "test:web:99"
      refute Map.has_key?(without_birth, "birth")
    end

    test "claims pid and birth from RuntimeOwner rather than inventing them", %{
      config: config,
      data_dir: dir
    } do
      # Fail-closed: a registered owner is the only source of either fact. The named
      # process is how `document/2` finds it, the same `whereis` the gateway listener uses.
      refute Process.whereis(Ouroboros.RuntimeOwner)

      start_supervised!(
        {Ouroboros.RuntimeOwner,
         data_dir: dir,
         os_pid: 4242,
         identity: "web-publication-vm",
         birth: "test:web:4242",
         pid_state: fn _pid -> :alive end,
         birth_state: fn _pid, _birth -> :alive end}
      )

      published = Publication.document(config, 4560)

      assert published["pid"] == 4242
      assert published["birth"] == "test:web:4242"

      start_supervised!({Ouroboros.Web, config: config})
      written = Endpoint.publication_path(dir) |> File.read!() |> JSON.decode!()

      assert written["pid"] == 4242
      assert written["birth"] == "test:web:4242"
    end
  end

  describe "the sticky port" do
    test "the next boot takes the port the last one published", %{config: config} do
      start_supervised!({Ouroboros.Web, config: config})
      {:ok, {_address, first}} = Endpoint.bound_address()
      stop_supervised!(Ouroboros.Web)

      # The publication was removed on the way out, so this is not a file the second boot
      # reads — it is what `sticky_port/1` computes from it. Write it back the way a
      # killed node would have left it.
      republish(config, first)

      start_supervised!({Ouroboros.Web, config: config})
      {:ok, {_address, second}} = Endpoint.bound_address()

      assert second == first,
             "a restart moved the port, which signs every browser out and breaks bookmarks"
    end

    test "a port somebody else holds falls back to an ephemeral one", %{config: config} do
      {:ok, held} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
      {:ok, taken} = :inet.port(held)
      on_exit(fn -> :gen_tcp.close(held) end)

      republish(config, taken)
      assert Endpoint.sticky_port(config) == 0

      start_supervised!({Ouroboros.Web, config: config})
      {:ok, {_address, bound}} = Endpoint.bound_address()

      assert bound != taken
      assert bound > 0
    end

    test "an operator who typed a port gets that port or a refusal", %{data_dir: dir} do
      pinned = Config.new!(data_dir: dir, port: 4571)

      # Not the published one, not zero: a number somebody typed is not negotiable.
      republish(pinned, 4999)
      assert Endpoint.sticky_port(pinned) == 4571
    end

    test "no publication at all means the configured port, unchanged", %{config: config} do
      refute File.exists?(Endpoint.publication_path(config.data_dir))
      assert Endpoint.sticky_port(config) == 0
    end
  end

  describe "the origin policy" do
    test "is never off, and is computed from what the endpoint bound", %{config: config} do
      start_supervised!({Ouroboros.Web, config: config})
      {:ok, {_address, port}} = Endpoint.bound_address()

      refute Endpoint.config(:check_origin) == false
      assert Endpoint.config(:check_origin) == {Endpoint, :origin_allowed?, []}

      assert Endpoint.origin_allowed?(URI.parse("http://127.0.0.1:#{port}"))
      assert Endpoint.origin_allowed?(URI.parse("http://localhost:#{port}"))

      refute Endpoint.origin_allowed?(URI.parse("http://127.0.0.1:#{port + 1}"))
      refute Endpoint.origin_allowed?(URI.parse("http://evil.example:#{port}"))
      refute Endpoint.origin_allowed?(URI.parse("https://127.0.0.1:#{port}"))
    end

    test "an explicit origin replaces it for a proxied deployment", %{data_dir: dir} do
      config = Config.new!(data_dir: dir, origin: "https://box.tailnet.ts.net")

      assert Endpoint.options(config, server: false)[:check_origin] ==
               ["https://box.tailnet.ts.net"]
    end
  end

  defp republish(config, port) do
    path = Endpoint.publication_path(config.data_dir)
    File.write!(path, JSON.encode_to_iodata!(Publication.document(config, port, %{pid: 1})))
    File.chmod!(path, 0o600)
    on_exit(fn -> File.rm(path) end)
  end

  defp request(port, path) do
    url = ~c"http://127.0.0.1:#{port}#{path}"

    {:ok, {{_version, status, _reason}, _headers, body}} =
      :httpc.request(:get, {url, []}, [autoredirect: false], [])

    {status, to_string(body)}
  end
end
