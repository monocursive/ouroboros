defmodule Ouroboros.Web.ConfigTest do
  @moduledoc """
  The web surface's admission policy, and the two layers that enforce it.

  Every refusal here is checked twice on purpose, the way the gateway's is: once in
  `Ouroboros.Web.Config`, which is what an operator writing application environment
  directly is held to, and once in `config/runtime.exs`, which is what a config provider
  can refuse a boot with before this application's modules are loadable. A refusal that
  only exists in one of them is a refusal half the postures skip.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Web.Config

  @token String.duplicate("t", 40)

  @web "OUROBOROS_WEB"
  @bind "OUROBOROS_WEB_BIND"
  @allow_remote "OUROBOROS_WEB_ALLOW_REMOTE"
  @token_file "OUROBOROS_WEB_TOKEN_FILE"
  @token_env "OUROBOROS_WEB_TOKEN"
  @scope "OUROBOROS_WEB_SCOPE"
  @port "OUROBOROS_WEB_PORT"
  @origin "OUROBOROS_WEB_ORIGIN"
  @data_dir "OUROBOROS_DATA_DIR"
  @gateway_token_file "OUROBOROS_GATEWAY_TOKEN_FILE"

  @managed [
    @web,
    @bind,
    @allow_remote,
    @token_file,
    @token_env,
    @scope,
    @port,
    @origin,
    @data_dir,
    @gateway_token_file
  ]

  setup do
    previous = System.get_env()

    data_dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-config-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(data_dir)
    Enum.each(@managed, &System.delete_env/1)

    on_exit(fn ->
      File.rm_rf(data_dir)
      Enum.each(@managed, &restore_env(&1, previous))
    end)

    {:ok, data_dir: data_dir}
  end

  describe "what the application layer refuses" do
    test "leaving loopback requires the override to have been typed out", %{data_dir: dir} do
      write_token(dir)

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_ALLOW_REMOTE/, fn ->
        Config.new!(data_dir: dir, bind: "0.0.0.0")
      end

      # The refusal explains the actual risk rather than only naming the flag, and it
      # names the posture that replaces it.
      assert_raise ArgumentError, ~r/no TLS/, fn ->
        Config.new!(data_dir: dir, bind: "10.0.0.4")
      end

      assert_raise ArgumentError, ~r/tailscale serve/, fn ->
        Config.new!(data_dir: dir, bind: "10.0.0.4")
      end
    end

    test "the override, typed out, is accepted", %{data_dir: dir} do
      write_token(dir)
      config = Config.new!(data_dir: dir, bind: "10.0.0.4", allow_remote: true)

      assert config.bind == {10, 0, 0, 4}
      assert config.allow_remote
    end

    test "an enabled surface with no token source is not a surface", %{data_dir: dir} do
      # No `gateway.token` in the directory, and nothing named. The path this system
      # would have defaulted to is in the message, because a reader who has not read the
      # source has no other way to learn it.
      assert_raise ArgumentError, ~r/no token source is configured/, fn ->
        Config.new!(data_dir: dir)
      end

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_TOKEN_FILE/, fn ->
        Config.new!(data_dir: dir)
      end

      assert_raise ArgumentError, ~r/gateway\.token/, fn -> Config.new!(data_dir: dir) end
    end

    test "a token file an operator named and did not create keeps the missing-file refusal",
         %{data_dir: dir} do
      named = Path.join(dir, "named.token")

      # Both variables are in the message: the gateway's, because its reader is what
      # refused, and the web's, because that is what points at this path.
      assert_raise ArgumentError, ~r/OUROBOROS_WEB_TOKEN_FILE/, fn ->
        Config.new!(data_dir: dir, token_file: named)
      end

      assert_raise ArgumentError, ~r/no such file|not readable/, fn ->
        Config.new!(data_dir: dir, token_file: named)
      end
    end

    test "a token file with the wrong mode is refused", %{data_dir: dir} do
      path = write_token(dir)
      File.chmod!(path, 0o644)

      assert_raise ArgumentError, ~r/0600|mode/, fn -> Config.new!(data_dir: dir) end
    end

    test "a token too short to be worth checking is refused", %{data_dir: dir} do
      write_token(dir)

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_TOKEN\b/, fn ->
        Config.new!(data_dir: dir, token: "hunter2")
      end

      assert_raise ArgumentError, ~r/7 bytes/, fn ->
        Config.new!(data_dir: dir, token: "hunter2")
      end
    end

    test "a surface with nowhere to publish its port is refused" do
      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn -> Config.new!(token: @token) end

      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn ->
        Config.new!(token: @token, data_dir: "   ")
      end
    end

    test "every other malformed value names its own variable", %{data_dir: dir} do
      write_token(dir)

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_PORT/, fn ->
        Config.new!(data_dir: dir, port: 70_000)
      end

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_BIND/, fn ->
        Config.new!(data_dir: dir, bind: "not-an-address")
      end

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_SCOPE/, fn ->
        Config.new!(data_dir: dir, scope: :admin)
      end

      assert_raise ArgumentError, ~r/OUROBOROS_WEB_ORIGIN/, fn ->
        Config.new!(data_dir: dir, origin: "no-host-here")
      end
    end
  end

  describe "what the config provider refuses, standing on System alone" do
    test "a non-loopback bind refuses the boot before this application is loadable",
         %{data_dir: dir} do
      path = write_token(dir)
      System.put_env(@web, "1")
      System.put_env(@data_dir, dir)
      System.put_env(@token_file, path)
      System.put_env(@bind, "0.0.0.0")

      assert_raise RuntimeError, ~r/OUROBOROS_WEB_ALLOW_REMOTE/, fn -> runtime_config() end
      assert_raise RuntimeError, ~r/no TLS/, fn -> runtime_config() end

      System.put_env(@allow_remote, "1")
      assert get_in(runtime_config(), [:ouroboros, :web, :bind]) == "0.0.0.0"
    end

    test "an enabled surface with no token source refuses the boot", %{data_dir: dir} do
      System.put_env(@web, "1")
      System.put_env(@data_dir, dir)

      assert_raise RuntimeError, ~r/requires a token/, fn -> runtime_config() end
      assert_raise RuntimeError, ~r/OUROBOROS_WEB_TOKEN_FILE/, fn -> runtime_config() end
    end

    test "the gateway's token file is what an unset web token file falls back to",
         %{data_dir: dir} do
      path = write_token(dir)
      System.put_env(@web, "1")
      System.put_env(@data_dir, dir)
      System.put_env(@gateway_token_file, path)

      assert get_in(runtime_config(), [:ouroboros, :web, :token_file]) == path
    end

    test "a surface with nowhere to publish refuses the boot", %{data_dir: dir} do
      System.put_env(@web, "1")
      System.put_env(@token_env, @token)
      System.delete_env(@data_dir)

      assert_raise RuntimeError, ~r/OUROBOROS_DATA_DIR/, fn -> runtime_config() end

      # Guard against the assertion above passing for the wrong reason: with a directory
      # it does not refuse.
      System.put_env(@data_dir, dir)
      assert get_in(runtime_config(), [:ouroboros, :web, :enabled]) == true
    end

    test "the surface is absent entirely when nobody asked for it", %{data_dir: dir} do
      System.put_env(@data_dir, dir)

      refute get_in(runtime_config(), [:ouroboros, :web])
      refute Config.enabled?()
    end

    test "scope and origin are read the way the gateway reads its own", %{data_dir: dir} do
      System.put_env(@web, "1")
      System.put_env(@data_dir, dir)
      System.put_env(@token_env, @token)
      System.put_env(@scope, "operate")
      System.put_env(@origin, "https://box.tailnet.ts.net, https://box.local")

      web = get_in(runtime_config(), [:ouroboros, :web])

      assert web[:scope] == :operate
      assert web[:origin] == ["https://box.tailnet.ts.net", "https://box.local"]

      System.put_env(@scope, "root")
      assert_raise RuntimeError, ~r/OUROBOROS_WEB_SCOPE/, fn -> runtime_config() end
    end
  end

  describe "the cookie secret" do
    test "is generated once, 0600, and never written over", %{data_dir: dir} do
      write_token(dir)

      first = Config.new!(data_dir: dir)
      path = first.secret_file

      assert path == Path.join(dir, "web.secret")
      assert %File.Stat{mode: mode, type: :regular} = File.lstat!(path)
      assert Bitwise.band(mode, 0o777) == 0o600

      # Long enough for Plug's cookie store, which is what makes a session survive a
      # restart rather than failing inside Plug.Crypto at the first request.
      assert byte_size(first.secret_key_base) >= 64
      assert String.trim(File.read!(path)) == first.secret_key_base

      second = Config.new!(data_dir: dir)

      assert second.secret_key_base == first.secret_key_base,
             "a second boot re-keyed the cookie and signed every browser out"
    end

    test "an operator-supplied secret too short for the cookie store is refused",
         %{data_dir: dir} do
      write_token(dir)
      path = Path.join(dir, "short.secret")
      File.write!(path, String.duplicate("s", 40))
      File.chmod!(path, 0o600)

      assert_raise ArgumentError, ~r/at least 64/, fn ->
        Config.new!(data_dir: dir, secret_file: path)
      end
    end

    test "a secret file with the wrong mode is refused rather than replaced",
         %{data_dir: dir} do
      write_token(dir)
      path = Path.join(dir, "loose.secret")
      File.write!(path, String.duplicate("s", 64))
      File.chmod!(path, 0o666)

      assert_raise ArgumentError, ~r/0600|mode/, fn ->
        Config.new!(data_dir: dir, secret_file: path)
      end

      assert File.read!(path) == String.duplicate("s", 64)
    end
  end

  describe "what it resolves to" do
    test "the default token file is the gateway's own credential", %{data_dir: dir} do
      path = write_token(dir)
      config = Config.new!(data_dir: dir)

      assert config.token_file == path
      assert config.token == @token
      assert config.bind == {127, 0, 0, 1}
      assert config.port == 0
      assert config.scope == :read
    end

    test "a token given as a value publishes no path to look for", %{data_dir: dir} do
      write_token(dir)
      config = Config.new!(data_dir: dir, token: @token <> "-env")

      assert config.token_file == nil
      assert config.token == @token <> "-env"
    end

    test "the defaulted posture creates the credential it shares with the gateway",
         %{data_dir: dir} do
      config = Config.new!(data_dir: dir, token_generate: true, scope: :operate)

      assert config.token_file == Path.join(dir, "gateway.token")
      assert byte_size(config.token) >= 32
      assert Bitwise.band(File.lstat!(config.token_file).mode, 0o777) == 0o600

      # And never over an existing one: a running client may already hold this token.
      again = Config.new!(data_dir: dir, token_generate: true, scope: :operate)
      assert again.token == config.token
    end

    test "neither secret is inspectable", %{data_dir: dir} do
      write_token(dir)
      rendered = inspect(Config.new!(data_dir: dir))

      assert rendered =~ "redacted"
      refute rendered =~ @token
    end

    test "an unknown key is ignored so an older node survives a newer runtime.exs",
         %{data_dir: dir} do
      write_token(dir)
      assert %Config{} = Config.new!(data_dir: dir, some_later_slice: true)
    end
  end

  defp write_token(dir, token \\ @token) do
    path = Path.join(dir, "gateway.token")
    File.write!(path, token)
    File.chmod!(path, 0o600)
    path
  end

  # `Elixir.` on purpose: `Config` is aliased to `Ouroboros.Web.Config` in this file, and
  # the reader wanted here is Elixir's own.
  defp runtime_config do
    Elixir.Config.Reader.read!("config/runtime.exs", env: :test, target: :host)
  end

  defp restore_env(name, previous) do
    case Map.fetch(previous, name) do
      {:ok, value} -> System.put_env(name, value)
      :error -> System.delete_env(name)
    end
  end
end
