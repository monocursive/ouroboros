defmodule Ouroboros.Gateway.ConfigTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Gateway.Config

  @token String.duplicate("t", 32)

  setup context do
    if tmp_dir = Map.get(context, :tmp_dir), do: File.chmod!(tmp_dir, 0o700)
    :ok
  end

  defp valid(overrides \\ []) do
    Keyword.merge([token: @token, data_dir: "/tmp/ouroboros-gateway-test"], overrides)
  end

  describe "what it refuses" do
    test "a gateway with no token source is not a gateway" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN_FILE/, fn ->
        Config.new!(data_dir: "/tmp/ouroboros-gateway-test")
      end

      # The fallback variable is named too: an operator who reached for the env var is
      # the one most likely to have left it unset.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN\b/, fn ->
        Config.new!(data_dir: "/tmp/ouroboros-gateway-test")
      end
    end

    test "a token too short to be worth checking is refused, with its length named" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN/, fn ->
        Config.new!(valid(token: "hunter2"))
      end

      assert_raise ArgumentError, ~r/7 bytes/, fn -> Config.new!(valid(token: "hunter2")) end
    end

    test "leaving loopback requires the override to have been typed out" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_ALLOW_REMOTE/, fn ->
        Config.new!(valid(bind: "0.0.0.0"))
      end

      # The refusal explains the actual risk rather than only naming the flag.
      assert_raise ArgumentError, ~r/cleartext/, fn -> Config.new!(valid(bind: "10.0.0.4")) end
    end

    test "an enabled gateway with nowhere to publish its port is refused" do
      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn -> Config.new!(token: @token) end

      assert_raise ArgumentError, ~r/OUROBOROS_DATA_DIR/, fn ->
        Config.new!(token: @token, data_dir: "   ")
      end
    end

    test "every other malformed value names its own variable" do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_PORT/, fn ->
        Config.new!(valid(port: 70_000))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_BIND/, fn ->
        Config.new!(valid(bind: "not-an-address"))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_SCOPE/, fn ->
        Config.new!(valid(scope: :admin))
      end

      # A max frame below the size of a `hello` would fail every connection with an
      # error naming the wrong cause.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_MAX_FRAME/, fn ->
        Config.new!(valid(max_frame: 16))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_QUEUE_LIMIT/, fn ->
        Config.new!(valid(queue_limit: 0))
      end

      # A byte cap below the floor makes every event payload a wall of markers naming
      # sizes and showing nothing. The listener refuses rather than starting like that.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_EVENT_LEAF_BYTES/, fn ->
        Config.new!(valid(event_leaf_bytes: 64))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_EVENT_PAYLOAD_BYTES/, fn ->
        Config.new!(valid(event_payload_bytes: "512k"))
      end

      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_DETAIL_LEAF_BYTES/, fn ->
        Config.new!(valid(detail_leaf_bytes: 0))
      end
    end

    test "an unreadable token file is refused by path" do
      path = Path.join(System.tmp_dir!(), "ouroboros-gateway-absent-#{System.unique_integer()}")

      error =
        assert_raise ArgumentError, fn ->
          Config.new!(token_file: path, data_dir: "/tmp/ouroboros-gateway-test")
        end

      assert error.message =~ "OUROBOROS_GATEWAY_TOKEN_FILE=#{path}"
      assert error.message =~ "no such file or directory"

      # The generation flag is the only thing that changes this, and it is off unless the
      # posture that chose the path also asked for it.
      assert_raise ArgumentError, ~r/no such file or directory/, fn ->
        Config.new!(token_file: path, token_generate: false, data_dir: "/tmp/x")
      end
    end
  end

  describe "generating a token" do
    import Bitwise

    @tag :tmp_dir
    test "a first boot writes a 0600 credential and every boot after it reads that one", %{
      tmp_dir: tmp_dir
    } do
      path = Path.join(tmp_dir, "gateway.token")

      config = Config.new!(token_file: path, token_generate: true, data_dir: tmp_dir)

      assert File.exists?(path)
      assert (File.stat!(path).mode &&& 0o777) == 0o600

      # 32 random bytes as hex, which is the floor the struct enforces twice over.
      assert byte_size(config.token) == 64
      assert config.token =~ ~r/\A[0-9a-f]{64}\z/
      assert File.read!(path) == config.token
      assert config.token_file == path
      assert config.token_generate == true

      # The second boot is the one that matters: a daemon that re-keyed itself on restart
      # would lock out the client holding the token from the first.
      again = Config.new!(token_file: path, token_generate: true, data_dir: tmp_dir)

      assert again.token == config.token

      # Nothing is left behind in the directory the token is written into.
      assert File.ls!(tmp_dir) == ["gateway.token"]
    end

    @tag :tmp_dir
    test "an existing credential is never replaced, whatever wrote it", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "gateway.token")
      existing = String.duplicate("e", 48)
      File.write!(path, existing <> "\n")

      config = Config.new!(token_file: path, token_generate: true, data_dir: tmp_dir)

      assert config.token == existing
      assert File.read!(path) == existing <> "\n"
    end

    @tag :tmp_dir
    test "generation still holds every other rule the struct enforces", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "gateway.token")

      # A generated token is not an excuse to leave loopback, and the refusal comes before
      # anything is written.
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_ALLOW_REMOTE/, fn ->
        Config.new!(token_file: path, token_generate: true, data_dir: tmp_dir, bind: "0.0.0.0")
      end

      refute File.exists?(path)
    end

    @tag :tmp_dir
    test "the flag alone generates nothing: there has to be a path to write", %{tmp_dir: tmp_dir} do
      assert_raise ArgumentError, ~r/OUROBOROS_GATEWAY_TOKEN_FILE/, fn ->
        Config.new!(token_generate: true, data_dir: tmp_dir)
      end

      assert File.ls!(tmp_dir) == []
    end
  end

  describe "what it accepts" do
    test "loopback defaults, with the ephemeral port that removes the bind race" do
      config = Config.new!(valid())

      assert config.bind == {127, 0, 0, 1}
      assert config.port == 0
      assert config.scope == :read
      assert config.allow_shutdown == false
      assert config.token_generate == false
      assert config.max_frame == 1_048_576
      assert config.queue_limit == 1_000
      assert config.event_leaf_bytes == 131_072
      assert config.event_payload_bytes == 524_288
      assert config.detail_leaf_bytes == 8_388_608
    end

    test "the encoder reads the same caps this struct validates" do
      # `Wire` cannot reach a connection's struct from a replay task, so it resolves the
      # caps itself. What it resolves has to be what an operator configured, and what it
      # falls back to has to be what `new!/1` would have handed a listener.
      assert Config.event_limits() == %{
               event_leaf_bytes: 131_072,
               event_payload_bytes: 524_288,
               detail_leaf_bytes: 8_388_608
             }

      assert Config.event_limits(event_leaf_bytes: 4_096).event_leaf_bytes == 4_096

      # The refusal already happened at boot: `new!/1` above rejects the same value. So a
      # cap that is somehow still unusable when a frame is halfway written falls back
      # rather than killing the connection that was writing it.
      assert Config.event_limits(event_leaf_bytes: 8).event_leaf_bytes == 131_072
      assert Config.event_limits(detail_leaf_bytes: nil).detail_leaf_bytes == 8_388_608
    end

    test "a token file wins over the environment token and is trimmed" do
      path = Path.join(System.tmp_dir!(), "ouroboros-gateway-token-#{System.unique_integer()}")
      File.write!(path, "  " <> String.duplicate("f", 40) <> "\n")
      on_exit(fn -> File.rm(path) end)

      config = Config.new!(token_file: path, token: @token, data_dir: "/tmp/x")

      assert config.token == String.duplicate("f", 40)

      # The path is kept because `gateway.json` publishes it: a client that did not spawn
      # this daemon has to be told where the credential is, and a path is not one.
      assert config.token_file == path
    end

    test "an environment token publishes no path, because there is no file to name" do
      config = Config.new!(valid())

      assert config.token == @token
      assert is_nil(config.token_file)
    end

    test "a non-loopback bind is accepted once the override says so" do
      config = Config.new!(valid(bind: "0.0.0.0", allow_remote: true))

      assert config.bind == {0, 0, 0, 0}
      assert config.allow_remote == true
      refute Config.loopback?(config.bind)
    end

    test "IPv6 loopback is loopback" do
      config = Config.new!(valid(bind: "::1"))

      assert config.bind == {0, 0, 0, 0, 0, 0, 0, 1}
      assert Config.loopback?(config.bind)
      assert Config.bind_to_string(config.bind) == "::1"
    end

    test "an unknown key is ignored so an older node survives a newer runtime.exs" do
      assert %Config{} = Config.new!(valid(subscriptions_enabled: true))
    end
  end

  describe "inspection" do
    test "the token never renders, and everything else still does" do
      rendered = inspect(Config.new!(valid(port: 4560)))

      refute rendered =~ @token
      assert rendered =~ "redacted"
      assert rendered =~ "4560"
    end
  end

  test "a node that was never told to serve a gateway does not serve one" do
    refute Config.enabled?()
  end
end
