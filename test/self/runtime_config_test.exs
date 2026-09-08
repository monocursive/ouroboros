defmodule Ouroboros.Self.RuntimeConfigTest do
  @moduledoc """
  `config/runtime.exs` itself, evaluated (S4).

  `test/upgrade/runtime_config_test.exs`' seam — `Config.Reader.read!/2` over the real file —
  because the two claims below are about the file and not about the function it calls:
  the `self` posture has to be readable in **every** environment, and a production node has
  to keep S2's promotion record somewhere that survives a restart.

  Not async: every case here writes process-global environment variables.
  """

  use ExUnit.Case, async: false

  @posture "OUROBOROS_POSTURE"
  @model "OUROBOROS_NATIVE_MODEL"
  @signing_node "OUROBOROS_SIGNING_NODE"
  @signers "OUROBOROS_UPGRADE_TRUSTED_SIGNERS"
  @self_ship "OUROBOROS_SELF_SHIP"
  @key_path "OUROBOROS_SIGNER_KEY_PATH"
  @signer_id "OUROBOROS_SIGNER_ID"
  @data_dir "OUROBOROS_DATA_DIR"

  @touched [
    @posture,
    @model,
    @signing_node,
    @signers,
    @self_ship,
    @key_path,
    @signer_id,
    @data_dir
  ]

  setup do
    previous = System.get_env()

    data_dir =
      Path.join(System.tmp_dir!(), "ouro-self-runtime-#{System.unique_integer([:positive])}")

    Enum.each(@touched, &System.delete_env/1)
    System.put_env(@data_dir, data_dir)

    on_exit(fn ->
      File.rm_rf(data_dir)
      Enum.each(@touched, &restore(&1, previous))
    end)

    {public, _private} = :crypto.generate_key(:eddsa, :ed25519, :crypto.strong_rand_bytes(32))

    %{data_dir: data_dir, public: public, signers: "self-dev:" <> Base.encode64(public)}
  end

  describe "the promotion record in production" do
    test "is a synced durable file under the data directory", %{data_dir: data_dir} do
      assert get_in(config(:prod), [:ouroboros, :policy_promotion_storage]) ==
               {Ouroboros.Storage.DurableFile, path: Path.join(data_dir, "policy-promotion")}
    end

    test "sits beside the grants it is the second half of", %{data_dir: data_dir} do
      config = config(:prod)

      # S2's record decides what an `allow` from a signed component may widen, which is the
      # same class of authority `:grants_storage` holds. Both are synced, both are under the
      # data directory, and neither is ETS in production.
      assert {Ouroboros.Storage.DurableFile, path: grants} =
               get_in(config, [:ouroboros, :grants_storage])

      assert {Ouroboros.Storage.DurableFile, path: promotion} =
               get_in(config, [:ouroboros, :policy_promotion_storage])

      assert Path.dirname(grants) == data_dir
      assert Path.dirname(promotion) == data_dir
    end
  end

  describe "the posture, read in every environment" do
    test "is off by default, and configures none of its keys", %{data_dir: _dir} do
      for env <- [:dev, :test, :prod] do
        ouroboros = config(env)[:ouroboros] || []

        refute Keyword.has_key?(ouroboros, :self_posture)
        refute Keyword.has_key?(ouroboros, :self_ship)
        refute Keyword.get(ouroboros, :native_forge_tool)
        refute Keyword.get(ouroboros, :permissions_engine)
      end
    end

    test "turns the runtime on outside production, which is where the dev loop is",
         %{signers: signers, public: public} do
      System.put_env(@posture, "self")
      System.put_env(@model, "anthropic:claude-sonnet-5")
      System.put_env(@signing_node, "signer@fleet")
      System.put_env(@signers, signers)

      for env <- [:dev, :prod] do
        ouroboros = config(env)[:ouroboros]

        assert ouroboros[:self_posture] == true
        assert ouroboros[:self_ship] == true
        assert ouroboros[:native_forge_tool] == true
        assert ouroboros[:permissions_engine] == Ouroboros.Wasm.PolicyEngine
        assert ouroboros[:signing_node] == :signer@fleet

        assert ouroboros[:upgrade_trust_policy] == [
                 allow_unsigned: false,
                 trusted_signers: %{"self-dev" => public}
               ]
      end
    end

    test "closes `allow_unsigned`, which config/config.exs leaves open outside production",
         %{signers: signers} do
      System.put_env(@posture, "self")
      System.put_env(@model, "anthropic:claude-sonnet-5")
      System.put_env(@signing_node, "signer@fleet")
      System.put_env(@signers, signers)

      # The compile-time default outside production is `allow_unsigned: true`. The posture's
      # arm runs after everything else in this file, so its value is the one of record.
      assert Application.get_env(:ouroboros, :upgrade_trust_policy)[:allow_unsigned] == true
      assert config(:dev)[:ouroboros][:upgrade_trust_policy][:allow_unsigned] == false
    end

    test "the one-machine arm names the key the application will load", %{
      signers: signers,
      data_dir: data_dir
    } do
      File.mkdir_p!(data_dir)
      # `Ouroboros.DataDir` refuses a data directory anyone but its owner can read, and it
      # will not chmod one it did not create, so a test that makes one makes it right.
      File.chmod!(data_dir, 0o700)
      key = Path.join(data_dir, "signer.key")
      File.write!(key, Base.encode64(:crypto.strong_rand_bytes(32)))
      File.chmod!(key, 0o600)

      System.put_env(@posture, "self")
      System.put_env(@model, "anthropic:claude-sonnet-5")
      System.put_env(@key_path, key)
      System.put_env(@signer_id, "self-dev")
      System.put_env(@signers, signers)

      ouroboros = config(:dev)[:ouroboros]

      assert ouroboros[:signer_key_path] == key
      assert ouroboros[:signer_id] == "self-dev"
      refute Keyword.has_key?(ouroboros, :signing_node)
    end

    test "OUROBOROS_SELF_SHIP=false keeps the posture and drops priv/self", %{signers: signers} do
      System.put_env(@posture, "self")
      System.put_env(@model, "anthropic:claude-sonnet-5")
      System.put_env(@signing_node, "signer@fleet")
      System.put_env(@signers, signers)
      System.put_env(@self_ship, "false")

      ouroboros = config(:dev)[:ouroboros]

      assert ouroboros[:self_posture] == true
      assert ouroboros[:self_ship] == false
    end
  end

  describe "the posture refuses the boot" do
    test "when a required variable is missing", %{signers: signers} do
      System.put_env(@posture, "self")
      System.put_env(@signing_node, "signer@fleet")
      System.put_env(@signers, signers)

      assert_raise RuntimeError, ~r/requires OUROBOROS_NATIVE_MODEL/, fn -> config(:dev) end
    end

    test "when it trusts nobody" do
      System.put_env(@posture, "self")
      System.put_env(@model, "anthropic:claude-sonnet-5")
      System.put_env(@signing_node, "signer@fleet")

      assert_raise RuntimeError, ~r/requires OUROBOROS_UPGRADE_TRUSTED_SIGNERS/, fn ->
        config(:dev)
      end
    end

    test "when the posture is a name this build does not have" do
      System.put_env(@posture, "paranoid")

      assert_raise RuntimeError, ~r/OUROBOROS_POSTURE must be/, fn -> config(:dev) end
      assert_raise RuntimeError, ~r/OUROBOROS_POSTURE must be/, fn -> config(:prod) end
    end
  end

  defp config(env), do: Config.Reader.read!("config/runtime.exs", env: env, target: :host)

  defp restore(name, previous) do
    case Map.fetch(previous, name) do
      {:ok, value} -> System.put_env(name, value)
      :error -> System.delete_env(name)
    end
  end
end
