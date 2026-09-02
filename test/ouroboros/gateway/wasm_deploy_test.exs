defmodule Ouroboros.Gateway.WasmDeployTest do
  # Not async: `wasm.upload` writes under this node's own data directory, and two cases
  # move `:data_dir` to say where.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm.Bundle
  alias Ouroboros.Wasm.Surface
  alias Ouroboros.Wasm.Upload

  @moduletag :capture_log

  @golden Path.expand("../../support/gateway_golden", __DIR__)
  @signer "gateway-wasm-test-key"

  setup do
    root = Path.join(System.tmp_dir!(), "ouro-gw-wasm-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    previous = Application.get_env(:ouroboros, :data_dir)
    Application.put_env(:ouroboros, :data_dir, root)
    on_exit(fn -> restore(:data_dir, previous) end)

    # A signing service under the module's own name, because `wasm.sign` reaches its signer
    # through configuration rather than through a parameter — which is the point: a socket
    # does not get to say who signs.
    key_path = Path.join(root, "signer.key")
    File.write!(key_path, :crypto.strong_rand_bytes(32))
    File.chmod!(key_path, 0o600)

    signing_node = Application.get_env(:ouroboros, :signing_node)
    Application.delete_env(:ouroboros, :signing_node)
    on_exit(fn -> restore(:signing_node, signing_node) end)

    start_supervised!(
      {Service,
       [
         name: Service,
         key_path: key_path,
         signer_id: @signer,
         storage:
           {Jido.Storage.ETS,
            table: String.to_atom("gw_wasm_journal_#{System.unique_integer([:positive])}")}
       ]}
    )

    %{root: root}
  end

  describe "the table" do
    test "all four are `:operate`, and a read listener reaches none of them" do
      for verb <- ~w(wasm.upload wasm.sign wasm.deploy wasm.rollback) do
        assert {:ok, entry} = Methods.fetch(verb)
        assert entry.scope == :operate

        # The listener's scope is the gate and it is checked before a handler runs.
        # `Ouroboros.Gateway.OperateTest` proves the socket half by enumerating every
        # operate verb from this same table; this is the table's own half of the claim.
        refute Methods.permits?(:read, entry), "#{verb} must not be reachable at read scope"
        assert Methods.permits?(:operate, entry)
      end
    end

    test "each declares a ceiling sized for the work it actually does" do
      {:ok, upload} = Methods.fetch("wasm.upload")
      {:ok, sign} = Methods.fetch("wasm.sign")
      {:ok, deploy} = Methods.fetch("wasm.deploy")

      assert sign.timeout > upload.timeout
      assert deploy.timeout > sign.timeout

      # A deploy's ceiling can fire while a peer is still staging, and `:erpc` does not
      # stop a peer. The table says `unknown` rather than letting a client read `-32005`
      # as "it did not happen".
      assert deploy.outcome == :unknown
    end

    test "every one of them has a parameter contract the reference is generated from" do
      for verb <- ~w(wasm.upload wasm.sign wasm.deploy wasm.rollback) do
        assert {:ok, %{envelope: :closed, params: params}} = Methods.params(verb)
        assert Enum.any?(params, &(&1.name == "node"))
      end
    end
  end

  describe "wasm.upload" do
    test "a file crosses in frames and the receipt says where the node is", %{root: _root} do
      assert {:ok, first} = invoke("wasm.upload", %{"offset" => 0, "data" => b64("hello ")})

      assert first.received == 6
      refute first.complete
      assert first.chunk_bytes == Upload.max_chunk_bytes()

      assert {:ok, last} =
               invoke("wasm.upload", %{
                 "upload" => first.upload,
                 "offset" => 6,
                 "data" => b64("component"),
                 "final" => true
               })

      assert last.complete
      assert last.sha256 == sha256("hello component")

      # And the bytes are exactly what was sent, readable by the verbs that consume them.
      assert {:ok, "hello component"} = Upload.take(last.upload, [])
    end

    test "the envelope is closed and every field is bounded" do
      assert {:error, code, message} =
               Methods.invoke("wasm.upload", %{"offset" => 0, "data" => b64("x"), "size" => 1})

      assert code == Methods.code(:invalid_params)
      assert message =~ "size"

      # `data` is bounded *before* it is decoded: the encoded length already states what a
      # decode would allocate, so an oversized frame costs no base64 pass.
      over = b64(:binary.copy("x", Upload.max_chunk_bytes() + 1))

      assert {:error, _code, message} =
               Methods.invoke("wasm.upload", %{"offset" => 0, "data" => over})

      assert message =~ "at most #{Upload.max_chunk_bytes()} bytes"

      assert {:error, _code, message} =
               Methods.invoke("wasm.upload", %{"offset" => 0, "data" => "not base64!!"})

      assert message =~ "base64"

      assert {:error, _code, message} = Methods.invoke("wasm.upload", %{"data" => b64("x")})
      assert message =~ "offset"

      assert {:error, _code, message} =
               Methods.invoke("wasm.upload", %{"offset" => -1, "data" => b64("x")})

      assert message =~ "offset"

      assert {:error, _code, message} =
               Methods.invoke("wasm.upload", %{
                 "offset" => 0,
                 "data" => b64("x"),
                 "final" => "yes"
               })

      assert message =~ "final"
    end

    test "an id this node did not mint is refused at the edge, before it is a filename" do
      for hostile <- ["../../etc/passwd", "..", "ZZZZ", String.duplicate("a", 33)] do
        assert {:error, code, message} =
                 Methods.invoke("wasm.upload", %{
                   "upload" => hostile,
                   "offset" => 0,
                   "data" => b64("x")
                 })

        assert code == Methods.code(:invalid_params)
        assert message =~ "upload id"
      end
    end

    test "an offset that is not where the node is answers where it is" do
      {:ok, %{upload: id}} = invoke("wasm.upload", %{"offset" => 0, "data" => b64("abcdef")})

      assert {:error, code, message, _data} =
               Methods.invoke("wasm.upload", %{
                 "upload" => id,
                 "offset" => 0,
                 "data" => b64("abcdef")
               })

      assert code == Methods.code(:invalid_params)
      assert message =~ "params.offset must be 6"
    end

    test "an unknown upload is `-32007` rather than a silent new one" do
      assert {:error, code, message} =
               Methods.invoke("wasm.upload", %{
                 "upload" => String.duplicate("0", 32),
                 "offset" => 0,
                 "data" => b64("x")
               })

      assert code == Methods.code(:not_found)
      assert message =~ "no upload"
    end
  end

  describe "wasm.sign's parameters" do
    test "the name is held to the manifest's own charset at the edge" do
      for hostile <- ["Greeter", "../etc", "wasm/greeter", String.duplicate("a", 65), " x"] do
        assert {:error, code, message} = sign(%{"name" => hostile})

        assert code == Methods.code(:invalid_params)
        assert message =~ "params.name"
      end
    end

    test "the envelope is closed, and the start id is not a field a caller may name" do
      assert {:error, _code, message} = sign(%{"start" => %{"id" => "wasm/anything"}})
      assert message =~ "start"

      # M24. Every key not in the list is refused by name, and `initial_state` is worth one
      # assertion of its own: `Ouroboros.Wasm.Rollout.start_state/2` names the six keys that
      # decide what is being evaluated, and a signed spec merges *under* them, so a key here
      # that looked like it seeded an evaluation would be a parameter promising something
      # the deployment already decided.
      for smuggled <- ["initial_state", "start_id", "signer", "trust_policy", "nodes"] do
        assert {:error, code, message} = sign(%{smuggled => %{}})
        assert code == Methods.code(:invalid_params)
        assert message =~ smuggled
      end

      # `start_config` is accepted; the id is derived from the name. There is no spelling
      # of the id a request could get wrong because there is no spelling of it at all.
      assert {:ok, %{params: params}} = Methods.params("wasm.sign")
      refute Enum.any?(params, &(&1.name == "start_id"))
      assert Enum.any?(params, &(&1.name == "start_config"))
    end

    test "the required fields are required, and the optional ones are shaped" do
      assert {:error, _code, message} = Methods.invoke("wasm.sign", %{"name" => "greeter"})
      assert message =~ "upload"

      assert {:error, _code, message} = sign(%{"author" => nil})
      assert message =~ "author"

      assert {:error, _code, message} = sign(%{"source_sha256" => "nope"})
      assert message =~ "source_sha256"

      assert {:error, _code, message} = sign(%{"imports" => ["log", 7]})
      assert message =~ "imports"

      # H3. `imports` is required, and `[]` is a real answer. The node used to resolve an
      # absent list by handing the staged, unsigned bytes to its own helper — at `:operate`,
      # before a signature existed and upstream of the signing service's rate limit.
      assert {:error, code, message} =
               Methods.invoke("wasm.sign", %{
                 "upload" => upload_id(),
                 "name" => "greeter",
                 "author" => "a"
               })

      assert code == Methods.code(:invalid_params)
      assert message =~ "params.imports is required"
      assert message =~ "does not parse unsigned bytes"

      # And the empty list is accepted as the statement it is, reaching the plane rather
      # than the validator.
      assert {:error, code, _message} = sign(%{"imports" => []})
      assert code == Methods.code(:not_found)

      assert {:error, _code, message} =
               sign(%{"start_config" => String.duplicate("x", 16_385)})

      assert message =~ "start_config"
    end
  end

  describe "the eval spec, which is the one place a client's bytes shape a signed term" do
    test "every atom in a built spec is one this module already held" do
      assert {:ok, spec} =
               build_eval(%{
                 "probes" => [
                   %{"input" => %{"greet" => "world"}},
                   %{"input" => 1, "expect" => %{"kind" => "any_reply"}},
                   %{"input" => 2, "expect" => %{"kind" => "contains", "substring" => "greet"}},
                   %{"input" => 3, "expect" => %{"kind" => "equals", "value" => %{"a" => 1}}},
                   %{
                     "input" => 4,
                     "expect" => %{
                       "kind" => "state_matches",
                       "key" => "messages_received",
                       "value" => 2
                     }
                   }
                 ],
                 "budget_ms" => 5_000,
                 "max_latency_ms" => 500,
                 "required" => %{"at_least" => 2}
               })

      assert spec.budget_ms == 5_000
      assert spec.max_latency_ms == 500
      assert spec.required == {:at_least, 2}

      assert Enum.map(spec.probes, & &1.expect) == [
               :any_reply,
               :any_reply,
               {:contains, "greet"},
               {:equals, %{"a" => 1}},
               {:state_matches, :messages_received, 2}
             ]

      # The spec this build produces is one the evaluator accepts, which is the only thing
      # that makes it worth signing.
      assert {:ok, _valid} = Ouroboros.Upgrade.Rollout.Evaluation.validate(spec)
    end

    # L6. `String.to_existing_atom/1` was the first answer and it is the wrong bound: every
    # atom the VM happens to hold — thousands of module names, every option key of every
    # dependency — was a legal state field to match on. The closed set is what
    # `Ouroboros.Wasm.Capability` declares, read from the agent rather than restated.
    test "only the wrapper agent's own state fields may be matched on" do
      fields = Methods.wasm_state_fields()

      assert :messages_received in fields
      assert :last_answer in fields

      for field <- fields do
        assert {:error, code, _message} =
                 sign(%{
                   "eval" => %{
                     "probes" => [
                       %{
                         "input" => 1,
                         "expect" => %{
                           "kind" => "state_matches",
                           "key" => Atom.to_string(field),
                           "value" => 1
                         }
                       }
                     ]
                   }
                 })

        # Past the validator and refused by the plane on the upload, which is how a valid
        # field is distinguished from a rejected one here.
        assert code == Methods.code(:not_found), "#{field} is a field of the agent's state"
      end
    end

    test "an atom this VM holds but the agent does not declare is still refused" do
      # `:gen_server` is interned in every running VM, so `String.to_existing_atom/1` would
      # have accepted it as a state field to match on. It is not one.
      assert interned?("gen_server")

      assert {:error, code, message} = state_matches_on("gen_server")
      assert code == Methods.code(:invalid_params)
      assert message =~ "field of the wasm capability's state"
      assert message =~ "messages_received"
    end

    test "a name this node has never interned is a parameter error, not a new atom" do
      key = "a_state_field_no_ouroboros_agent_declares_anywhere"
      refute interned?(key)

      assert {:error, code, message} = state_matches_on(key)

      assert code == Methods.code(:invalid_params)
      assert message =~ "field of the wasm capability's state"

      # Nothing here converts a client's bytes at all: the comparison is a string against
      # `Atom.to_string/1`, so an unknown name never becomes an atom, existing or otherwise.
      refute interned?(key)
    end

    test "the spec's envelope is closed at every level" do
      assert {:error, _code, message} = sign(%{"eval" => %{"probes" => [], "seed" => 1}})
      assert message =~ "seed"

      # `initial_state` is deliberately absent: the six keys that decide what is being
      # evaluated are the deployment's, and a signed spec merges underneath them.
      assert {:error, _code, message} =
               sign(%{"eval" => %{"probes" => [%{"input" => 1}], "initial_state" => %{}}})

      assert message =~ "initial_state"

      assert {:error, _code, message} =
               sign(%{"eval" => %{"probes" => [%{"input" => 1, "extra" => true}]}})

      assert message =~ "extra"

      assert {:error, _code, message} =
               sign(%{
                 "eval" => %{"probes" => [%{"input" => 1, "expect" => %{"kind" => "guess"}}]}
               })

      assert message =~ "must name a kind"

      assert {:error, _code, message} = sign(%{"eval" => %{"probes" => []}})
      assert message =~ "1 to 20"

      assert {:error, _code, message} = sign(%{"eval" => %{"probes" => [%{}]}})
      assert message =~ "input"

      assert {:error, _code, message} =
               sign(%{"eval" => %{"probes" => [%{"input" => 1}], "required" => "most"}})

      assert message =~ "at_least"
    end
  end

  describe "the epoch, which is not a parameter" do
    # H2. `epoch` was an optional client parameter with no ceiling. The rollout register
    # admits an epoch only *above* its watermark and refuses one at its plausibility
    # ceiling, so one deploy at the ceiling left no number that was both — on every lane-W
    # capability on that node, durably, from one `:operate` call.
    test "the envelope refuses `epoch` by name" do
      assert {:error, code, message} =
               sign(%{"epoch" => 100_000_000_000_000})

      assert code == Methods.code(:invalid_params)
      assert message =~ "epoch"

      # Any epoch, not merely a large one: there is no parameter at all.
      assert {:error, _code, message} = sign(%{"epoch" => 7})
      assert message =~ "epoch"

      refute Enum.any?(elem(Methods.params("wasm.sign"), 1).params, &(&1.name == "epoch"))
    end
  end

  describe "wasm.deploy and wasm.rollback parameters" do
    test "targets default to the driving node and are bounded" do
      assert {:error, _code, message} = Methods.invoke("wasm.deploy", %{"nodes" => []})
      assert message =~ "upload"

      assert {:error, _code, message} =
               Methods.invoke("wasm.deploy", %{"upload" => upload_id(), "nodes" => []})

      assert message =~ "1 to 32"

      assert {:error, _code, message} =
               Methods.invoke("wasm.deploy", %{
                 "upload" => upload_id(),
                 "nodes" => ["ouroboros@nowhere-in-this-fleet"]
               })

      assert message =~ "connected machine"
    end

    test "rollback takes a name and nothing else" do
      assert {:error, _code, message} =
               Methods.invoke("wasm.rollback", %{"name" => "greeter", "force" => true})

      assert message =~ "force"

      assert {:error, code, message} = Methods.invoke("wasm.rollback", %{"name" => "Greeter"})
      assert code == Methods.code(:invalid_params)
      assert message =~ "params.name"

      # A name with no live rollout is `-32007`, which is the answer an operator acts on.
      assert {:error, code, _message} = Methods.invoke("wasm.rollback", %{"name" => "greeter"})
      assert code == Methods.code(:not_found)
    end

    test "a machine this node is not connected to is refused rather than answered locally" do
      for verb <- ~w(wasm.upload wasm.sign wasm.deploy wasm.rollback) do
        params =
          Map.merge(%{"node" => "ouroboros@nowhere-in-this-fleet"}, minimal_params(verb))

        assert {:error, code, message} = Methods.invoke(verb, params)
        assert code == Methods.code(:invalid_params)
        assert message =~ "connected machine"
      end
    end
  end

  describe "the bounds a mutation would otherwise walk straight past" do
    # M25. The chunk is bounded from the *encoded* length, before a decode of it allocates
    # anything — four characters to three bytes, so the string in hand already states what a
    # decode would cost. Delete the pre-decode branch and the refusal still happens, but
    # only after building the bytes; the two are told apart by which length is reported.
    test "an oversized chunk is refused from its encoded length, not its decoded one" do
      max = Upload.max_chunk_bytes()
      over = b64(:binary.copy("x", max + 1))

      assert {:error, code, message} =
               Methods.invoke("wasm.upload", %{"offset" => 0, "data" => over})

      assert code == Methods.code(:invalid_params)
      assert message =~ "at most #{max} bytes"

      # A string that is far too long *and* not base64 at all: with the pre-decode bound it
      # never reaches `Base.decode64/1`, so the answer is about size and not about encoding.
      hostile = String.duplicate("!", max * 2)

      assert {:error, _code, message} =
               Methods.invoke("wasm.upload", %{"offset" => 0, "data" => hostile})

      assert message =~ "at most #{max} bytes",
             "an oversized frame was decoded before it was measured"
    end

    # M37. The target list is bounded before any of it is resolved.
    test "a deploy naming more machines than the bound is refused" do
      many = for n <- 1..33, do: "machine-#{n}"

      assert {:error, code, message} =
               Methods.invoke("wasm.deploy", %{"upload" => upload_id(), "nodes" => many})

      assert code == Methods.code(:invalid_params)
      assert message =~ "1 to 32"

      # Thirty-two is the bound, so thirty-two is resolved rather than refused for length —
      # and then refused for naming machines this node is not connected to.
      assert {:error, _code, message} =
               Methods.invoke("wasm.deploy", %{
                 "upload" => upload_id(),
                 "nodes" => Enum.take(many, 32)
               })

      assert message =~ "connected machine"
    end

    # L5's other half: the offset a client resumes from arrives as data, not as prose.
    test "an offset mismatch carries the held offset a client resumes from" do
      {:ok, %{upload: id}} = invoke("wasm.upload", %{"offset" => 0, "data" => b64("abcdef")})

      assert {:error, code, message, data} =
               Methods.invoke("wasm.upload", %{
                 "upload" => id,
                 "offset" => 0,
                 "data" => b64("abcdef")
               })

      assert code == Methods.code(:invalid_params)
      assert message =~ "must be 6"
      assert data == %{"reason" => "offset_mismatch", "offset" => 6}
    end
  end

  describe "the result shapes the goldens pin" do
    test "a projected deployment has exactly the fixture's shape" do
      projected = Surface.deployment(outcome()) |> Wire.to_json()
      fixture = fixture("wasm_deploy_result")["result"]

      assert shape(projected) == shape(fixture)
    end

    test "a projected rollback has exactly the fixture's shape" do
      projected =
        Surface.rollback(%{
          artifact_id: "wasm-0000000000000000000001",
          module: "wasm/vet",
          name: "vet",
          component_sha256: String.duplicate("a", 64),
          epoch: 7,
          start_id: "wasm/vet",
          state: :rolled_back,
          nodes: [:ouroboros@golden, :ouroboros@peer],
          recovery: %{ouroboros@golden: :rolled_back, ouroboros@peer: :not_needed}
        })
        |> Wire.to_json()

      assert shape(projected) == shape(fixture("wasm_rollback_result")["result"])
    end

    test "an upload receipt has exactly the fixture's shape" do
      {:ok, receipt} = invoke("wasm.upload", %{"offset" => 0, "data" => b64("x")})

      assert shape(Wire.to_json(receipt)) == shape(fixture("wasm_upload_result")["result"])
    end
  end

  ## Helpers

  defp invoke(method, params) do
    assert {:ok, result} = Methods.invoke(method, params)
    {:ok, result}
  end

  defp sign(overrides) do
    Methods.invoke(
      "wasm.sign",
      Map.merge(
        %{
          "upload" => upload_id(),
          "name" => "greeter",
          "author" => "test-agent",
          "imports" => ["log"]
        },
        overrides
      )
    )
  end

  # A syntactically valid id that names nothing, so parameter validation is reached and the
  # plane behind it is not.
  defp upload_id, do: String.duplicate("0", 32)

  # The spec the gateway builds, read back out of the manifest it was *signed into*. There
  # is no shortcut here on purpose: what matters is not what the builder returned but what
  # ended up inside a signature, and the only way to see that is to sign something.
  defp build_eval(spec) do
    bytes = "\0asm\x01\x00\x00\x00 a component this test never runs"

    {:ok, %{upload: upload}} =
      invoke("wasm.upload", %{"offset" => 0, "data" => b64(bytes), "final" => true})

    case Methods.invoke("wasm.sign", %{
           "upload" => upload,
           "name" => "greeter",
           "author" => "test-agent",
           "imports" => [],
           "eval" => spec
         }) do
      {:ok, receipt} ->
        prefix = Base.decode64!(receipt.bundle_prefix)
        {:ok, %{artifact: artifact}} = Bundle.decode(prefix <> bytes)
        {:ok, artifact.metadata.eval}

      {:error, _code, message} ->
        {:error, message}
    end
  end

  defp minimal_params("wasm.upload"), do: %{"offset" => 0, "data" => b64("x")}

  defp minimal_params("wasm.sign"),
    do: %{"upload" => upload_id(), "name" => "greeter", "author" => "a", "imports" => []}

  defp minimal_params("wasm.deploy"), do: %{"upload" => upload_id()}
  defp minimal_params("wasm.rollback"), do: %{"name" => "greeter"}

  # One rollout outcome in the shape `Ouroboros.Wasm.Rollout.deploy/4` answers with, so the
  # golden is checked against a projection of a real term rather than against itself.
  defp outcome do
    eval = %{satisfied?: true, probes: 2, passed: 2, failed: 0, total_ms: 41, failures: []}

    %{
      artifact_id: "wasm-0000000000000000000001",
      module: "wasm/vet",
      component_sha256: String.duplicate("a", 64),
      epoch: 7,
      name: "vet",
      nodes: [:ouroboros@golden, :ouroboros@peer],
      state: :live,
      stage: :evaluate,
      eval_report: %{
        spec: %{probes: 2, required: :all, budget_ms: 10_000, max_latency_ms: nil},
        compare: false,
        nodes: %{ouroboros@golden: eval, ouroboros@peer: eval}
      },
      started: %{id: "wasm/vet", node: :ouroboros@golden, errors: %{}},
      warnings: [],
      deployment: %{
        ouroboros@golden: %{stage: :ok, probe: :ok, eval: eval, recovery: nil},
        ouroboros@peer: %{stage: :ok, probe: :ok, eval: eval, recovery: nil}
      }
    }
  end

  # A structural fingerprint: keys all the way down, values reduced to their kind. What a
  # golden pins for a second implementation is the shape, and comparing values would pin
  # this test's own invented numbers instead.
  defp shape(value) when is_map(value),
    do: value |> Enum.map(fn {key, inner} -> {to_string(key), shape(inner)} end) |> Enum.sort()

  defp shape(value) when is_list(value), do: value |> Enum.map(&shape/1) |> Enum.uniq()
  defp shape(nil), do: :null
  defp shape(value) when is_binary(value), do: :string
  defp shape(value) when is_integer(value), do: :integer
  defp shape(value) when is_boolean(value), do: :boolean
  defp shape(_other), do: :other

  defp fixture(name) do
    @golden |> Path.join(name <> ".json") |> File.read!() |> JSON.decode!()
  end

  defp state_matches_on(key) do
    sign(%{
      "eval" => %{
        "probes" => [
          %{"input" => 1, "expect" => %{"kind" => "state_matches", "key" => key, "value" => 1}}
        ]
      }
    })
  end

  defp b64(bytes), do: Base.encode64(bytes)
  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp interned?(name) do
    _atom = String.to_existing_atom(name)
    true
  rescue
    ArgumentError -> false
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
