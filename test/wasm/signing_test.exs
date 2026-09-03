defmodule Ouroboros.Wasm.SigningTest do
  # Not async: the service reads application environment for its defaults, and two tests
  # move `:signing_require_wasm_eval` and `:signing_max_artifact_bytes` to prove they are
  # read at all.
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Forge.Signer
  alias Ouroboros.Upgrade.Signing.Policy
  alias Ouroboros.Upgrade.Signing.Service
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Artifact
  alias Ouroboros.Wasm.Verifier

  @bytes "\0asm\x01\x00\x00\x00 pretend this is a component"
  @signer_id "wasm-release-key"

  # The order §7.5 states, and the order the arm checks in. Each case below moves exactly
  # one thing and names the refusal it earns, so a reordering of the checks shows up as a
  # different reason rather than as a still-passing test.
  describe "the policy arm, check by check" do
    test "admits a well-formed manifest and reports what it recomputed" do
      assert {:ok, findings} = evaluate(artifact!(), context())

      assert findings.lane == :wasm
      assert findings.world == Wasm.world()
      assert findings.component_sha256 == sha256(@bytes)
      assert findings.size == byte_size(@bytes)
      assert findings.imports == ["log"]

      assert findings.recomputed == %{
               sha256: :recomputed,
               size: :recomputed,
               bytes: byte_size(@bytes)
             }

      assert findings.provenance.author == "test-agent"
      assert findings.eval == :required_and_valid
      assert findings.start == %{id: "wasm/greeter", config_bytes: 2}
      # W8. Absent is the ordinary manifest and is said out loud rather than left out of the
      # findings: a signer that is silent about a block is one whose journal cannot later be
      # read for whether it saw one.
      assert findings.precompiled == :absent
    end

    # W8, D22. What this block authorizes is a loading node deserializing machine code it did
    # not produce, so the signer decides its shape rather than believing it. Delete
    # `check_precompiled/1` from the `with` and every case below is signed.
    test "the precompiled block is validated, and is journalled when it is there" do
      block = %{
        wasmtime: "48.0.1",
        target: "aarch64-apple-darwin",
        sha256: String.duplicate("a", 64),
        size: 258_093
      }

      assert {:ok, findings} = evaluate(artifact!(precompiled: block), context())
      assert findings.precompiled == block

      # The serialized form of a component is never the component: one is a wasm binary and
      # the other an object file. Equal digests are a manifest built out of one set of bytes
      # twice, which would have a node deserializing a component as if it were machine code.
      itself = %{block | sha256: sha256(@bytes)}

      assert {:refused, {:precompiled_is_the_component, _}} =
               evaluate(%{artifact!() | precompiled: itself}, context())

      # And the same ceiling the component is held to, times the multiple a bundle admits.
      oversize = %{block | size: 8 * 16 * 1024 * 1024 + 1}

      assert {:refused, {:precompiled_too_large, _, _}} =
               evaluate(%{artifact!() | precompiled: oversize}, context())

      # A block a manifest carried from a file, past `Artifact.build/2` entirely: the signer
      # is handed structs by `Ouroboros.Upgrade.Signing.Service`, so its own shape check is
      # the one that has to hold.
      assert {:refused, {:invalid_precompiled, _}} =
               evaluate(%{artifact!() | precompiled: Map.delete(block, :target)}, context())
    end

    test "1. shape and size come first" do
      assert {:refused, :invalid_artifact_id} = evaluate(%{artifact!() | id: ""}, context())
      assert {:refused, {:invalid_epoch, _}} = evaluate(%{artifact!() | epoch: 0}, context())

      assert {:refused, {:invalid_component_name, _}} =
               evaluate(%{artifact!() | name: ""}, context())

      assert {:refused, {:invalid_component_sha256, _}} =
               evaluate(%{artifact!() | component_sha256: "nope"}, context())

      assert {:refused, {:invalid_component_size, _}} =
               evaluate(%{artifact!() | size: 0}, context())

      assert {:refused, {:invalid_component_imports, _}} =
               evaluate(%{artifact!() | imports: [:log]}, context())

      assert {:refused, :invalid_artifact_metadata} =
               evaluate(%{artifact!() | metadata: []}, context())

      # The same bound the BEAM lane's submissions are held to, read from the context the
      # service supplies.
      assert {:refused, {:component_too_large, size, 16}} =
               evaluate(artifact!(), context(max_artifact_bytes: 16))

      assert size == byte_size(@bytes)

      # Shape outranks the world: a manifest this malformed is not a policy question.
      assert {:refused, :invalid_artifact_id} =
               evaluate(%{artifact!() | id: "", world: "other:world@1.0.0"}, context())
    end

    test "2. the world is hard, and no context widens it" do
      artifact = %{artifact!() | world: "other:world@1.0.0"}

      assert {:refused, {:world_not_supported, "other:world@1.0.0"}} =
               evaluate(artifact, context())

      # There is no flag for this, on purpose. Even a context that turns off everything
      # that *is* configurable still refuses.
      assert {:refused, {:world_not_supported, _}} =
               evaluate(artifact, context(require_wasm_eval: false))

      # And it outranks the recomputation, which would also have refused.
      assert {:refused, {:world_not_supported, _}} =
               evaluate(artifact, context(component_bytes: nil))
    end

    test "3. absent bytes are a refusal, never a pass" do
      assert {:refused, :missing_component_bytes} =
               evaluate(artifact!(), context(component_bytes: nil))

      assert {:refused, :missing_component_bytes} =
               evaluate(artifact!(), Map.delete(context(), :component_bytes))

      assert {:refused, :missing_component_bytes} =
               evaluate(artifact!(), context(component_bytes: ""))
    end

    test "3. the digest and the size are recomputed from the bytes in hand" do
      artifact = artifact!()

      assert {:refused, {:component_manifest_mismatch, :size, 4, size}} =
               evaluate(artifact, context(component_bytes: "\0asm"))

      assert size == byte_size(@bytes)

      # Same length, different bytes: only the digest catches this one.
      swapped = String.replace_prefix(@bytes, "\0asm", "\0ASM")

      assert {:refused, {:component_manifest_mismatch, :sha256}} =
               evaluate(artifact, context(component_bytes: swapped))

      # And a manifest that claims a sha the bytes do not have is refused for the same
      # reason, which is the point: nothing here believes the manifest.
      lying = %{artifact | component_sha256: String.duplicate("b", 64)}
      assert {:refused, {:component_manifest_mismatch, :sha256}} = evaluate(lying, context())
    end

    test "4. an import outside the world is refused, without parsing anything" do
      assert {:refused, {:import_not_in_world, "clock"}} =
               evaluate(%{artifact!() | imports: ["log", "clock"]}, context())

      # Declaring fewer than the world offers is fine here: the linker is the boundary,
      # and this list is provenance. `Ouroboros.Wasm.Verifier.cross_check/2` is where the
      # declared list has to equal what the helper actually found.
      assert {:ok, findings} = evaluate(%{artifact!() | imports: []}, context())
      assert findings.imports == []

      # A repeated import is refused rather than deduplicated. The list is what gets
      # signed, so a signer that silently rewrote it would be signing a different list from
      # the one it was shown — and `Ouroboros.Wasm.Verifier.cross_check/2` compares the
      # declared list against the helper's own reading, which can never repeat an import.
      # `["log", "log"]` was therefore a manifest signed into a permanent quarantine.
      assert {:refused, {:duplicate_component_imports, rendered}} =
               evaluate(%{artifact!() | imports: ["log", "log"]}, context())

      assert rendered =~ "log"
    end

    test "the component's name is held to the charset its durable id is compared in" do
      # The name is the register's `module` field and the `start` block's id. A name that
      # can hold a path separator or a bidirectional control is a name two readers can
      # disagree about, and one of those readers claims a cluster-wide process id.
      for name <- ["greeter/../evil", "Greeter", "greeter ", String.duplicate("g", 65), ""] do
        assert {:refused, {:invalid_component_name, _rendered}} =
                 evaluate(%{artifact!() | name: name}, context()),
               "the signer accepted the name #{inspect(name)}"
      end
    end

    test "5. provenance: the author is required, everything else is checked when present" do
      assert {:refused, {:provenance_missing, :author}} =
               evaluate(with_metadata(&Map.delete(&1, :author)), context())

      assert {:refused, {:invalid_provenance, :author, _}} =
               evaluate(with_metadata(&Map.put(&1, :author, 42)), context())

      assert {:refused, {:invalid_provenance, :source_sha256, _}} =
               evaluate(with_metadata(&Map.put(&1, :source_sha256, "nope")), context())

      assert {:refused, {:invalid_provenance, :language, _}} =
               evaluate(with_metadata(&Map.put(&1, :language, :rust)), context())

      assert {:refused, {:tests_failed, 2, 5}} =
               evaluate(
                 with_metadata(&Map.put(&1, :test_report, %{total: 5, failures: 2})),
                 context()
               )

      assert {:refused, {:invalid_provenance, :test_report, _}} =
               evaluate(with_metadata(&Map.put(&1, :test_report, %{total: 5})), context())

      # A guest toolchain that produces a report is welcome to say so, and a lane with no
      # analogue of one is not asked to invent it.
      assert {:ok, findings} =
               evaluate(
                 with_metadata(&Map.put(&1, :test_report, %{total: 5, failures: 0})),
                 context()
               )

      assert findings.provenance.test_report == %{total: 5, failures: 0}
      assert {:ok, findings} = evaluate(artifact!(), context())
      assert findings.provenance.test_report == nil
    end

    test "5. an eval spec is required by default and validated whenever it is there" do
      absent = with_metadata(&Map.delete(&1, :eval))

      assert {:refused, :eval_spec_required} = evaluate(absent, context())

      # The flag extends the BEAM lane's semantics rather than forking them: same
      # validator, same refusal, only the default differs.
      assert {:ok, %{eval: :absent}} = evaluate(absent, context(require_wasm_eval: false))

      invalid = with_metadata(&Map.put(&1, :eval, %{probes: []}))

      assert {:refused, {:invalid_eval_spec, :probes_required}} = evaluate(invalid, context())

      assert {:refused, {:invalid_eval_spec, :probes_required}} =
               evaluate(invalid, context(require_wasm_eval: false))

      assert {:ok, %{eval: :present}} = evaluate(artifact!(), context(require_wasm_eval: false))
    end

    test "6. a start block is optional, and bounded when present" do
      assert {:ok, %{start: :absent}} =
               evaluate(with_metadata(&Map.delete(&1, :start)), context())

      # The id is bound to *this manifest's name*, not merely to the lane's prefix. A
      # prefix bound nothing: a component named `evil` could declare `wasm/greeter`, be
      # signed, be recorded in the register as `wasm/evil`, and then claim the cluster-wide
      # durable id everybody trusts as `greeter`. It also made a traversal-shaped id and a
      # right-to-left-override id signable.
      for start <- [
            %{id: "greeter", config: "{}"},
            %{id: "wasm/", config: "{}"},
            %{id: "Elixir.Ouroboros.Capability.Sneaky", config: "{}"},
            %{id: 42, config: "{}"},
            %{id: "wasm/victim", config: "{}"},
            %{id: "wasm/greeter/../../etc/passwd", config: "{}"},
            %{id: "wasm/../../etc/passwd", config: "{}"},
            %{id: "wasm/ ", config: "{}"},
            %{id: "wasm/greeter ", config: "{}"},
            %{id: "wasm/\u{202E}retteerg", config: "{}"},
            %{id: "wasm/" <> String.duplicate("x", 300), config: "{}"},
            %{id: "WASM/greeter", config: "{}"},
            %{id: "wasm/Greeter", config: "{}"}
          ] do
        assert {:refused, {:invalid_start_id, _reason}} =
                 evaluate(with_metadata(&Map.put(&1, :start, start)), context()),
               "the signer accepted #{inspect(start.id)} for a component named greeter"
      end

      # And a component named `evil` cannot declare the id belonging to `greeter`, which is
      # the same rule read from the other side.
      squat = %{artifact!() | name: "evil"}

      assert {:refused, {:invalid_start_id, _reason}} = evaluate(squat, context())

      assert {:refused, {:invalid_start, :config}} =
               evaluate(
                 with_metadata(&Map.put(&1, :start, %{id: "wasm/greeter", config: %{}})),
                 context()
               )

      assert {:refused, {:invalid_start, :config_too_large}} =
               evaluate(
                 with_metadata(
                   &Map.put(&1, :start, %{
                     id: "wasm/greeter",
                     config: String.duplicate("x", 20_000)
                   })
                 ),
                 context()
               )

      assert {:refused, {:invalid_start, :unknown_keys}} =
               evaluate(
                 with_metadata(
                   &Map.put(&1, :start, %{id: "wasm/greeter", config: "{}", role: "worker"})
                 ),
                 context()
               )

      assert {:refused, {:invalid_start, _}} =
               evaluate(with_metadata(&Map.put(&1, :start, "wasm/greeter")), context())
    end

    test "the arm's own defaults hold when a context omits the keys" do
      # Every case above passes a fully-populated context, which means the policy's own
      # defaults — the ones a caller that is not the shipped service would land on — are
      # never exercised. These are those defaults.
      bare = %{signer_id: @signer_id, requester: node(), require_eval: false}

      # `require_wasm_eval` defaults to **true** inside the policy, not only inside the
      # service. A context that says nothing still requires a signed eval spec (D12).
      refute Map.has_key?(bare, :require_wasm_eval)

      assert {:refused, :eval_spec_required} =
               evaluate(
                 with_metadata(&Map.delete(&1, :eval)),
                 Map.put(bare, :component_bytes, @bytes)
               )

      # And the size bound falls back to `:signing_max_artifact_bytes` read here rather
      # than to no bound at all.
      previous = Application.get_env(:ouroboros, :signing_max_artifact_bytes)
      on_exit(fn -> restore(:signing_max_artifact_bytes, previous) end)
      Application.put_env(:ouroboros, :signing_max_artifact_bytes, 8)

      refute Map.has_key?(bare, :max_artifact_bytes)

      assert {:refused, {:component_too_large, size, 8}} =
               evaluate(artifact!(), Map.put(bare, :component_bytes, @bytes))

      assert size == byte_size(@bytes)

      # A configured value this build cannot use is not a licence to drop the bound.
      Application.put_env(:ouroboros, :signing_max_artifact_bytes, :unlimited)
      assert {:ok, _findings} = evaluate(artifact!(), Map.put(bare, :component_bytes, @bytes))
    end

    test "the BEAM arm is untouched by any of it" do
      # A context shaped for lane W does not change what the other arm does with a term it
      # does not recognize, and the wasm keys are simply not read.
      assert {:refused, {:invalid_artifact, _}} = evaluate(%{not: "an artifact"}, context())
      assert {:refused, {:invalid_policy_context, _}} = evaluate(artifact!(), :not_a_context)
    end
  end

  describe "the signing service" do
    test "signs a component manifest, and the loading node's verifier accepts it" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, signature} = sign(service, artifact)
      assert byte_size(signature) == 64

      assert {:ok, %{public_key: public_key}} = Service.public_info(service)
      {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer_id, value: signature})

      assert :ok = Verifier.verify(signed, @bytes, trusted_signers: %{@signer_id => public_key})

      # The signature is over the service's own derivation. Nothing about the manifest may
      # move afterwards.
      assert {:error, {:invalid_signature, @signer_id}} =
               Verifier.verify(%{signed | epoch: signed.epoch + 1}, @bytes,
                 trusted_signers: %{@signer_id => public_key}
               )
    end

    test "the advisory payload is cross-checked against this lane's own derivation" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, _signature} =
               sign(service, artifact,
                 request: %{
                   requester: node(),
                   component_bytes: @bytes,
                   payload: Artifact.signing_payload(artifact, @signer_id)
                 }
               )

      assert {:refused, {:payload_mismatch, _mine, _theirs}} =
               sign(service, artifact,
                 request: %{
                   requester: node(),
                   component_bytes: @bytes,
                   payload: "not the payload"
                 }
               )
    end

    test "a request with no component bytes is refused rather than signed" do
      service = start_service!()

      assert {:refused, :missing_component_bytes} =
               sign(service, artifact!(), request: %{requester: node()})
    end

    test "component bytes are bounded before anything looks at them" do
      # Big enough that the bound is about the component and not about the manifest beside
      # it, which is a few hundred bytes serialized.
      big = "\0asm\x01\x00\x00\x00" <> String.duplicate("x", 3_992)
      service = start_service!(max_artifact_bytes: 2_000)

      assert {:refused, {:component_too_large, 4_000, 2_000}} =
               sign(service, artifact!(bytes: big),
                 request: %{requester: node(), component_bytes: big}
               )

      # And a component this build cannot even read is a malformed request, not a policy
      # question about its digest.
      assert {:refused, {:invalid_signing_request, {:component_bytes, _}}} =
               sign(service, artifact!(), request: %{requester: node(), component_bytes: :nope})
    end

    test "a lane-W request is journaled as one, with the component it would have loaded" do
      service = start_service!()
      artifact = artifact!()

      assert {:ok, _signature} = sign(service, artifact)
      assert {:refused, _reason} = sign(service, %{artifact | world: "other:world@1.0.0"})

      assert {:ok, [issued, refused]} = Service.decisions(service)

      assert issued.lane == :wasm
      assert issued.decision == :issued
      assert issued.artifact_id == artifact.id

      assert issued.modules == [
               %{module: "wasm/greeter", disposition: :component, sha256: sha256(@bytes)}
             ]

      assert refused.lane == :wasm
      assert refused.decision == :refused
      assert refused.reason == {:world_not_supported, "other:world@1.0.0"}
    end

    test "an oversized test_report does not erase the identity of the decision" do
      # `metadata.test_report` is provenance a guest toolchain writes and a manifest
      # carries: `fetch_optional_tests/1` checks that it is a map whose `failures` is 0 and
      # nothing about its size. Six kilobytes of it — legal, signable — pushed the whole
      # findings map past the journal's ceiling, and the map collapsed to one rendered
      # string. What went with it was every structured field the policy had just proved:
      # the component sha, the world, the imports, the start id.
      service = start_service!()

      fat =
        with_metadata(
          &Map.put(&1, :test_report, %{
            total: 1,
            failures: 0,
            notes: String.duplicate("z", 6_000)
          })
        )

      assert {:ok, _signature} = sign(service, fat)
      assert {:ok, [entry]} = Service.decisions(service)
      assert entry.decision == :issued

      assert entry.findings.lane == :wasm
      assert entry.findings.component_sha256 == fat.component_sha256
      assert entry.findings.world == fat.world
      assert entry.findings.imports == fat.imports
      assert entry.findings.epoch == fat.epoch
      assert entry.findings.start == %{id: "wasm/greeter", config_bytes: 2}
      assert entry.findings.provenance.author == "test-agent"

      # Only the value that could not fit is a marker, and it says which value that was.
      assert %{too_large: rendered} = entry.findings.provenance.test_report
      assert is_binary(rendered)

      # And the entry is still bounded, which is the other half of the promise.
      assert byte_size(:erlang.term_to_binary(entry.findings)) <= 8_192
    end

    test "the require_wasm_eval switch is read from configuration and defaults to true" do
      previous = Application.get_env(:ouroboros, :signing_require_wasm_eval)
      on_exit(fn -> restore(:signing_require_wasm_eval, previous) end)

      assert {:ok, %{require_wasm_eval: true}} = Service.status(start_service!())

      Application.put_env(:ouroboros, :signing_require_wasm_eval, false)
      service = start_service!()
      assert {:ok, %{require_wasm_eval: false}} = Service.status(service)

      assert {:ok, _signature} = sign(service, with_metadata(&Map.delete(&1, :eval)))
    end

    test "the deny signer still refuses, and a Local dev signer signs through sign/2" do
      assert {:error, :signing_denied} =
               Signer.Deny.sign(Artifact.signing_payload(artifact!(), @signer_id), @signer_id)

      # `Signer.Local` implements only `sign/2` — the generic payload path. Lane W needs no
      # new callback: the payload it hands over is bytes like any other.
      {public, secret} = :crypto.generate_key(:eddsa, :ed25519)
      artifact = artifact!()

      assert {:ok, signature} =
               Signer.Local.sign(
                 Artifact.signing_payload(artifact, @signer_id),
                 @signer_id,
                 private_key: secret
               )

      {:ok, signed} = Artifact.with_signature(artifact, %{signer: @signer_id, value: signature})
      assert :ok = Verifier.verify(signed, @bytes, trusted_signers: %{@signer_id => public})
    end
  end

  ## Helpers

  defp evaluate(artifact, context), do: Policy.Default.evaluate(artifact, context)

  defp context(overrides \\ []) do
    %{
      signer_id: @signer_id,
      requester: node(),
      require_eval: false,
      require_wasm_eval: true,
      component_bytes: @bytes,
      max_artifact_bytes: 16 * 1024 * 1024,
      node: node()
    }
    |> Map.merge(Map.new(overrides))
  end

  defp artifact!(attrs \\ []) do
    {bytes, attrs} = Keyword.pop(attrs, :bytes, @bytes)

    {:ok, artifact} =
      Artifact.build(
        bytes,
        Keyword.merge(
          [
            name: "greeter",
            imports: ["log"],
            author: "test-agent",
            epoch: System.unique_integer([:positive, :monotonic]),
            eval: %{probes: [%{input: %{"n" => 1}, expect: :any_reply}], budget_ms: 1_000},
            start: %{id: "wasm/greeter", config: "{}"}
          ],
          attrs
        )
      )

    artifact
  end

  defp with_metadata(fun) do
    artifact = artifact!()
    %{artifact | metadata: fun.(artifact.metadata)}
  end

  defp sign(service, artifact, opts \\ []) do
    Service.sign_artifact(
      artifact,
      Keyword.get(opts, :signer_id, @signer_id),
      Keyword.get(opts, :request, %{requester: node(), component_bytes: @bytes}),
      service
    )
  end

  defp start_service!(opts \\ []) do
    opts =
      opts
      |> Keyword.put_new_lazy(:key_path, fn -> write_key!(:crypto.strong_rand_bytes(32)) end)
      |> Keyword.put_new(:signer_id, @signer_id)
      |> Keyword.put_new(
        :storage,
        {Jido.Storage.ETS,
         table: String.to_atom("wasm_signing_journal_#{System.unique_integer([:positive])}")}
      )
      |> Keyword.put(:name, nil)

    start_supervised!({Service, opts}, id: {Service, System.unique_integer([:positive])})
  end

  defp write_key!(contents) do
    path = Path.join(tmp_dir!(), "signer-#{System.unique_integer([:positive])}.key")
    File.write!(path, contents)
    File.chmod!(path, 0o600)
    path
  end

  defp tmp_dir! do
    directory =
      Path.join(System.tmp_dir!(), "ouroboros-wasm-signing-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
end
