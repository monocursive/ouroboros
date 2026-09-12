defmodule Ouroboros.Runtime.SafeStatusTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias Ouroboros.Runtime.SafeStatus
  @secret "SECRET_CANARY_NEVER_PUBLISH_4fb857"

  test "emits one closed string-keyed bounded wire shape" do
    assert {:ok, status} = SafeStatus.session(facts(), 1_100)
    assert status["scope"] == "session"
    assert status["owner"] == "session-1"
    assert status["freshness"] == "fresh"
    assert status["provenance"] == "interactive_owner"

    assert status["identity"] == %{
             "logical_id" => "logical-1",
             "native_id" => "native-1",
             "runtime_id" => "runtime-1",
             "generation" => "generation-4",
             "pid" => 321,
             "port" => 4560,
             "birth" => "macos:birth-1"
           }

    assert status["listener"]["publication"] == "available"
    assert status["activity"] == %{"owner_active" => true, "turn_id" => "turn-7"}
    assert status["posture"] == %{"sandbox" => "workspace_write", "approval" => "prompt"}

    assert status["credentials"] == [
             %{"provider" => "openai", "present" => true, "source" => "file"}
           ]

    assert byte_size(JSON.encode!(status)) <= SafeStatus.limits().output_bytes
  end

  test "credential observations are a closed enum and unknown cannot become false" do
    for state <- [:invalid, :unavailable, @secret, nil] do
      rows = [%{provider: :openai_codex, present: false, source: nil, credential_state: state}]
      assert {:ok, status} = SafeStatus.session(Map.put(facts(), :credentials, rows), 1_100)
      assert [row] = status["credentials"]
      assert row["present"] == nil
      assert row["credential_state"] in ["invalid", "unavailable"]
      refute JSON.encode!(status) =~ @secret
    end
  end

  test "compatibility API is only consistency checking and refuses mismatches" do
    assert {:ok, _} =
             SafeStatus.project(Map.put(facts(), :scope, :session), %{
               scope: :session,
               owner: "session-1",
               now_ms: 1_100
             })

    assert {:error, :scope_refused} =
             SafeStatus.project(Map.put(facts(), :scope, :runtime), %{
               scope: :runtime,
               owner: "session-1",
               now_ms: 1_100
             })

    assert {:error, :ownership_refused} =
             SafeStatus.project(Map.put(facts(), :scope, :session), %{
               scope: :session,
               owner: "session-2",
               now_ms: 1_100
             })
  end

  test "missing invalid future and stale time fail closed" do
    for now <- [nil, -10_000_000_000_000_000_000, "1100"] do
      assert {:error, :invalid_observation_time} = SafeStatus.session(facts(), now)
    end

    for observed <- [nil, -1, "1000", 1_101, 1] do
      assert {:ok, status} = SafeStatus.session(%{facts() | observed_at_ms: observed}, 100_000)
      assert status["freshness"] in ["unknown", "stale"]
      assert Enum.all?(status["identity"], fn {_key, value} -> is_nil(value) end)
      assert status["activity"] == %{"owner_active" => nil, "turn_id" => nil}
      assert status["credentials"] == []
    end
  end

  test "incoherent and independently stale publication is unavailable" do
    for listener <- [
          %{publication: :available, observed_at_ms: 1_000, port: 9999, birth: "macos:other"},
          %{
            publication: :available,
            observed_at_ms: -100_000,
            port: 4560,
            birth: "macos:birth-1"
          },
          %{}
        ] do
      assert {:ok, status} = SafeStatus.session(%{facts() | listener: listener}, 1_100)
      assert status["listener"]["publication"] == "unavailable"
      assert status["listener"]["port"] == nil
      assert status["listener"]["birth"] == nil
    end
  end

  test "huge numbers and semantic canaries cannot escape output-capable fields" do
    huge = 1 <<< 200_000

    hostile =
      facts()
      |> put_in([:identity, :logical_id], "/private/#{@secret}")
      |> put_in([:identity, :native_id], "/private/#{@secret}")
      |> put_in([:identity, :pid], huge)
      |> put_in([:deadlines, :effective_ms], huge)
      |> put_in([:activity, :turn_id], "/private/#{@secret}")
      |> Map.put(:credentials, [
        %{provider: @secret, present: true, source: :environment, value: @secret},
        %{provider: :openai, present: true, source: :file},
        %{provider: :openai, present: false, source: :environment}
      ])
      |> Map.put(:prompt, @secret)

    assert {:ok, status} = SafeStatus.session(hostile, 1_100)
    encoded = JSON.encode!(status)
    refute encoded =~ @secret
    refute encoded =~ "/private/"
    assert status["identity"]["pid"] == nil
    assert status["deadlines"]["effective_ms"] == nil

    assert status["credentials"] == [
             %{"provider" => "openai", "present" => true, "source" => "file"}
           ]
  end

  defp facts do
    %{
      owner: "session-1",
      observed_at_ms: 1_000,
      identity: %{
        logical_id: "logical-1",
        native_id: "native-1",
        runtime_id: "runtime-1",
        generation: "generation-4",
        pid: 321,
        port: 4560,
        birth: "macos:birth-1"
      },
      listener: %{
        publication: :available,
        observed_at_ms: 1_000,
        port: 4560,
        birth: "macos:birth-1"
      },
      activity: %{owner_active: true, turn_id: "turn-7"},
      posture: %{sandbox: :workspace_write, approval: :prompt},
      deadlines: %{requested_ms: 120_000, effective_ms: 60_000},
      credentials: [%{provider: :openai, present: true, source: :file}]
    }
  end
end
