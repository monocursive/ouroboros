defmodule Ouroboros.Control.EvidenceContractTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Control.EvidenceContract

  @digest String.duplicate("a", 64)

  test "normalizes string-keyed content-minimized evidence" do
    contract = %{
      "version" => 1,
      "evidence" => [
        %{
          "id" => "mix-test",
          "kind" => "test",
          "outcome" => "pass",
          "digest" => @digest,
          "recorded_at" => 1_700_000_000_000
        }
      ],
      "criteria" => [
        %{"id" => "tests-pass", "status" => "met", "evidence_ids" => ["mix-test"]}
      ],
      "claims" => [
        %{
          "id" => "verified",
          "classification" => "observed",
          "status" => "supported",
          "statement_digest" => @digest,
          "evidence_ids" => ["mix-test"]
        },
        %{
          "id" => "future-risk",
          "classification" => "assumed",
          "status" => "unknown",
          "statement_digest" => @digest,
          "evidence_ids" => []
        }
      ]
    }

    assert {:ok, normalized} = EvidenceContract.normalize(contract)
    assert normalized.version == 1
    assert hd(normalized.evidence).kind == :test
    assert hd(normalized.criteria).status == :met
    assert Enum.map(normalized.claims, & &1.classification) == [:observed, :assumed]
    assert {:ok, digest} = EvidenceContract.digest(normalized)
    assert byte_size(digest) == 64
  end

  test "requires evidence for decisive claims and criteria" do
    contract = %{
      version: 1,
      evidence: [],
      criteria: [%{id: "tests", status: :met, evidence_ids: []}],
      claims: []
    }

    assert {:error, {:criteria, {:missing_evidence, :criterion}}} =
             EvidenceContract.normalize(contract)
  end

  test "rejects content fields and dangling evidence references" do
    evidence = %{
      id: "test",
      kind: :test,
      outcome: :pass,
      digest: @digest,
      recorded_at: 1,
      output: "secret output"
    }

    assert {:error, {:evidence, {:unknown_field, :output}}} =
             EvidenceContract.normalize(%{
               version: 1,
               evidence: [evidence],
               criteria: [%{id: "tests", status: :unknown, evidence_ids: []}],
               claims: []
             })

    assert {:error, {:criteria, {:unknown_evidence, ["missing"]}}} =
             EvidenceContract.normalize(%{
               version: 1,
               evidence: [],
               criteria: [%{id: "tests", status: :unknown, evidence_ids: ["missing"]}],
               claims: []
             })
  end
end
