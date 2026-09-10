defmodule Ouroboros.Test.ActionMessageBaseline do
  @moduledoc false
  alias Ouroboros.Signals.AgentMessage
  alias Ouroboros.Test.NativeToolBehaviorBaseline.Probe

  def action_cases do
    [
      {"required_default", %{title: "fixture"}},
      {"explicit", %{title: "fixture", count: 4, enabled: true}},
      {"empty", %{}},
      {"required_nil", %{title: nil}},
      {"optional_nil", %{title: "fixture", count: nil}},
      {"zero", %{title: "fixture", count: 0}},
      {"negative", %{title: "fixture", count: -1}},
      {"fraction", %{title: "fixture", count: 1.5}},
      {"large", %{title: "fixture", count: 9_007_199_254_740_993}},
      {"boolean", %{title: "fixture", enabled: "true"}},
      {"list_wrong", %{title: "fixture", items: %{}}},
      {"nested", %{title: "fixture", items: [%{"unknown" => [nil, true, 1]}], payload: %{}}},
      {"unknown_preserved", %{"remote_unknown" => nil, :title => "fixture", :extra => true}},
      {"string_not_converted", %{"title" => "fixture"}},
      {"atom_precedence", %{"title" => "string", :title => "atom"}},
      {"atom_wrong_type", %{"title" => "string", :title => 4}}
    ]
  end

  def message_cases do
    data = %{from: "sender", body: %{"hello" => [nil, true, 1]}, correlation_id: "corr"}
    fixed = [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"]

    [
      {"defaults", data, fixed},
      {"identity", Map.put(data, :causation_id, "cause"),
       fixed ++ [source: "sender", subject: "recipient"]},
      {"opaque_body", %{data | body: nil}, fixed},
      {"metadata", data,
       fixed ++
         [
           datacontenttype: "application/json",
           dataschema: "https://example.test/schema",
           extensions: %{"trace" => %{"span" => "opaque"}}
         ]},
      {"missing", Map.delete(data, :from), fixed},
      {"invalid_sender", %{data | from: 1}, fixed},
      {"unknown_data", Map.put(data, :unexpected, true), fixed},
      {"string_data_keys", Map.new(data, fn {k, v} -> {Atom.to_string(k), v} end), fixed},
      {"invalid_source", data, fixed ++ [source: nil]},
      {"invalid_subject", data, fixed ++ [subject: 7]},
      {"invalid_time", data, Keyword.put(fixed, :time, "yesterday")},
      {"invalid_id", data, Keyword.put(fixed, :id, "")},
      {"nil_time", data, Keyword.put(fixed, :time, nil)}
    ]
  end

  def capture do
    %{
      actions:
        Enum.map(action_cases(), fn {id, input} ->
          %{id: id, input: input, result: normalize(Probe.validate_params(input))}
        end),
      malformed_execution:
        Enum.map([nil, [], "arguments", 7], fn input ->
          %{
            input: input,
            result:
              Ouroboros.Provider.Native.Tools.execute(Probe, input, %{observer: self()}, 5_000)
          }
        end),
      messages:
        Enum.map(message_cases(), fn {id, input, opts} ->
          result =
            case observe(fn -> AgentMessage.new(input, opts) end) do
              {:ok, message} ->
                {:ok,
                 %{fields: Map.from_struct(message), wire: Jason.decode!(Jason.encode!(message))}}

              {:error, reason} ->
                {:error, reason}

              {:raised, reason} ->
                {:raised, reason}
            end

          %{id: id, input: input, opts: opts, result: result}
        end)
    }
  end

  defp observe(fun) do
    fun.()
  rescue
    error -> {:raised, Exception.message(error)}
  end

  def normalize({:error, %{__exception__: true} = reason}),
    do: {:error, Exception.message(reason)}

  def normalize(result), do: result
end
