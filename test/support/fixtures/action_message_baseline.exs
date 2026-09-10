# Frozen with pre-J3 dependencies. Do not regenerate using the owned implementation.
%{
  sources: %{
    "lib/ouroboros/provider/native/tools.ex" =>
      "bc35414ef2a88904135e4a4ebb57c75ea76b9c47deef5d3c243c6016e1e1e32d",
    "lib/ouroboros/signals.ex" =>
      "e5bf668374baa0653c5fed033c1cae50a21be7d90b112a42838ad2bac9a2ebe7",
    "test/support/native_tool_behavior_baseline.ex" =>
      "ef353ae3c31eb440d975614170362f86ad5cd93320dcad784d852c6edab0d319"
  },
  source_revision: "4dc862776b754544459967e5d292e81497d569b6",
  packages: %{
    jido:
      {:hex, :jido, "2.3.3", "ee4b61e0c08e073c1bda15fd937851a17a5f846fba767759f4772ad31a42d5df",
       [:mix],
       [
         {:crontab, "~> 1.2", [hex: :crontab, repo: "hexpm", optional: false]},
         {:igniter, "~> 0.7", [hex: :igniter, repo: "hexpm", optional: true]},
         {:jido_action, "~> 2.3", [hex: :jido_action, repo: "hexpm", optional: false]},
         {:jido_signal, "~> 2.2", [hex: :jido_signal, repo: "hexpm", optional: false]},
         {:nimble_options, "~> 1.1", [hex: :nimble_options, repo: "hexpm", optional: false]},
         {:poolboy, "~> 1.5", [hex: :poolboy, repo: "hexpm", optional: false]},
         {:splode, "~> 0.3.0", [hex: :splode, repo: "hexpm", optional: false]},
         {:telemetry, "~> 1.3", [hex: :telemetry, repo: "hexpm", optional: false]},
         {:telemetry_metrics, "~> 1.1",
          [hex: :telemetry_metrics, repo: "hexpm", optional: false]},
         {:time_zone_info, "~> 0.7", [hex: :time_zone_info, repo: "hexpm", optional: false]}
       ], "hexpm", "efed04440117d30c2d5bf75cc4feb9f41144862a6fb54c729c0add04590caaba"},
    jido_action:
      {:hex, :jido_action, "2.3.2",
       "e52bc949db4dedff523850172555629b29ffaa11fec162e728d5b7e43e7235d5", [:mix],
       [
         {:igniter, "~> 0.7", [hex: :igniter, repo: "hexpm", optional: true]},
         {:jason, "~> 1.4", [hex: :jason, repo: "hexpm", optional: false]},
         {:lua, "~> 0.4 or ~> 1.0.0-rc", [hex: :lua, repo: "hexpm", optional: true]},
         {:multigraph, "~> 0.16.1-mg.3", [hex: :multigraph, repo: "hexpm", optional: false]},
         {:nimble_options, "~> 1.1", [hex: :nimble_options, repo: "hexpm", optional: false]},
         {:req, "~> 0.7.2", [hex: :req, repo: "hexpm", optional: true]},
         {:splode, "~> 0.3.0", [hex: :splode, repo: "hexpm", optional: false]},
         {:telemetry, "~> 1.3", [hex: :telemetry, repo: "hexpm", optional: false]},
         {:zoi, "~> 0.17", [hex: :zoi, repo: "hexpm", optional: false]}
       ], "hexpm", "e6e222e5c8da489de36d637930628d56fb898b072a17cd467d27bf4f5ecb63e4"},
    nimble_options:
      {:hex, :nimble_options, "1.1.1",
       "e3a492d54d85fc3fd7c5baf411d9d2852922f66e69476317787a7b2bb000a61b", [:mix], [], "hexpm",
       "821b2470ca9442c4b6984882fe9bb0389371b8ddec4d45a9504f00a66f650b44"},
    jido_signal:
      {:hex, :jido_signal, "2.2.2",
       "419a1c0f26e86cf53b73d37ffc6200bd534d7d98048606e36d5e9a19191bf987", [:mix],
       [
         {:fuse, "~> 2.5", [hex: :fuse, repo: "hexpm", optional: false]},
         {:igniter, "~> 0.7", [hex: :igniter, repo: "hexpm", optional: true]},
         {:jason, "~> 1.4", [hex: :jason, repo: "hexpm", optional: false]},
         {:msgpax, "~> 2.3", [hex: :msgpax, repo: "hexpm", optional: true]},
         {:nimble_options, "~> 1.1", [hex: :nimble_options, repo: "hexpm", optional: false]},
         {:phoenix_pubsub, "~> 2.1", [hex: :phoenix_pubsub, repo: "hexpm", optional: true]},
         {:splode, "~> 0.3.0", [hex: :splode, repo: "hexpm", optional: false]},
         {:telemetry, "~> 1.3", [hex: :telemetry, repo: "hexpm", optional: false]},
         {:zoi, "~> 0.18.1", [hex: :zoi, repo: "hexpm", optional: false]}
       ], "hexpm", "60c35f022e6efd379b84a3f5c0af10b2ae5213f3d61c6211a299bc6dcc4be531"}
  },
  observations: %{
    messages: [
      %{
        id: "defaults",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: nil
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "2026-09-10T12:00:00.000000Z",
               extensions: %{},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => "2026-09-10T12:00:00.000000Z",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "identity",
        input: %{
          body: %{"hello" => [nil, true, 1]},
          from: "sender",
          correlation_id: "corr",
          causation_id: "cause"
        },
        opts: [
          id: "019935ce-c000-7000-8000-000000000001",
          time: "2026-09-10T12:00:00.000000Z",
          source: "sender",
          subject: "recipient"
        ],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: "cause"
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "2026-09-10T12:00:00.000000Z",
               extensions: %{},
               source: "sender",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: "recipient"
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => "cause",
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "sender",
               "specversion" => "1.0.2",
               "subject" => "recipient",
               "time" => "2026-09-10T12:00:00.000000Z",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "opaque_body",
        input: %{body: nil, from: "sender", correlation_id: "corr"},
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:ok,
           %{
             fields: %{
               data: %{body: nil, from: "sender", correlation_id: "corr", causation_id: nil},
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "2026-09-10T12:00:00.000000Z",
               extensions: %{},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => nil,
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => "2026-09-10T12:00:00.000000Z",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "metadata",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [
          id: "019935ce-c000-7000-8000-000000000001",
          time: "2026-09-10T12:00:00.000000Z",
          datacontenttype: "application/json",
          dataschema: "https://example.test/schema",
          extensions: %{"trace" => %{"span" => "opaque"}}
        ],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: nil
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "2026-09-10T12:00:00.000000Z",
               extensions: %{"trace" => %{"span" => "opaque"}},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: "https://example.test/schema",
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => "https://example.test/schema",
               "extensions" => %{"trace" => %{"span" => "opaque"}},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => "2026-09-10T12:00:00.000000Z",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "missing",
        input: %{body: %{"hello" => [nil, true, 1]}, correlation_id: "corr"},
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:error,
           "Invalid parameters for Signal (Elixir.Ouroboros.Signals.AgentMessage): required :from option not found, received options: [:body, :correlation_id]"}
      },
      %{
        id: "invalid_sender",
        input: %{body: %{"hello" => [nil, true, 1]}, from: 1, correlation_id: "corr"},
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:error,
           "Invalid parameters for Signal (Elixir.Ouroboros.Signals.AgentMessage): invalid value for :from option: expected string, got: 1"}
      },
      %{
        id: "unknown_data",
        input: %{
          unexpected: true,
          body: %{"hello" => [nil, true, 1]},
          from: "sender",
          correlation_id: "corr"
        },
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:error,
           "Invalid parameters for Signal (Elixir.Ouroboros.Signals.AgentMessage): unknown options [:unexpected], valid options are: [:from, :body, :correlation_id, :causation_id]"}
      },
      %{
        id: "string_data_keys",
        input: %{
          "body" => %{"hello" => [nil, true, 1]},
          "correlation_id" => "corr",
          "from" => "sender"
        },
        opts: [id: "019935ce-c000-7000-8000-000000000001", time: "2026-09-10T12:00:00.000000Z"],
        result:
          {:raised,
           "expected a keyword list, but an entry in the list is not a two-element tuple with an atom as its first element, got: {\"body\", %{\"hello\" => [nil, true, 1]}}"}
      },
      %{
        id: "invalid_source",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [
          id: "019935ce-c000-7000-8000-000000000001",
          time: "2026-09-10T12:00:00.000000Z",
          source: nil
        ],
        result: {:error, "parse error: missing source"}
      },
      %{
        id: "invalid_subject",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [
          id: "019935ce-c000-7000-8000-000000000001",
          time: "2026-09-10T12:00:00.000000Z",
          subject: 7
        ],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: nil
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "2026-09-10T12:00:00.000000Z",
               extensions: %{},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => "2026-09-10T12:00:00.000000Z",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "invalid_time",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [time: "yesterday", id: "019935ce-c000-7000-8000-000000000001"],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: nil
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: "yesterday",
               extensions: %{},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => "yesterday",
               "type" => "ouroboros.agent.message"
             }
           }}
      },
      %{
        id: "invalid_id",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [id: "", time: "2026-09-10T12:00:00.000000Z"],
        result: {:error, "parse error: id given but empty"}
      },
      %{
        id: "nil_time",
        input: %{body: %{"hello" => [nil, true, 1]}, from: "sender", correlation_id: "corr"},
        opts: [time: nil, id: "019935ce-c000-7000-8000-000000000001"],
        result:
          {:ok,
           %{
             fields: %{
               data: %{
                 body: %{"hello" => [nil, true, 1]},
                 from: "sender",
                 correlation_id: "corr",
                 causation_id: nil
               },
               id: "019935ce-c000-7000-8000-000000000001",
               type: "ouroboros.agent.message",
               time: nil,
               extensions: %{},
               source: "/ouroboros/mesh",
               datacontenttype: "application/json",
               dataschema: nil,
               jido_dispatch: nil,
               specversion: "1.0.2",
               subject: nil
             },
             wire: %{
               "data" => %{
                 "body" => %{"hello" => [nil, true, 1]},
                 "causation_id" => nil,
                 "correlation_id" => "corr",
                 "from" => "sender"
               },
               "datacontenttype" => "application/json",
               "dataschema" => nil,
               "extensions" => %{},
               "id" => "019935ce-c000-7000-8000-000000000001",
               "source" => "/ouroboros/mesh",
               "specversion" => "1.0.2",
               "subject" => nil,
               "time" => nil,
               "type" => "ouroboros.agent.message"
             }
           }}
      }
    ],
    actions: [
      %{
        id: "required_default",
        input: %{title: "fixture"},
        result: {:ok, %{count: 2, enabled: false, title: "fixture", items: [], payload: nil}}
      },
      %{
        id: "explicit",
        input: %{count: 4, enabled: true, title: "fixture"},
        result: {:ok, %{count: 4, enabled: true, title: "fixture", items: [], payload: nil}}
      },
      %{
        id: "empty",
        input: %{},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: []"}
      },
      %{
        id: "required_nil",
        input: %{title: nil},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :title option: expected string, got: nil"}
      },
      %{
        id: "optional_nil",
        input: %{count: nil, title: "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: nil"}
      },
      %{
        id: "zero",
        input: %{count: 0, title: "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: 0"}
      },
      %{
        id: "negative",
        input: %{count: -1, title: "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: -1"}
      },
      %{
        id: "fraction",
        input: %{count: 1.5, title: "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: 1.5"}
      },
      %{
        id: "large",
        input: %{count: 9_007_199_254_740_993, title: "fixture"},
        result:
          {:ok,
           %{
             count: 9_007_199_254_740_993,
             enabled: false,
             title: "fixture",
             items: [],
             payload: nil
           }}
      },
      %{
        id: "boolean",
        input: %{enabled: "true", title: "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :enabled option: expected boolean, got: \"true\""}
      },
      %{
        id: "list_wrong",
        input: %{title: "fixture", items: %{}},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :items option: expected list, got: %{}"}
      },
      %{
        id: "nested",
        input: %{title: "fixture", items: [%{"unknown" => [nil, true, 1]}], payload: %{}},
        result:
          {:ok,
           %{
             count: 2,
             enabled: false,
             title: "fixture",
             items: [%{"unknown" => [nil, true, 1]}],
             payload: %{}
           }}
      },
      %{
        id: "unknown_preserved",
        input: %{:extra => true, :title => "fixture", "remote_unknown" => nil},
        result:
          {:ok,
           %{
             :count => 2,
             :enabled => false,
             :extra => true,
             :title => "fixture",
             :items => [],
             :payload => nil,
             "remote_unknown" => nil
           }}
      },
      %{
        id: "string_not_converted",
        input: %{"title" => "fixture"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: []"}
      },
      %{
        id: "atom_precedence",
        input: %{:title => "atom", "title" => "string"},
        result:
          {:ok,
           %{
             :count => 2,
             :enabled => false,
             :title => "atom",
             :items => [],
             :payload => nil,
             "title" => "string"
           }}
      },
      %{
        id: "atom_wrong_type",
        input: %{:title => 4, "title" => "string"},
        result:
          {:error,
           "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :title option: expected string, got: 4"}
      }
    ],
    malformed_execution: [
      %{
        input: nil,
        result: %{
          output:
            "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
          plan: nil,
          is_error: true,
          reads: %{},
          changes: [],
          escalation: nil
        }
      },
      %{
        input: [],
        result: %{
          output:
            "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
          plan: nil,
          is_error: true,
          reads: %{},
          changes: [],
          escalation: nil
        }
      },
      %{
        input: "arguments",
        result: %{
          output:
            "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
          plan: nil,
          is_error: true,
          reads: %{},
          changes: [],
          escalation: nil
        }
      },
      %{
        input: 7,
        result: %{
          output:
            "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
          plan: nil,
          is_error: true,
          reads: %{},
          changes: [],
          escalation: nil
        }
      }
    ]
  }
}
