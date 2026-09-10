# Frozen from the original pre-J1 action schema adapter. Do not regenerate from the replacement.
%{
  command:
    "MIX_ENV=test mix run --no-start /tmp/j1-capture-native-tool-behavior-baseline.exs (original Tools source loaded from git; see capture script)",
  context: %{
    distributed: false,
    audit: :standard,
    user_skills: "isolated empty directory",
    model_metadata: "inline, synthetic"
  },
  source_revision: "d6cc85309141111b6ae1ae3852b254a30092f426",
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
    jido_ai:
      {:hex, :jido_ai, "2.3.0",
       "b25117f5c2422a5d4067ce5c8a48bda2d67a48412309da938c73e04ac4c2136f", [:mix],
       [
         {:fsmx, "~> 0.5", [hex: :fsmx, repo: "hexpm", optional: false]},
         {:igniter, "~> 0.7", [hex: :igniter, repo: "hexpm", optional: true]},
         {:jason, "~> 1.4", [hex: :jason, repo: "hexpm", optional: false]},
         {:jido, "~> 2.3", [hex: :jido, repo: "hexpm", optional: false]},
         {:jido_action, "~> 2.3", [hex: :jido_action, repo: "hexpm", optional: false]},
         {:req_llm, "~> 1.14", [hex: :req_llm, repo: "hexpm", optional: false]},
         {:splode, "~> 0.3.0", [hex: :splode, repo: "hexpm", optional: false]},
         {:yaml_elixir, "~> 2.12", [hex: :yaml_elixir, repo: "hexpm", optional: false]},
         {:zoi, "~> 0.18", [hex: :zoi, repo: "hexpm", optional: false]}
       ], "hexpm", "ea21b9e23bb23fde985c53c8860cca3a3a629591d46e4af38508f40e4a5b959d"},
    req_llm:
      {:hex, :req_llm, "1.21.1",
       "492c4af4ce4a6b72bcacc3cd9f9ef0d48b5750cb8a3e651876ed4b98ea975bf8", [:mix],
       [
         {:dotenvy, "~> 1.1", [hex: :dotenvy, repo: "hexpm", optional: false]},
         {:ex_aws_auth, "~> 1.4", [hex: :ex_aws_auth, repo: "hexpm", optional: true]},
         {:goth, "~> 1.4", [hex: :goth, repo: "hexpm", optional: true]},
         {:igniter, "~> 0.7", [hex: :igniter, repo: "hexpm", optional: true]},
         {:jason, "~> 1.4", [hex: :jason, repo: "hexpm", optional: false]},
         {:jsv, "~> 0.11", [hex: :jsv, repo: "hexpm", optional: false]},
         {:llm_db, "~> 2026.8.4", [hex: :llm_db, repo: "hexpm", optional: false]},
         {:nimble_options, "~> 1.1", [hex: :nimble_options, repo: "hexpm", optional: false]},
         {:req, "~> 0.5", [hex: :req, repo: "hexpm", optional: false]},
         {:server_sent_events, "~> 1.1.0",
          [hex: :server_sent_events, repo: "hexpm", optional: false]},
         {:splode, "~> 0.3.0", [hex: :splode, repo: "hexpm", optional: false]},
         {:websockex, "~> 0.5.1", [hex: :websockex, repo: "hexpm", optional: false]},
         {:zoi, "~> 0.14", [hex: :zoi, repo: "hexpm", optional: false]}
       ], "hexpm", "99056a0d2e93323224911696545e6a8ab71541ff12fbd3949e38b6af51c20eaa"},
    jido_harness:
      {:git, "https://github.com/agentjido/jido_harness.git",
       "8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b",
       [ref: "8bf0d52f4fed0d8a9d2594000d8b3a775da16f8b"]},
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
       ], "hexpm", "e6e222e5c8da489de36d637930628d56fb898b072a17cd467d27bf4f5ecb63e4"}
  },
  source_sha256: "baf7a98b99acab87fd9511e19a27c7cf9e0f793c0ae28f6b57915abd312fd294",
  captured: %{
    action: [
      %{
        id: "defaults",
        input: %{"title" => "Inspect"},
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received, %{count: 2, enabled: false, items: [], title: "Inspect", payload: nil}}
        }
      },
      %{
        id: "explicit_values",
        input: %{"count" => 3, "enabled" => true, "title" => "Inspect"},
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received, %{count: 3, enabled: true, items: [], title: "Inspect", payload: nil}}
        }
      },
      %{
        id: "null_any",
        input: %{"payload" => nil, "title" => "Inspect"},
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received, %{count: 2, enabled: false, items: [], title: "Inspect", payload: nil}}
        }
      },
      %{
        id: "nested_string_keys",
        input: %{
          "items" => [%{"id" => 1, "nested" => [nil, true]}],
          "payload" => %{"name" => "untouched"},
          "title" => "Inspect"
        },
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received,
             %{
               count: 2,
               enabled: false,
               items: [%{"id" => 1, "nested" => [nil, true]}],
               title: "Inspect",
               payload: %{"name" => "untouched"}
             }}
        }
      },
      %{
        id: "unknown_keys_dropped",
        input: %{"title" => "Inspect", "unregistered_field" => "ignored"},
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received, %{count: 2, enabled: false, items: [], title: "Inspect", payload: nil}}
        }
      },
      %{
        id: "atom_string_collision",
        input: %{:count => 9, :title => "atom", "title" => "string"},
        observation: %{
          result: %{
            output: "synthetic effect",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: false,
            reads: %{}
          },
          effective_input:
            {:received, %{count: 2, enabled: false, items: [], title: "string", payload: nil}}
        }
      },
      %{
        id: "atom_only_ignored",
        input: %{title: "atom"},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "required_missing",
        input: %{},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): required :title option not found, received options: [:count, :enabled, :items, :payload]",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "required_null",
        input: %{"title" => nil},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :title option: expected string, got: nil",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "optional_null",
        input: %{"count" => nil, "title" => "Inspect"},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: nil",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "wrong_primitive",
        input: %{"enabled" => "true", "title" => "Inspect"},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :enabled option: expected boolean, got: \"true\"",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "below_bound",
        input: %{"count" => 0, "title" => "Inspect"},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :count option: expected positive integer, got: 0",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      },
      %{
        id: "wrong_array",
        input: %{"items" => %{}, "title" => "Inspect"},
        observation: %{
          result: %{
            output:
              "Invalid parameters for Action (Elixir.Ouroboros.Test.NativeToolBehaviorBaseline.Probe): invalid value for :items option: expected list, got: %{}",
            plan: nil,
            changes: [],
            escalation: nil,
            is_error: true,
            reads: %{}
          },
          effective_input: :no_effect
        }
      }
    ],
    validation: [
      %{
        id: "missing_required",
        input: %{},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: property 'path' is required Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "wrong_primitive",
        input: %{"path" => 7},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value is not of type string Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "required_null",
        input: %{"path" => nil},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value is not of type string Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "optional_null",
        input: %{"offset" => nil, "path" => "README.md"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value is not of type integer Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "omitted_defaults",
        input: %{"path" => "README.md"},
        name: "read",
        result: {:ok, %{"path" => "README.md"}}
      },
      %{
        id: "integer_minimum",
        input: %{"offset" => 0, "path" => "README.md"},
        name: "read",
        result: {:ok, %{"offset" => 0, "path" => "README.md"}}
      },
      %{
        id: "integer_below_minimum",
        input: %{"offset" => -1, "path" => "README.md"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value -1 is lower than minimum 0 Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "integer_fraction",
        input: %{"offset" => 1.5, "path" => "README.md"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value is not of type integer Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "unknown_key",
        input: %{"hallucinated" => true, "path" => "README.md"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: value was rejected from boolean schema: false Required arguments: path. Argument schema: limit: integer (optional), offset: integer (optional), path: string (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "atom_key_only",
        input: %{path: "README.md"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: no function clause matching in JSV.Validator.validate_in/5 Retry with corrected arguments matching the advertised schema; do not repeat the unchanged call."}
      },
      %{
        id: "atom_string_collision",
        input: %{:path => "atom", "path" => "string"},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: no function clause matching in JSV.Validator.validate_in/5 Retry with corrected arguments matching the advertised schema; do not repeat the unchanged call."}
      },
      %{
        id: "atom_string_collision_wrong_type",
        input: %{:path => "atom", "path" => 1},
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: no function clause matching in JSV.Validator.validate_in/5 Retry with corrected arguments matching the advertised schema; do not repeat the unchanged call."}
      },
      %{id: "empty_optional", input: %{}, name: "ls", result: {:ok, %{}}},
      %{
        id: "positive_integer_zero",
        input: %{"depth" => 0},
        name: "ls",
        result:
          {:error,
           "Invalid arguments for `ls`: value 0 is lower than minimum 1 Required arguments: none. Argument schema: depth: integer (optional), path: string (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "positive_integer_one",
        input: %{"depth" => 1},
        name: "ls",
        result: {:ok, %{"depth" => 1}}
      },
      %{
        id: "positive_integer_large",
        input: %{"depth" => 1000},
        name: "ls",
        result: {:ok, %{"depth" => 1000}}
      },
      %{
        id: "wrong_boolean",
        input: %{"new_string" => "y", "old_string" => "x", "path" => "a", "replace_all" => "true"},
        name: "edit",
        result:
          {:error,
           "Invalid arguments for `edit`: value is not of type boolean Required arguments: path, old_string, new_string. Argument schema: new_string: string (required), old_string: string (required), path: string (required), replace_all: boolean (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "not_object_array",
        input: [],
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: expected an object, got an array. Retry with a JSON object matching the advertised schema; do not repeat the unchanged call."}
      },
      %{
        id: "not_object_string",
        input: "README.md",
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: expected an object, got a string. Retry with a JSON object matching the advertised schema; do not repeat the unchanged call."}
      },
      %{
        id: "not_object_null",
        input: nil,
        name: "read",
        result:
          {:error,
           "Invalid arguments for `read`: expected an object, got null. Retry with a JSON object matching the advertised schema; do not repeat the unchanged call."}
      },
      %{
        id: "not_advertised",
        input: %{},
        name: "invented",
        result: {:error, "Invalid arguments for `invented`: no schema is available."}
      },
      %{id: "alias_plan", input: %{"steps" => []}, name: "todo", result: {:ok, %{"steps" => []}}},
      %{
        id: "plan_empty_array",
        input: %{"steps" => []},
        name: "plan",
        result: {:ok, %{"steps" => []}}
      },
      %{
        id: "plan_nested_valid",
        input: %{"steps" => [%{"status" => "pending", "step" => "Review"}]},
        name: "plan",
        result: {:ok, %{"steps" => [%{"status" => "pending", "step" => "Review"}]}}
      },
      %{
        id: "plan_nested_missing",
        input: %{"steps" => [%{"step" => "Review"}]},
        name: "plan",
        result:
          {:error,
           "Invalid arguments for `plan`: property 'status' is required Required arguments: steps. Argument schema: explanation: string (optional), steps: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "plan_nested_wrong_primitive",
        input: %{"steps" => ["Review"]},
        name: "plan",
        result:
          {:error,
           "Invalid arguments for `plan`: value is not of type object Required arguments: steps. Argument schema: explanation: string (optional), steps: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "plan_nested_unknown",
        input: %{"steps" => [%{"extra" => true, "status" => "pending", "step" => "Review"}]},
        name: "plan",
        result:
          {:error,
           "Invalid arguments for `plan`: value was rejected from boolean schema: false Required arguments: steps. Argument schema: explanation: string (optional), steps: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "plan_nested_bad_enum",
        input: %{"steps" => [%{"status" => "later", "step" => "Review"}]},
        name: "plan",
        result:
          {:error,
           "Invalid arguments for `plan`: value must be one of the enum values: \\ Required arguments: steps. Argument schema: explanation: string (optional), steps: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "agent_valid",
        input: %{"prompt" => "Inspect", "tools" => ["read"]},
        name: "agent",
        result: {:ok, %{"prompt" => "Inspect", "tools" => ["read"]}}
      },
      %{
        id: "agent_tools_wrong_item",
        input: %{"prompt" => "Inspect", "tools" => [1]},
        name: "agent",
        result:
          {:error,
           "Invalid arguments for `agent`: value is not of type string Required arguments: prompt. Argument schema: background: boolean (optional), deadline_ms: integer (optional), description: string (optional), machine: string (optional), max_turns: integer (optional), prompt: string (required), sync: boolean (optional), tools: array (optional), workspace: string (optional), worktree: boolean (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "agent_default_omission",
        input: %{"prompt" => "Inspect"},
        name: "agent",
        result: {:ok, %{"prompt" => "Inspect"}}
      },
      %{
        id: "agent_max_turns_zero",
        input: %{"max_turns" => 0, "prompt" => "Inspect"},
        name: "agent",
        result:
          {:error,
           "Invalid arguments for `agent`: value 0 is lower than minimum 1 Required arguments: prompt. Argument schema: background: boolean (optional), deadline_ms: integer (optional), description: string (optional), machine: string (optional), max_turns: integer (optional), prompt: string (required), sync: boolean (optional), tools: array (optional), workspace: string (optional), worktree: boolean (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "capability_open_message",
        input: %{
          "message" => %{"rows" => [%{"anything" => [1, true, nil]}]},
          "name" => "fixture",
          "operation" => "call"
        },
        name: "capability",
        result:
          {:ok,
           %{
             "message" => %{"rows" => [%{"anything" => [1, true, nil]}]},
             "name" => "fixture",
             "operation" => "call"
           }}
      },
      %{
        id: "capability_wrong_message",
        input: %{"message" => "{}", "operation" => "call"},
        name: "capability",
        result:
          {:error,
           "Invalid arguments for `capability`: value is not of type object Required arguments: operation. Argument schema: message: object (optional), name: string (optional), operation: one of \"list\", \"call\" (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "capability_null_message",
        input: %{"message" => nil, "operation" => "call"},
        name: "capability",
        result:
          {:error,
           "Invalid arguments for `capability`: value is not of type object Required arguments: operation. Argument schema: message: object (optional), name: string (optional), operation: one of \"list\", \"call\" (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "capability_bad_enum",
        input: %{"operation" => "delete"},
        name: "capability",
        result:
          {:error,
           "Invalid arguments for `capability`: value must be one of the enum values: \\ Required arguments: operation. Argument schema: message: object (optional), name: string (optional), operation: one of \"list\", \"call\" (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "forge_open_eval",
        input: %{
          "eval" => %{"future" => true, "probes" => [%{"input" => %{"a" => 1}}]},
          "operation" => "forge"
        },
        name: "forge",
        result:
          {:ok,
           %{
             "eval" => %{"future" => true, "probes" => [%{"input" => %{"a" => 1}}]},
             "operation" => "forge"
           }}
      },
      %{
        id: "forge_wrong_eval",
        input: %{"eval" => "{}", "operation" => "forge"},
        name: "forge",
        result:
          {:error,
           "Invalid arguments for `forge`: value is not of type object Required arguments: operation. Argument schema: artifact_id: string (optional), eval: object (optional), name: string (optional), operation: one of \"preview\", \"forge\", \"deploy\", \"status\" (required), path: string (optional), start_config: string (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "forge_bad_enum",
        input: %{"operation" => "build"},
        name: "forge",
        result:
          {:error,
           "Invalid arguments for `forge`: value must be one of the enum values: \\ Required arguments: operation. Argument schema: artifact_id: string (optional), eval: object (optional), name: string (optional), operation: one of \"preview\", \"forge\", \"deploy\", \"status\" (required), path: string (optional), start_config: string (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "forge_unknown_author",
        input: %{"author" => "model", "operation" => "status"},
        name: "forge",
        result:
          {:error,
           "Invalid arguments for `forge`: value was rejected from boolean schema: false Required arguments: operation. Argument schema: artifact_id: string (optional), eval: object (optional), name: string (optional), operation: one of \"preview\", \"forge\", \"deploy\", \"status\" (required), path: string (optional), start_config: string (optional). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "mcp_open",
        input: %{"arbitrary" => [%{"deep" => nil}]},
        name: "mcp__baseline__open",
        result: {:ok, %{"arbitrary" => [%{"deep" => nil}]}}
      },
      %{
        id: "mcp_nested_valid",
        input: %{"rows" => [%{"id" => 1, "note" => nil}, %{"id" => 3}]},
        name: "mcp__baseline__nested",
        result: {:ok, %{"rows" => [%{"id" => 1, "note" => nil}, %{"id" => 3}]}}
      },
      %{
        id: "mcp_nested_below_bound",
        input: %{"rows" => [%{"id" => 0}]},
        name: "mcp__baseline__nested",
        result:
          {:error,
           "Invalid arguments for `mcp__baseline__nested`: value 0 is lower than minimum 1 Required arguments: rows. Argument schema: options: object or null (optional), rows: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "mcp_nested_above_bound",
        input: %{"rows" => [%{"id" => 4}]},
        name: "mcp__baseline__nested",
        result:
          {:error,
           "Invalid arguments for `mcp__baseline__nested`: value 4 is higher than maximum 3 Required arguments: rows. Argument schema: options: object or null (optional), rows: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "mcp_nested_unknown",
        input: %{"rows" => [%{"id" => 1, "unknown" => true}]},
        name: "mcp__baseline__nested",
        result:
          {:error,
           "Invalid arguments for `mcp__baseline__nested`: value was rejected from boolean schema: false Required arguments: rows. Argument schema: options: object or null (optional), rows: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "mcp_nested_null_required",
        input: %{"rows" => [%{"id" => nil}]},
        name: "mcp__baseline__nested",
        result:
          {:error,
           "Invalid arguments for `mcp__baseline__nested`: value is not of type integer Required arguments: rows. Argument schema: options: object or null (optional), rows: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      },
      %{
        id: "mcp_nested_wrong_boolean",
        input: %{"options" => %{"enabled" => "yes"}, "rows" => []},
        name: "mcp__baseline__nested",
        result:
          {:error,
           "Invalid arguments for `mcp__baseline__nested`: value did not conform to any of the given schemas Required arguments: rows. Argument schema: options: object or null (optional), rows: array (required). Retry with corrected arguments; do not repeat the unchanged call."}
      }
    ],
    transport: [
      %{
        id: "responses",
        tools: [
          %{
            name: "read",
            strict: true,
            description:
              "Read a file from the workspace. Returns line-numbered text starting at `offset`. Read a file before editing it.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "limit" => %{
                  "anyOf" => [
                    %{
                      "description" => "How many lines to return.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "offset" => %{
                  "anyOf" => [
                    %{
                      "description" => "First line to return, 0-based.",
                      "minimum" => 0,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["limit", "offset", "path"],
              "type" => "object"
            }
          },
          %{
            name: "write",
            strict: true,
            description:
              "Write a file in the workspace, replacing it if it exists. Prefer `edit` for a change to an existing file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "content" => %{
                  "description" => "The complete new file content.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["content", "path"],
              "type" => "object"
            }
          },
          %{
            name: "edit",
            strict: true,
            description:
              "Replace an exact string in a workspace file. Read the file first. `old_string` must appear exactly once unless `replace_all` is true.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "new_string" => %{"description" => "The replacement text.", "type" => "string"},
                "old_string" => %{
                  "description" => "The exact text to replace.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                },
                "replace_all" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Replace every occurrence instead of requiring exactly one.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["new_string", "old_string", "path", "replace_all"],
              "type" => "object"
            }
          },
          %{
            name: "apply_patch",
            strict: true,
            description:
              "Apply a V4A patch (`*** Begin Patch` … `*** End Patch`) that adds, updates, moves or deletes several files at once. Read every file you update first. Prefer `edit` for a single change to a single file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "patch" => %{
                  "description" =>
                    "The complete patch, starting with `*** Begin Patch` and ending with `*** End Patch`. Sections are `*** Add File: <path>`, `*** Delete File: <path>`, and `*** Update File: <path>` with optional `*** Move to: <path>`; hunks start with `@@` and their lines are prefixed with a space, `-`, or `+`. No line numbers.",
                  "type" => "string"
                }
              },
              "required" => ["patch"],
              "type" => "object"
            }
          },
          %{
            name: "bash",
            strict: true,
            description:
              "Run a shell command in the workspace root. Under read_only and workspace_write it runs inside this node's OS sandbox; without a backend those modes refuse rather than running unsandboxed. A sandbox denial reports the constraint that was hit. Output is truncated to 30 KiB; the full output is saved to a file whose path is returned.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "command" => %{
                  "description" => "The command line to run with `sh -c`.",
                  "type" => "string"
                },
                "description" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A short description of what the command does, shown in the transcript.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "timeout_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Kill the command after this many milliseconds. Bounded by this node’s bash_max_timeout_ms (default 600000, absolute 4 h).",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["command", "description", "timeout_ms"],
              "type" => "object"
            }
          },
          %{
            name: "grep",
            strict: true,
            description:
              "Search file contents for a regular expression, in the workspace. Returns matching lines with their paths and line numbers, newest-modified files first. Bounded to 200 matches.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "case_insensitive" => %{
                  "anyOf" => [
                    %{"description" => "Ignore case, like ripgrep's `-i`.", "type" => "boolean"},
                    %{"type" => "null"}
                  ]
                },
                "glob" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Only search files whose name matches this glob, for example `*.ex`.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "line_numbers" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Prefix each match with its line number, like ripgrep's `-n`.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "File or directory to search. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "pattern" => %{
                  "description" => "The regular expression to search for.",
                  "type" => "string"
                }
              },
              "required" => ["case_insensitive", "glob", "line_numbers", "path", "pattern"],
              "type" => "object"
            }
          },
          %{
            name: "glob",
            strict: true,
            description:
              "List workspace files matching a glob pattern such as `**/*.ex` or `lib/**/*_test.exs`, most-recently-modified first. Bounded to 2000 results.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Directory to search from. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "pattern" => %{
                  "description" => "A glob pattern, relative to `path` or to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["path", "pattern"],
              "type" => "object"
            }
          },
          %{
            name: "ls",
            strict: true,
            description:
              "List the entries of a workspace directory. `depth` defaults to 1 and is capped at 3. Bounded to 1000 entries.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "depth" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How many levels to descend. 1 lists the directory itself. Maximum 3.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" => "Directory to list. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["depth", "path"],
              "type" => "object"
            }
          },
          %{
            name: "web_fetch",
            strict: true,
            description:
              "Fetch an http(s) URL with GET and return its text. HTML is converted to text. Bounded to 1 MiB and 15 seconds; redirects to another host are reported, not followed. Loopback, private, link-local, and metadata destinations are refused.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "max_bytes" => %{
                  "anyOf" => [
                    %{
                      "description" => "Stop reading after this many bytes. Maximum 1048576.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "url" => %{
                  "description" => "The absolute http:// or https:// URL to fetch.",
                  "type" => "string"
                }
              },
              "required" => ["max_bytes", "url"],
              "type" => "object"
            }
          },
          %{
            name: "ask_user",
            strict: true,
            description:
              "Ask the operator one question and wait for their answer. Use it when a choice changes what you build and you cannot infer it from the workspace. Do not use it for anything you can find out by reading a file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "header" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A two- or three-word label for the question, shown above it.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "options" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Optional suggested answers. The operator may answer with something else.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "question" => %{
                  "description" => "The question, in one or two sentences.",
                  "type" => "string"
                }
              },
              "required" => ["header", "options", "question"],
              "type" => "object"
            }
          },
          %{
            name: "agent",
            strict: true,
            description:
              "Spawn a child agent with its own context window and get a summary back. Use it for work whose *findings* you need but whose *reading* you do not — searching a large codebase, checking a hypothesis in unfamiliar files, running several independent explorations at once. The child sees no part of this conversation except the prompt you write, so put everything it needs in that prompt. It can never use a tool you do not have, and never run more permissively than you do.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "background" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Return a task_id immediately instead of waiting. Collect it with agent_result. Interactive background children can ask for permission between turns. Foreground children are bounded by the loop tool timeout; use background for long work.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "deadline_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Wall-clock limit in milliseconds, bounded by this node’s subagent_max_deadline_ms.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "description" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A three- to five-word label for this child, shown in the transcript.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "machine" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Run the child on another machine of this fleet. Call fleet for the live list. Name a connected machine or use tag:NAME when exactly one matches; omit to run here.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "max_turns" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How many model round-trips the child may take. Maximum 30.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "prompt" => %{
                  "description" =>
                    "The child's entire instruction. It shares none of your context, so state the goal, the constraints, and exactly what to report back.",
                  "type" => "string"
                },
                "sync" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Send a snapshot of this repository, including uncommitted work, to the machine. Requires machine and creates an isolated worktree there. Cannot be combined with workspace. Ignored files do not travel; the child installs dependencies.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "tools" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Tool names the child may use. Empty means every tool you have. The child always gets the intersection with your own tools, never more.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "workspace" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Absolute path of the child's workspace on that machine. Required with `machine:` unless sync is true; refused without it.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "worktree" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Run the child in its own git worktree of this workspace, so its edits cannot touch your tree. Refused with a reason when this node cannot provision one.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => [
                "background",
                "deadline_ms",
                "description",
                "machine",
                "max_turns",
                "prompt",
                "sync",
                "tools",
                "workspace",
                "worktree"
              ],
              "type" => "object"
            }
          },
          %{
            name: "agent_result",
            strict: true,
            description:
              "Wait for a background subagent and return its summary. Give it the task_id `agent` returned. A child that is still running says so and stays collectable.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "stop" => %{
                  "anyOf" => [
                    %{
                      "description" => "Stop this session's child and collect its summary.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "task_id" => %{
                  "description" =>
                    "The task_id `agent` returned when it spawned the child in the background.",
                  "type" => "string"
                },
                "wait_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How long to wait for it to finish. Maximum 60000. 0 returns what it has now.",
                      "minimum" => 0,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["stop", "task_id", "wait_ms"],
              "type" => "object"
            }
          },
          %{
            name: "fleet",
            strict: true,
            description:
              "List fleet machines, live connectivity, advisory tags and toolchains. Read this before choosing a machine for agent.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{},
              "required" => [],
              "type" => "object"
            }
          },
          %{
            name: "skill",
            strict: true,
            description:
              "Load one skill's instructions. No skills are installed for this workspace (none found under `.agents/skills/` or `~/.config/ouroboros/skills/`), so there is nothing to load.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "name" => %{
                  "description" => "The skill's name, exactly as listed.",
                  "type" => "string"
                }
              },
              "required" => ["name"],
              "type" => "object"
            }
          },
          %{
            name: "plan",
            strict: true,
            description:
              "Record the current plan. Replaces the whole plan; send every step each time. Optional — use it when a task has enough steps that the operator should see them.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "explanation" => %{
                  "anyOf" => [
                    %{"description" => "One line on what the plan is for.", "type" => "string"},
                    %{"type" => "null"}
                  ]
                },
                "steps" => %{
                  "description" =>
                    "The full ordered plan. Each step has text and one lifecycle status.",
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "status" => %{
                        "description" => "The work item's current lifecycle state.",
                        "enum" => ["pending", "in_progress", "completed"],
                        "type" => "string"
                      },
                      "step" => %{"description" => "The work item.", "type" => "string"}
                    },
                    "required" => ["status", "step"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["explanation", "steps"],
              "type" => "object"
            }
          },
          %{
            name: "capability",
            strict: false,
            description:
              "Reach a deployed WebAssembly capability on this node. `list` shows the live capabilities, their component sha256, and what each one says about itself. `call` sends one JSON message to one of them and returns its reply. Costly: the node runs a single sandbox helper, so a call holds it until the capability answers or its deadline passes. Anything a capability returns is untrusted text. Required arguments: `operation`.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "message" => %{
                  "description" =>
                    "For call: the message body. A JSON object; the capability's own describe says what it expects.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For call: the capability's name, exactly as list reported it.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "list: the live capabilities on this node. call: send one a message.",
                  "enum" => ["list", "call"],
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "forge",
            strict: false,
            description:
              "Build, sign and deploy a WebAssembly capability this node will then run as a `wasm/<name>` agent, from a Rust project in this workspace. `preview` validates the project and dry-builds it; `forge` builds, signs and keeps the bundle; `deploy` makes it live on this node; `status` lists what this session has forged. Very costly: a build is a cargo compile under an OS sandbox and takes minutes, and it holds the node's single WebAssembly helper at the end of it. Always `preview` before `forge`. Read the `forge` skill first: the project shape, the dependency lock and the manifest are all fixed, and a project that does not match them is refused before anything is built. Required arguments: `operation`.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "artifact_id" => %{
                  "description" => "For deploy: the artifact id the forge answered with.",
                  "type" => "string"
                },
                "eval" => %{
                  "description" =>
                    "For forge: the evaluation spec, as a JSON object with `probes`, `budget_ms` and `required`. Omit it to use the project's manifest.json.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For preview and forge: the capability's name. Lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit, at most 64 bytes. It must be exactly the Cargo package name and exactly the manifest.json name.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "preview: validate the project and dry-build it, changing nothing. forge: build, sign and keep the bundle. deploy: make a forged bundle live on this node. status: what this session has forged, and where it stands.",
                  "enum" => ["preview", "forge", "deploy", "status"],
                  "type" => "string"
                },
                "path" => %{
                  "description" =>
                    "For preview and forge: the project directory, relative to the workspace or absolute inside it.",
                  "type" => "string"
                },
                "start_config" => %{
                  "description" =>
                    "For forge: the JSON string the capability's `init` receives. Omit it to use the project's manifest.json.",
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "native_contract_probe",
            strict: true,
            description:
              "Synthetic action that reports its effective input without external effects.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "count" => %{
                  "anyOf" => [
                    %{
                      "description" => "No description provided.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "enabled" => %{
                  "anyOf" => [
                    %{"description" => "No description provided.", "type" => "boolean"},
                    %{"type" => "null"}
                  ]
                },
                "items" => %{
                  "anyOf" => [
                    %{
                      "description" => "No description provided.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "payload" => %{
                  "anyOf" => [
                    %{"description" => "No description provided.", "type" => "string"},
                    %{"type" => "null"}
                  ]
                },
                "title" => %{"description" => "No description provided.", "type" => "string"}
              },
              "required" => ["count", "enabled", "items", "payload", "title"],
              "type" => "object"
            }
          },
          %{
            name: "mcp__baseline__open",
            strict: false,
            description: "The remote server accepts arbitrary arguments.",
            parameter_schema: %{"additionalProperties" => true, "type" => "object"}
          },
          %{
            name: "mcp__baseline__nested",
            strict: true,
            description: "A controlled remote nested and nullable contract.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "options" => %{
                  "anyOf" => [
                    %{
                      "additionalProperties" => false,
                      "properties" => %{
                        "enabled" => %{"anyOf" => [%{"type" => "boolean"}, %{"type" => "null"}]}
                      },
                      "required" => ["enabled"],
                      "type" => "object"
                    },
                    %{"type" => "null"}
                  ]
                },
                "rows" => %{
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "id" => %{"maximum" => 3, "minimum" => 1, "type" => "integer"},
                      "label" => %{"anyOf" => [%{"type" => "string"}, %{"type" => "null"}]},
                      "note" => %{"type" => ["string", "null"]}
                    },
                    "required" => ["id", "label", "note"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["options", "rows"],
              "type" => "object"
            }
          }
        ],
        model: %{
          extra: %{wire: %{protocol: "openai_responses"}, use_responses_lite: false},
          id: "native-parity-fixture",
          name: "Native parity fixture",
          provider: :openai
        }
      },
      %{
        id: "responses_lite",
        tools: [
          %{
            name: "read",
            strict: true,
            description:
              "Read a file from the workspace. Returns line-numbered text starting at `offset`. Read a file before editing it.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "limit" => %{
                  "anyOf" => [
                    %{
                      "description" => "How many lines to return.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "offset" => %{
                  "anyOf" => [
                    %{
                      "description" => "First line to return, 0-based.",
                      "minimum" => 0,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["limit", "offset", "path"],
              "type" => "object"
            }
          },
          %{
            name: "write",
            strict: true,
            description:
              "Write a file in the workspace, replacing it if it exists. Prefer `edit` for a change to an existing file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "content" => %{
                  "description" => "The complete new file content.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["content", "path"],
              "type" => "object"
            }
          },
          %{
            name: "edit",
            strict: true,
            description:
              "Replace an exact string in a workspace file. Read the file first. `old_string` must appear exactly once unless `replace_all` is true.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "new_string" => %{"description" => "The replacement text.", "type" => "string"},
                "old_string" => %{
                  "description" => "The exact text to replace.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                },
                "replace_all" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Replace every occurrence instead of requiring exactly one.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["new_string", "old_string", "path", "replace_all"],
              "type" => "object"
            }
          },
          %{
            name: "apply_patch",
            strict: true,
            description:
              "Apply a V4A patch (`*** Begin Patch` … `*** End Patch`) that adds, updates, moves or deletes several files at once. Read every file you update first. Prefer `edit` for a single change to a single file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "patch" => %{
                  "description" =>
                    "The complete patch, starting with `*** Begin Patch` and ending with `*** End Patch`. Sections are `*** Add File: <path>`, `*** Delete File: <path>`, and `*** Update File: <path>` with optional `*** Move to: <path>`; hunks start with `@@` and their lines are prefixed with a space, `-`, or `+`. No line numbers.",
                  "type" => "string"
                }
              },
              "required" => ["patch"],
              "type" => "object"
            }
          },
          %{
            name: "bash",
            strict: true,
            description:
              "Run a shell command in the workspace root. Under read_only and workspace_write it runs inside this node's OS sandbox; without a backend those modes refuse rather than running unsandboxed. A sandbox denial reports the constraint that was hit. Output is truncated to 30 KiB; the full output is saved to a file whose path is returned.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "command" => %{
                  "description" => "The command line to run with `sh -c`.",
                  "type" => "string"
                },
                "description" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A short description of what the command does, shown in the transcript.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "timeout_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Kill the command after this many milliseconds. Bounded by this node’s bash_max_timeout_ms (default 600000, absolute 4 h).",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["command", "description", "timeout_ms"],
              "type" => "object"
            }
          },
          %{
            name: "grep",
            strict: true,
            description:
              "Search file contents for a regular expression, in the workspace. Returns matching lines with their paths and line numbers, newest-modified files first. Bounded to 200 matches.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "case_insensitive" => %{
                  "anyOf" => [
                    %{"description" => "Ignore case, like ripgrep's `-i`.", "type" => "boolean"},
                    %{"type" => "null"}
                  ]
                },
                "glob" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Only search files whose name matches this glob, for example `*.ex`.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "line_numbers" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Prefix each match with its line number, like ripgrep's `-n`.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "File or directory to search. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "pattern" => %{
                  "description" => "The regular expression to search for.",
                  "type" => "string"
                }
              },
              "required" => ["case_insensitive", "glob", "line_numbers", "path", "pattern"],
              "type" => "object"
            }
          },
          %{
            name: "glob",
            strict: true,
            description:
              "List workspace files matching a glob pattern such as `**/*.ex` or `lib/**/*_test.exs`, most-recently-modified first. Bounded to 2000 results.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Directory to search from. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "pattern" => %{
                  "description" => "A glob pattern, relative to `path` or to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["path", "pattern"],
              "type" => "object"
            }
          },
          %{
            name: "ls",
            strict: true,
            description:
              "List the entries of a workspace directory. `depth` defaults to 1 and is capped at 3. Bounded to 1000 entries.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "depth" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How many levels to descend. 1 lists the directory itself. Maximum 3.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "path" => %{
                  "anyOf" => [
                    %{
                      "description" => "Directory to list. Defaults to the workspace root.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["depth", "path"],
              "type" => "object"
            }
          },
          %{
            name: "web_fetch",
            strict: true,
            description:
              "Fetch an http(s) URL with GET and return its text. HTML is converted to text. Bounded to 1 MiB and 15 seconds; redirects to another host are reported, not followed. Loopback, private, link-local, and metadata destinations are refused.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "max_bytes" => %{
                  "anyOf" => [
                    %{
                      "description" => "Stop reading after this many bytes. Maximum 1048576.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "url" => %{
                  "description" => "The absolute http:// or https:// URL to fetch.",
                  "type" => "string"
                }
              },
              "required" => ["max_bytes", "url"],
              "type" => "object"
            }
          },
          %{
            name: "ask_user",
            strict: true,
            description:
              "Ask the operator one question and wait for their answer. Use it when a choice changes what you build and you cannot infer it from the workspace. Do not use it for anything you can find out by reading a file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "header" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A two- or three-word label for the question, shown above it.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "options" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Optional suggested answers. The operator may answer with something else.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "question" => %{
                  "description" => "The question, in one or two sentences.",
                  "type" => "string"
                }
              },
              "required" => ["header", "options", "question"],
              "type" => "object"
            }
          },
          %{
            name: "agent",
            strict: true,
            description:
              "Spawn a child agent with its own context window and get a summary back. Use it for work whose *findings* you need but whose *reading* you do not — searching a large codebase, checking a hypothesis in unfamiliar files, running several independent explorations at once. The child sees no part of this conversation except the prompt you write, so put everything it needs in that prompt. It can never use a tool you do not have, and never run more permissively than you do.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "background" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Return a task_id immediately instead of waiting. Collect it with agent_result. Interactive background children can ask for permission between turns. Foreground children are bounded by the loop tool timeout; use background for long work.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "deadline_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Wall-clock limit in milliseconds, bounded by this node’s subagent_max_deadline_ms.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "description" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "A three- to five-word label for this child, shown in the transcript.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "machine" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Run the child on another machine of this fleet. Call fleet for the live list. Name a connected machine or use tag:NAME when exactly one matches; omit to run here.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "max_turns" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How many model round-trips the child may take. Maximum 30.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "prompt" => %{
                  "description" =>
                    "The child's entire instruction. It shares none of your context, so state the goal, the constraints, and exactly what to report back.",
                  "type" => "string"
                },
                "sync" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Send a snapshot of this repository, including uncommitted work, to the machine. Requires machine and creates an isolated worktree there. Cannot be combined with workspace. Ignored files do not travel; the child installs dependencies.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "tools" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Tool names the child may use. Empty means every tool you have. The child always gets the intersection with your own tools, never more.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "workspace" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Absolute path of the child's workspace on that machine. Required with `machine:` unless sync is true; refused without it.",
                      "type" => "string"
                    },
                    %{"type" => "null"}
                  ]
                },
                "worktree" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "Run the child in its own git worktree of this workspace, so its edits cannot touch your tree. Refused with a reason when this node cannot provision one.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => [
                "background",
                "deadline_ms",
                "description",
                "machine",
                "max_turns",
                "prompt",
                "sync",
                "tools",
                "workspace",
                "worktree"
              ],
              "type" => "object"
            }
          },
          %{
            name: "agent_result",
            strict: true,
            description:
              "Wait for a background subagent and return its summary. Give it the task_id `agent` returned. A child that is still running says so and stays collectable.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "stop" => %{
                  "anyOf" => [
                    %{
                      "description" => "Stop this session's child and collect its summary.",
                      "type" => "boolean"
                    },
                    %{"type" => "null"}
                  ]
                },
                "task_id" => %{
                  "description" =>
                    "The task_id `agent` returned when it spawned the child in the background.",
                  "type" => "string"
                },
                "wait_ms" => %{
                  "anyOf" => [
                    %{
                      "description" =>
                        "How long to wait for it to finish. Maximum 60000. 0 returns what it has now.",
                      "minimum" => 0,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                }
              },
              "required" => ["stop", "task_id", "wait_ms"],
              "type" => "object"
            }
          },
          %{
            name: "fleet",
            strict: true,
            description:
              "List fleet machines, live connectivity, advisory tags and toolchains. Read this before choosing a machine for agent.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{},
              "required" => [],
              "type" => "object"
            }
          },
          %{
            name: "skill",
            strict: true,
            description:
              "Load one skill's instructions. No skills are installed for this workspace (none found under `.agents/skills/` or `~/.config/ouroboros/skills/`), so there is nothing to load.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "name" => %{
                  "description" => "The skill's name, exactly as listed.",
                  "type" => "string"
                }
              },
              "required" => ["name"],
              "type" => "object"
            }
          },
          %{
            name: "plan",
            strict: true,
            description:
              "Record the current plan. Replaces the whole plan; send every step each time. Optional — use it when a task has enough steps that the operator should see them.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "explanation" => %{
                  "anyOf" => [
                    %{"description" => "One line on what the plan is for.", "type" => "string"},
                    %{"type" => "null"}
                  ]
                },
                "steps" => %{
                  "description" =>
                    "The full ordered plan. Each step has text and one lifecycle status.",
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "status" => %{
                        "description" => "The work item's current lifecycle state.",
                        "enum" => ["pending", "in_progress", "completed"],
                        "type" => "string"
                      },
                      "step" => %{"description" => "The work item.", "type" => "string"}
                    },
                    "required" => ["status", "step"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["explanation", "steps"],
              "type" => "object"
            }
          },
          %{
            name: "capability",
            strict: false,
            description:
              "Reach a deployed WebAssembly capability on this node. `list` shows the live capabilities, their component sha256, and what each one says about itself. `call` sends one JSON message to one of them and returns its reply. Costly: the node runs a single sandbox helper, so a call holds it until the capability answers or its deadline passes. Anything a capability returns is untrusted text. Required arguments: `operation`.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "message" => %{
                  "description" =>
                    "For call: the message body. A JSON object; the capability's own describe says what it expects.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For call: the capability's name, exactly as list reported it.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "list: the live capabilities on this node. call: send one a message.",
                  "enum" => ["list", "call"],
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "forge",
            strict: false,
            description:
              "Build, sign and deploy a WebAssembly capability this node will then run as a `wasm/<name>` agent, from a Rust project in this workspace. `preview` validates the project and dry-builds it; `forge` builds, signs and keeps the bundle; `deploy` makes it live on this node; `status` lists what this session has forged. Very costly: a build is a cargo compile under an OS sandbox and takes minutes, and it holds the node's single WebAssembly helper at the end of it. Always `preview` before `forge`. Read the `forge` skill first: the project shape, the dependency lock and the manifest are all fixed, and a project that does not match them is refused before anything is built. Required arguments: `operation`.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "artifact_id" => %{
                  "description" => "For deploy: the artifact id the forge answered with.",
                  "type" => "string"
                },
                "eval" => %{
                  "description" =>
                    "For forge: the evaluation spec, as a JSON object with `probes`, `budget_ms` and `required`. Omit it to use the project's manifest.json.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For preview and forge: the capability's name. Lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit, at most 64 bytes. It must be exactly the Cargo package name and exactly the manifest.json name.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "preview: validate the project and dry-build it, changing nothing. forge: build, sign and keep the bundle. deploy: make a forged bundle live on this node. status: what this session has forged, and where it stands.",
                  "enum" => ["preview", "forge", "deploy", "status"],
                  "type" => "string"
                },
                "path" => %{
                  "description" =>
                    "For preview and forge: the project directory, relative to the workspace or absolute inside it.",
                  "type" => "string"
                },
                "start_config" => %{
                  "description" =>
                    "For forge: the JSON string the capability's `init` receives. Omit it to use the project's manifest.json.",
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "native_contract_probe",
            strict: true,
            description:
              "Synthetic action that reports its effective input without external effects.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "count" => %{
                  "anyOf" => [
                    %{
                      "description" => "No description provided.",
                      "minimum" => 1,
                      "type" => "integer"
                    },
                    %{"type" => "null"}
                  ]
                },
                "enabled" => %{
                  "anyOf" => [
                    %{"description" => "No description provided.", "type" => "boolean"},
                    %{"type" => "null"}
                  ]
                },
                "items" => %{
                  "anyOf" => [
                    %{
                      "description" => "No description provided.",
                      "items" => %{"type" => "string"},
                      "type" => "array"
                    },
                    %{"type" => "null"}
                  ]
                },
                "payload" => %{
                  "anyOf" => [
                    %{"description" => "No description provided.", "type" => "string"},
                    %{"type" => "null"}
                  ]
                },
                "title" => %{"description" => "No description provided.", "type" => "string"}
              },
              "required" => ["count", "enabled", "items", "payload", "title"],
              "type" => "object"
            }
          },
          %{
            name: "mcp__baseline__open",
            strict: false,
            description: "The remote server accepts arbitrary arguments.",
            parameter_schema: %{"additionalProperties" => true, "type" => "object"}
          },
          %{
            name: "mcp__baseline__nested",
            strict: true,
            description: "A controlled remote nested and nullable contract.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "options" => %{
                  "anyOf" => [
                    %{
                      "additionalProperties" => false,
                      "properties" => %{
                        "enabled" => %{"anyOf" => [%{"type" => "boolean"}, %{"type" => "null"}]}
                      },
                      "required" => ["enabled"],
                      "type" => "object"
                    },
                    %{"type" => "null"}
                  ]
                },
                "rows" => %{
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "id" => %{"maximum" => 3, "minimum" => 1, "type" => "integer"},
                      "label" => %{"anyOf" => [%{"type" => "string"}, %{"type" => "null"}]},
                      "note" => %{"type" => ["string", "null"]}
                    },
                    "required" => ["id", "label", "note"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["options", "rows"],
              "type" => "object"
            }
          }
        ],
        model: %{
          extra: %{wire: %{protocol: "openai_codex_responses"}, use_responses_lite: true},
          id: "native-parity-fixture",
          name: "Native parity fixture",
          provider: :openai_codex
        }
      },
      %{
        id: "other_transport",
        tools: [
          %{
            name: "read",
            strict: false,
            description:
              "Read a file from the workspace. Returns line-numbered text starting at `offset`. Read a file before editing it.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "limit" => %{
                  "description" => "How many lines to return.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "offset" => %{
                  "description" => "First line to return, 0-based.",
                  "minimum" => 0,
                  "type" => "integer"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["path"],
              "type" => "object"
            }
          },
          %{
            name: "write",
            strict: false,
            description:
              "Write a file in the workspace, replacing it if it exists. Prefer `edit` for a change to an existing file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "content" => %{
                  "description" => "The complete new file content.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["path", "content"],
              "type" => "object"
            }
          },
          %{
            name: "edit",
            strict: false,
            description:
              "Replace an exact string in a workspace file. Read the file first. `old_string` must appear exactly once unless `replace_all` is true.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "new_string" => %{"description" => "The replacement text.", "type" => "string"},
                "old_string" => %{
                  "description" => "The exact text to replace.",
                  "type" => "string"
                },
                "path" => %{
                  "description" => "Absolute path, or a path relative to the workspace root.",
                  "type" => "string"
                },
                "replace_all" => %{
                  "description" => "Replace every occurrence instead of requiring exactly one.",
                  "type" => "boolean"
                }
              },
              "required" => ["path", "old_string", "new_string"],
              "type" => "object"
            }
          },
          %{
            name: "apply_patch",
            strict: false,
            description:
              "Apply a V4A patch (`*** Begin Patch` … `*** End Patch`) that adds, updates, moves or deletes several files at once. Read every file you update first. Prefer `edit` for a single change to a single file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "patch" => %{
                  "description" =>
                    "The complete patch, starting with `*** Begin Patch` and ending with `*** End Patch`. Sections are `*** Add File: <path>`, `*** Delete File: <path>`, and `*** Update File: <path>` with optional `*** Move to: <path>`; hunks start with `@@` and their lines are prefixed with a space, `-`, or `+`. No line numbers.",
                  "type" => "string"
                }
              },
              "required" => ["patch"],
              "type" => "object"
            }
          },
          %{
            name: "bash",
            strict: false,
            description:
              "Run a shell command in the workspace root. Under read_only and workspace_write it runs inside this node's OS sandbox; without a backend those modes refuse rather than running unsandboxed. A sandbox denial reports the constraint that was hit. Output is truncated to 30 KiB; the full output is saved to a file whose path is returned.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "command" => %{
                  "description" => "The command line to run with `sh -c`.",
                  "type" => "string"
                },
                "description" => %{
                  "description" =>
                    "A short description of what the command does, shown in the transcript.",
                  "type" => "string"
                },
                "timeout_ms" => %{
                  "description" =>
                    "Kill the command after this many milliseconds. Bounded by this node’s bash_max_timeout_ms (default 600000, absolute 4 h).",
                  "minimum" => 1,
                  "type" => "integer"
                }
              },
              "required" => ["command"],
              "type" => "object"
            }
          },
          %{
            name: "grep",
            strict: false,
            description:
              "Search file contents for a regular expression, in the workspace. Returns matching lines with their paths and line numbers, newest-modified files first. Bounded to 200 matches.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "case_insensitive" => %{
                  "description" => "Ignore case, like ripgrep's `-i`.",
                  "type" => "boolean"
                },
                "glob" => %{
                  "description" =>
                    "Only search files whose name matches this glob, for example `*.ex`.",
                  "type" => "string"
                },
                "line_numbers" => %{
                  "description" => "Prefix each match with its line number, like ripgrep's `-n`.",
                  "type" => "boolean"
                },
                "path" => %{
                  "description" => "File or directory to search. Defaults to the workspace root.",
                  "type" => "string"
                },
                "pattern" => %{
                  "description" => "The regular expression to search for.",
                  "type" => "string"
                }
              },
              "required" => ["pattern"],
              "type" => "object"
            }
          },
          %{
            name: "glob",
            strict: false,
            description:
              "List workspace files matching a glob pattern such as `**/*.ex` or `lib/**/*_test.exs`, most-recently-modified first. Bounded to 2000 results.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "path" => %{
                  "description" => "Directory to search from. Defaults to the workspace root.",
                  "type" => "string"
                },
                "pattern" => %{
                  "description" => "A glob pattern, relative to `path` or to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => ["pattern"],
              "type" => "object"
            }
          },
          %{
            name: "ls",
            strict: false,
            description:
              "List the entries of a workspace directory. `depth` defaults to 1 and is capped at 3. Bounded to 1000 entries.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "depth" => %{
                  "description" =>
                    "How many levels to descend. 1 lists the directory itself. Maximum 3.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "path" => %{
                  "description" => "Directory to list. Defaults to the workspace root.",
                  "type" => "string"
                }
              },
              "required" => [],
              "type" => "object"
            }
          },
          %{
            name: "web_fetch",
            strict: false,
            description:
              "Fetch an http(s) URL with GET and return its text. HTML is converted to text. Bounded to 1 MiB and 15 seconds; redirects to another host are reported, not followed. Loopback, private, link-local, and metadata destinations are refused.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "max_bytes" => %{
                  "description" => "Stop reading after this many bytes. Maximum 1048576.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "url" => %{
                  "description" => "The absolute http:// or https:// URL to fetch.",
                  "type" => "string"
                }
              },
              "required" => ["url"],
              "type" => "object"
            }
          },
          %{
            name: "ask_user",
            strict: false,
            description:
              "Ask the operator one question and wait for their answer. Use it when a choice changes what you build and you cannot infer it from the workspace. Do not use it for anything you can find out by reading a file.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "header" => %{
                  "description" => "A two- or three-word label for the question, shown above it.",
                  "type" => "string"
                },
                "options" => %{
                  "description" =>
                    "Optional suggested answers. The operator may answer with something else.",
                  "items" => %{"type" => "string"},
                  "type" => "array"
                },
                "question" => %{
                  "description" => "The question, in one or two sentences.",
                  "type" => "string"
                }
              },
              "required" => ["question"],
              "type" => "object"
            }
          },
          %{
            name: "agent",
            strict: false,
            description:
              "Spawn a child agent with its own context window and get a summary back. Use it for work whose *findings* you need but whose *reading* you do not — searching a large codebase, checking a hypothesis in unfamiliar files, running several independent explorations at once. The child sees no part of this conversation except the prompt you write, so put everything it needs in that prompt. It can never use a tool you do not have, and never run more permissively than you do.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "background" => %{
                  "description" =>
                    "Return a task_id immediately instead of waiting. Collect it with agent_result. Interactive background children can ask for permission between turns. Foreground children are bounded by the loop tool timeout; use background for long work.",
                  "type" => "boolean"
                },
                "deadline_ms" => %{
                  "description" =>
                    "Wall-clock limit in milliseconds, bounded by this node’s subagent_max_deadline_ms.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "description" => %{
                  "description" =>
                    "A three- to five-word label for this child, shown in the transcript.",
                  "type" => "string"
                },
                "machine" => %{
                  "description" =>
                    "Run the child on another machine of this fleet. Call fleet for the live list. Name a connected machine or use tag:NAME when exactly one matches; omit to run here.",
                  "type" => "string"
                },
                "max_turns" => %{
                  "description" => "How many model round-trips the child may take. Maximum 30.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "prompt" => %{
                  "description" =>
                    "The child's entire instruction. It shares none of your context, so state the goal, the constraints, and exactly what to report back.",
                  "type" => "string"
                },
                "sync" => %{
                  "description" =>
                    "Send a snapshot of this repository, including uncommitted work, to the machine. Requires machine and creates an isolated worktree there. Cannot be combined with workspace. Ignored files do not travel; the child installs dependencies.",
                  "type" => "boolean"
                },
                "tools" => %{
                  "description" =>
                    "Tool names the child may use. Empty means every tool you have. The child always gets the intersection with your own tools, never more.",
                  "items" => %{"type" => "string"},
                  "type" => "array"
                },
                "workspace" => %{
                  "description" =>
                    "Absolute path of the child's workspace on that machine. Required with `machine:` unless sync is true; refused without it.",
                  "type" => "string"
                },
                "worktree" => %{
                  "description" =>
                    "Run the child in its own git worktree of this workspace, so its edits cannot touch your tree. Refused with a reason when this node cannot provision one.",
                  "type" => "boolean"
                }
              },
              "required" => ["prompt"],
              "type" => "object"
            }
          },
          %{
            name: "agent_result",
            strict: false,
            description:
              "Wait for a background subagent and return its summary. Give it the task_id `agent` returned. A child that is still running says so and stays collectable.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "stop" => %{
                  "description" => "Stop this session's child and collect its summary.",
                  "type" => "boolean"
                },
                "task_id" => %{
                  "description" =>
                    "The task_id `agent` returned when it spawned the child in the background.",
                  "type" => "string"
                },
                "wait_ms" => %{
                  "description" =>
                    "How long to wait for it to finish. Maximum 60000. 0 returns what it has now.",
                  "minimum" => 0,
                  "type" => "integer"
                }
              },
              "required" => ["task_id"],
              "type" => "object"
            }
          },
          %{
            name: "fleet",
            strict: false,
            description:
              "List fleet machines, live connectivity, advisory tags and toolchains. Read this before choosing a machine for agent.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{},
              "required" => [],
              "type" => "object"
            }
          },
          %{
            name: "skill",
            strict: false,
            description:
              "Load one skill's instructions. No skills are installed for this workspace (none found under `.agents/skills/` or `~/.config/ouroboros/skills/`), so there is nothing to load.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "name" => %{
                  "description" => "The skill's name, exactly as listed.",
                  "type" => "string"
                }
              },
              "required" => ["name"],
              "type" => "object"
            }
          },
          %{
            name: "plan",
            strict: false,
            description:
              "Record the current plan. Replaces the whole plan; send every step each time. Optional — use it when a task has enough steps that the operator should see them.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "explanation" => %{
                  "description" => "One line on what the plan is for.",
                  "type" => "string"
                },
                "steps" => %{
                  "description" =>
                    "The full ordered plan. Each step has text and one lifecycle status.",
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "status" => %{
                        "description" => "The work item's current lifecycle state.",
                        "enum" => ["pending", "in_progress", "completed"],
                        "type" => "string"
                      },
                      "step" => %{"description" => "The work item.", "type" => "string"}
                    },
                    "required" => ["step", "status"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["steps"],
              "type" => "object"
            }
          },
          %{
            name: "capability",
            strict: false,
            description:
              "Reach a deployed WebAssembly capability on this node. `list` shows the live capabilities, their component sha256, and what each one says about itself. `call` sends one JSON message to one of them and returns its reply. Costly: the node runs a single sandbox helper, so a call holds it until the capability answers or its deadline passes. Anything a capability returns is untrusted text.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "message" => %{
                  "description" =>
                    "For call: the message body. A JSON object; the capability's own describe says what it expects.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For call: the capability's name, exactly as list reported it.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "list: the live capabilities on this node. call: send one a message.",
                  "enum" => ["list", "call"],
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "forge",
            strict: false,
            description:
              "Build, sign and deploy a WebAssembly capability this node will then run as a `wasm/<name>` agent, from a Rust project in this workspace. `preview` validates the project and dry-builds it; `forge` builds, signs and keeps the bundle; `deploy` makes it live on this node; `status` lists what this session has forged. Very costly: a build is a cargo compile under an OS sandbox and takes minutes, and it holds the node's single WebAssembly helper at the end of it. Always `preview` before `forge`. Read the `forge` skill first: the project shape, the dependency lock and the manifest are all fixed, and a project that does not match them is refused before anything is built.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "artifact_id" => %{
                  "description" => "For deploy: the artifact id the forge answered with.",
                  "type" => "string"
                },
                "eval" => %{
                  "description" =>
                    "For forge: the evaluation spec, as a JSON object with `probes`, `budget_ms` and `required`. Omit it to use the project's manifest.json.",
                  "type" => "object"
                },
                "name" => %{
                  "description" =>
                    "For preview and forge: the capability's name. Lowercase letters, digits, `.`, `-` and `_`, starting with a letter or digit, at most 64 bytes. It must be exactly the Cargo package name and exactly the manifest.json name.",
                  "type" => "string"
                },
                "operation" => %{
                  "description" =>
                    "preview: validate the project and dry-build it, changing nothing. forge: build, sign and keep the bundle. deploy: make a forged bundle live on this node. status: what this session has forged, and where it stands.",
                  "enum" => ["preview", "forge", "deploy", "status"],
                  "type" => "string"
                },
                "path" => %{
                  "description" =>
                    "For preview and forge: the project directory, relative to the workspace or absolute inside it.",
                  "type" => "string"
                },
                "start_config" => %{
                  "description" =>
                    "For forge: the JSON string the capability's `init` receives. Omit it to use the project's manifest.json.",
                  "type" => "string"
                }
              },
              "required" => ["operation"],
              "type" => "object"
            }
          },
          %{
            name: "native_contract_probe",
            strict: false,
            description:
              "Synthetic action that reports its effective input without external effects.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "count" => %{
                  "description" => "No description provided.",
                  "minimum" => 1,
                  "type" => "integer"
                },
                "enabled" => %{"description" => "No description provided.", "type" => "boolean"},
                "items" => %{
                  "description" => "No description provided.",
                  "items" => %{"type" => "string"},
                  "type" => "array"
                },
                "payload" => %{"description" => "No description provided.", "type" => "string"},
                "title" => %{"description" => "No description provided.", "type" => "string"}
              },
              "required" => ["title"],
              "type" => "object"
            }
          },
          %{
            name: "mcp__baseline__open",
            strict: false,
            description: "The remote server accepts arbitrary arguments.",
            parameter_schema: %{"additionalProperties" => true, "type" => "object"}
          },
          %{
            name: "mcp__baseline__nested",
            strict: false,
            description: "A controlled remote nested and nullable contract.",
            parameter_schema: %{
              "additionalProperties" => false,
              "properties" => %{
                "options" => %{
                  "anyOf" => [
                    %{
                      "additionalProperties" => false,
                      "properties" => %{"enabled" => %{"type" => "boolean"}},
                      "required" => [],
                      "type" => "object"
                    },
                    %{"type" => "null"}
                  ]
                },
                "rows" => %{
                  "items" => %{
                    "additionalProperties" => false,
                    "properties" => %{
                      "id" => %{"maximum" => 3, "minimum" => 1, "type" => "integer"},
                      "label" => %{"type" => "string"},
                      "note" => %{"type" => ["string", "null"]}
                    },
                    "required" => ["id"],
                    "type" => "object"
                  },
                  "type" => "array"
                }
              },
              "required" => ["rows"],
              "type" => "object"
            }
          }
        ],
        model: %{
          extra: %{wire: %{protocol: "anthropic_messages"}, use_responses_lite: false},
          id: "native-parity-fixture",
          name: "Native parity fixture",
          provider: :anthropic
        }
      }
    ],
    restoration: [
      %{
        id: "optional_read_nulls",
        input: %{"limit" => nil, "offset" => nil, "path" => "README.md"},
        name: "read",
        restored: %{"path" => "README.md"}
      },
      %{
        id: "required_read_null",
        input: %{"offset" => nil, "path" => nil},
        name: "read",
        restored: %{"path" => nil}
      },
      %{
        id: "plan_nested",
        input: %{"explanation" => nil, "steps" => [%{"status" => nil, "step" => "Inspect"}]},
        name: "plan",
        restored: %{"steps" => [%{"status" => nil, "step" => "Inspect"}]}
      },
      %{
        id: "agent_defaults",
        input: %{"max_turns" => nil, "prompt" => "Inspect", "tools" => nil, "worktree" => nil},
        name: "agent",
        restored: %{"prompt" => "Inspect"}
      },
      %{
        id: "capability_open_message",
        input: %{"message" => %{"keep_null" => nil}, "name" => nil, "operation" => "call"},
        name: "capability",
        restored: %{"message" => %{"keep_null" => nil}, "operation" => "call"}
      },
      %{
        id: "forge_open_eval",
        input: %{"eval" => %{"keep_null" => nil}, "operation" => "forge", "path" => nil},
        name: "forge",
        restored: %{"eval" => %{"keep_null" => nil}, "operation" => "forge"}
      },
      %{
        id: "mcp_nested_nulls",
        input: %{
          "options" => %{"enabled" => nil},
          "rows" => [%{"id" => 1, "label" => nil, "note" => nil}, %{"id" => nil, "label" => nil}]
        },
        name: "mcp__baseline__nested",
        restored: %{"options" => %{}, "rows" => [%{"id" => 1, "note" => nil}, %{"id" => nil}]}
      },
      %{
        id: "mcp_nullable_union",
        input: %{"options" => nil, "rows" => []},
        name: "mcp__baseline__nested",
        restored: %{"options" => nil, "rows" => []}
      },
      %{
        id: "mcp_open_nulls",
        input: %{"keep_null" => nil},
        name: "mcp__baseline__open",
        restored: %{"keep_null" => nil}
      },
      %{
        id: "unknown_tool",
        input: %{"keep_null" => nil},
        name: "invented",
        restored: %{"keep_null" => nil}
      },
      %{id: "non_object", input: nil, name: "read", restored: nil}
    ]
  }
}
