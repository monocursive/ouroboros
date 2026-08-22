defmodule Ouroboros.CodeIntel.Registry do
  @moduledoc """
  Turns a file path into "which language server, started how, rooted where".

  Three rules govern this module, and all three are refusals.

  **Nothing is ever installed.** Discovery looks in the project's own binary directories
  and then on the user's `PATH`, in that order, and stops. A language with no server
  present resolves to `{:error, {:server_unavailable, server_id, hint}}` carrying the
  command an operator would run — printing a hint is the whole of this runtime's
  involvement. OpenCode downloads and compiles ElixirLS from GitHub and Serena
  auto-downloads with checksums; both are reasonable and neither is this. `ouro lsp
  install` is a later slice, and until it exists the answer is the hint.

  **A root is never above the workspace.** The project root is the nearest directory
  holding one of the language's marker files, walking up from the file and stopping at
  the workspace root — which is included in the walk, because a marker sitting in the
  workspace root itself is the common case and the walk that misses it is the off-by-one
  a reviewer caught in Gemini CLI's PR #15149. A path outside every admitted workspace
  root resolves to an error before any directory is read.

  **No marker means no server.** A file with no project root above it is not silently
  rooted at the workspace: an unrooted server is how monorepo false-positive diagnostics
  happen (R4 §4). A caller that knows better passes `root:` explicitly, and that root is
  still checked for containment.

  Preferring the project's own binary — `node_modules/.bin/typescript-language-server`
  over a global one — matches every client surveyed, and it means running a program the
  repository supplied. That is the same trust an editor extends by opening the project,
  and it is stated here rather than left implicit.

  Operators extend or override definitions through `config :ouroboros, :code_intel,
  servers: [...]`; an entry for a known language merges over the built-in, an entry for a
  new one is added, and a malformed entry is dropped with a warning rather than taking
  the boot with it.
  """

  require Logger

  alias Ouroboros.CodeIntel.Config
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  # A project tree deeper than this between a file and its workspace root is a symlink
  # loop or a mistake, not a layout.
  @max_walk_depth 64

  @type definition :: %{
          language: atom(),
          extensions: %{String.t() => String.t()},
          root_markers: [String.t()],
          candidates: [candidate()]
        }

  @type candidate :: %{
          server_id: String.t(),
          command: String.t(),
          args: [String.t()],
          local_bins: [String.t()],
          hint: String.t()
        }

  @built_in [
    %{
      language: :typescript,
      extensions: %{
        ".ts" => "typescript",
        ".mts" => "typescript",
        ".cts" => "typescript",
        ".tsx" => "typescriptreact",
        ".js" => "javascript",
        ".mjs" => "javascript",
        ".cjs" => "javascript",
        ".jsx" => "javascriptreact"
      },
      root_markers: ["tsconfig.json", "jsconfig.json", "package.json"],
      candidates: [
        %{
          server_id: "typescript-language-server",
          command: "typescript-language-server",
          args: ["--stdio"],
          local_bins: ["node_modules/.bin/typescript-language-server"],
          hint: "npm install -g typescript-language-server typescript"
        }
      ]
    },
    %{
      language: :python,
      extensions: %{".py" => "python", ".pyi" => "python"},
      root_markers: ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"],
      candidates: [
        %{
          server_id: "pyright-langserver",
          command: "pyright-langserver",
          args: ["--stdio"],
          local_bins: [
            "node_modules/.bin/pyright-langserver",
            ".venv/bin/pyright-langserver",
            "venv/bin/pyright-langserver"
          ],
          hint: "npm install -g pyright"
        }
      ]
    },
    %{
      language: :go,
      extensions: %{".go" => "go"},
      root_markers: ["go.work", "go.mod"],
      candidates: [
        %{
          server_id: "gopls",
          command: "gopls",
          args: [],
          local_bins: [],
          hint: "go install golang.org/x/tools/gopls@latest"
        }
      ]
    },
    %{
      language: :rust,
      extensions: %{".rs" => "rust"},
      root_markers: ["Cargo.toml", "rust-project.json"],
      candidates: [
        %{
          server_id: "rust-analyzer",
          command: "rust-analyzer",
          args: [],
          local_bins: [],
          hint: "rustup component add rust-analyzer"
        }
      ]
    },
    %{
      language: :c,
      extensions: %{
        ".c" => "c",
        ".h" => "c",
        ".cc" => "cpp",
        ".cpp" => "cpp",
        ".cxx" => "cpp",
        ".hh" => "cpp",
        ".hpp" => "cpp",
        ".hxx" => "cpp",
        ".m" => "objective-c",
        ".mm" => "objective-cpp"
      },
      root_markers: ["compile_commands.json", ".clangd", "compile_flags.txt"],
      candidates: [
        %{
          server_id: "clangd",
          command: "clangd",
          args: [],
          local_bins: [],
          hint: "install clangd from your LLVM distribution"
        }
      ]
    },
    %{
      language: :java,
      extensions: %{".java" => "java"},
      root_markers: ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
      candidates: [
        %{
          server_id: "jdtls",
          command: "jdtls",
          args: [],
          local_bins: [],
          hint: "install eclipse.jdt.ls and put jdtls on PATH"
        }
      ]
    },
    %{
      language: :elixir,
      extensions: %{".ex" => "elixir", ".exs" => "elixir", ".heex" => "html-eex"},
      root_markers: ["mix.exs"],
      candidates: [
        %{
          server_id: "expert",
          command: "expert",
          args: [],
          local_bins: [".expert/expert"],
          hint: "install Expert from https://expert-lsp.org and put expert on PATH"
        },
        %{
          server_id: "elixir-ls",
          command: "elixir-ls",
          args: [],
          local_bins: [".elixir_ls/release/language_server.sh"],
          hint: "install ElixirLS and put elixir-ls (or language_server.sh) on PATH"
        },
        %{
          server_id: "elixir-ls",
          command: "language_server.sh",
          args: [],
          local_bins: [],
          hint: "install ElixirLS and put elixir-ls (or language_server.sh) on PATH"
        }
      ]
    },
    %{
      language: :ruby,
      extensions: %{".rb" => "ruby", ".rake" => "ruby"},
      root_markers: ["Gemfile", ".ruby-lsp"],
      candidates: [
        %{
          server_id: "ruby-lsp",
          command: "ruby-lsp",
          args: [],
          local_bins: ["bin/ruby-lsp"],
          hint: "gem install ruby-lsp, or add it to the Gemfile and run bundle binstubs"
        }
      ]
    },
    %{
      language: :swift,
      extensions: %{".swift" => "swift"},
      root_markers: ["Package.swift"],
      candidates: [
        %{
          server_id: "sourcekit-lsp",
          command: "sourcekit-lsp",
          args: [],
          local_bins: [],
          hint: "install a Swift toolchain; sourcekit-lsp ships with it"
        }
      ]
    }
  ]

  @doc """
  Every definition this node understands, operator configuration merged in.

  An override for a language already known carries only the keys it changes — restating
  the extension table to move a root marker is the kind of duplication that goes stale. A
  definition for a language the registry does not know has to be complete, and one that
  is not is dropped with a warning.
  """
  @spec definitions() :: [definition()]
  def definitions do
    Enum.reduce(configured(), @built_in, fn override, acc ->
      case Enum.find_index(acc, &(&1.language == override.language)) do
        nil -> add_language(acc, override)
        index -> List.update_at(acc, index, &Map.merge(&1, override))
      end
    end)
  end

  defp add_language(acc, override) do
    if Map.has_key?(override, :extensions) and Map.has_key?(override, :candidates) and
         Map.get(override, :root_markers, []) != [] do
      acc ++ [Map.put_new(override, :root_markers, [])]
    else
      Logger.warning(fn ->
        "code_intel ignored a :servers entry for the unknown language " <>
          "#{inspect(override.language)}: a new language needs extensions, root_markers, " <>
          "and candidates"
      end)

      acc
    end
  end

  @doc """
  Returns the definition and LSP language identifier for a file, by extension.
  """
  @spec for_path(String.t()) :: {:ok, definition(), String.t()} | {:error, term()}
  def for_path(path) when is_binary(path) do
    extension = path |> Path.extname() |> String.downcase()

    definitions()
    |> Enum.find_value(fn definition ->
      case Map.fetch(definition.extensions, extension) do
        {:ok, language_id} -> {:ok, definition, language_id}
        :error -> nil
      end
    end)
    |> case do
      nil -> {:error, {:unsupported_language, extension}}
      found -> found
    end
  end

  @doc """
  Resolves a file into a spawn spec for `Ouroboros.CodeIntel.LspPool`.

  Options: `workspace_root:` names the boundary the walk may not cross (otherwise the
  admitted workspace root containing the file is used), and `root:` forces the project
  root, skipping the marker walk but not the containment check.
  """
  @spec resolve(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def resolve(path, opts \\ []) when is_binary(path) do
    with {:ok, file} <- WorkspacePath.canonicalize_file(path),
         {:ok, workspace_root} <- workspace_root(file, opts),
         true <-
           WorkspacePath.within?(file, workspace_root) || {:error, {:outside_workspace, path}},
         {:ok, definition, language_id} <- for_path(file),
         {:ok, root} <- project_root(file, workspace_root, definition, opts),
         {:ok, candidate, executable} <- discover(definition, root, workspace_root) do
      {:ok,
       %{
         root: root,
         server_id: candidate.server_id,
         executable: executable,
         args: candidate.args,
         env: [],
         language: definition.language,
         language_id: language_id,
         path: file,
         workspace_root: workspace_root
       }}
    else
      {:error, reason} -> {:error, reason}
      false -> {:error, {:outside_workspace, path}}
    end
  end

  @doc """
  The nearest directory at or above `file` holding one of `markers`, bounded below by
  `workspace_root`.
  """
  @spec nearest_root(String.t(), String.t(), [String.t()]) :: {:ok, String.t()} | :error
  def nearest_root(file, workspace_root, markers) do
    file
    |> Path.dirname()
    |> ancestors(workspace_root, @max_walk_depth)
    |> Enum.find(fn directory ->
      Enum.any?(markers, &File.exists?(Path.join(directory, &1)))
    end)
    |> case do
      nil -> :error
      directory -> {:ok, directory}
    end
  end

  @doc """
  Every directory from `directory` up to and including `boundary`.

  `Path.dirname("/") == "/"`, so a walk that does not name its own stop condition either
  spins at the filesystem root or drops the root directory from the list. Both have
  shipped in real clients; this returns `["/a", "/"]` for `("/a", "/")` and `[]` for a
  directory the boundary does not contain.
  """
  @spec ancestors(String.t(), String.t(), pos_integer()) :: [String.t()]
  def ancestors(directory, boundary, depth \\ @max_walk_depth)
  def ancestors(_directory, _boundary, depth) when depth <= 0, do: []

  def ancestors(directory, boundary, depth) do
    cond do
      directory == boundary ->
        [directory]

      not WorkspacePath.within?(directory, boundary) ->
        []

      true ->
        parent = Path.dirname(directory)

        if parent == directory,
          do: [directory],
          else: [directory | ancestors(parent, boundary, depth - 1)]
    end
  end

  ## Internals

  defp workspace_root(file, opts) do
    case Keyword.get(opts, :workspace_root) do
      root when is_binary(root) and root != "" ->
        WorkspacePath.canonicalize(root)

      _unset ->
        admitted_root(file)
    end
  end

  # Fail closed: a file under no admitted workspace root gets no language server, because
  # the alternative is spawning a program with a foreign directory as its cwd.
  defp admitted_root(file) do
    :ouroboros
    |> Application.get_env(:workspace_allowed_roots, [])
    |> Enum.flat_map(fn root ->
      case WorkspacePath.canonicalize(root) do
        {:ok, canonical} -> [canonical]
        {:error, _reason} -> []
      end
    end)
    |> Enum.filter(&WorkspacePath.within?(file, &1))
    |> Enum.max_by(&byte_size/1, fn -> nil end)
    |> case do
      nil -> {:error, {:outside_workspace, file}}
      root -> {:ok, root}
    end
  end

  defp project_root(file, workspace_root, definition, opts) do
    case Keyword.get(opts, :root) do
      forced when is_binary(forced) and forced != "" ->
        with {:ok, canonical} <- WorkspacePath.canonicalize(forced) do
          if WorkspacePath.within?(canonical, workspace_root) and
               WorkspacePath.within?(file, canonical) do
            {:ok, canonical}
          else
            {:error, {:root_outside_workspace, forced, workspace_root}}
          end
        end

      _unset ->
        case nearest_root(file, workspace_root, definition.root_markers) do
          {:ok, root} -> {:ok, root}
          :error -> {:error, {:no_project_root, definition.language, definition.root_markers}}
        end
    end
  end

  # Project-local binaries first, from the project root up to the workspace root — a
  # hoisted `node_modules/.bin` in a monorepo is the normal layout, not an exception.
  defp discover(definition, root, workspace_root) do
    directories = ancestors(root, workspace_root, @max_walk_depth)

    Enum.find_value(definition.candidates, fn candidate ->
      case executable_for(candidate, directories) do
        {:ok, executable} -> {:ok, candidate, executable}
        :error -> nil
      end
    end)
    |> case do
      nil ->
        preferred = List.first(definition.candidates)
        {:error, {:server_unavailable, preferred.server_id, preferred.hint}}

      found ->
        found
    end
  end

  defp executable_for(candidate, directories) do
    local =
      for directory <- directories,
          local_bin <- candidate.local_bins,
          path = Path.join(directory, local_bin),
          executable_file?(path),
          do: path

    case local do
      [path | _rest] ->
        {:ok, path}

      [] ->
        case System.find_executable(candidate.command) do
          nil -> :error
          path -> {:ok, path}
        end
    end
  end

  defp executable_file?(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular, mode: mode}} -> Bitwise.band(mode, 0o111) != 0
      _other -> false
    end
  end

  defp configured do
    Config.get(:servers)
    |> List.wrap()
    |> Enum.flat_map(fn entry ->
      case normalize(entry) do
        {:ok, definition} ->
          [definition]

        {:error, reason} ->
          Logger.warning(fn ->
            "code_intel ignored a :servers entry: #{inspect(reason)} in #{inspect(entry)}"
          end)

          []
      end
    end)
  end

  defp normalize(entry) when is_list(entry) do
    if Keyword.keyword?(entry), do: normalize(Map.new(entry)), else: {:error, :not_a_definition}
  end

  defp normalize(%{language: language} = entry) when is_atom(language) and not is_nil(language) do
    with {:ok, partial} <- put_extensions(%{language: language}, entry),
         {:ok, partial} <- put_candidates(partial, entry) do
      case Map.fetch(entry, :root_markers) do
        {:ok, markers} ->
          if is_list(markers) and Enum.all?(markers, &is_binary/1),
            do: {:ok, Map.put(partial, :root_markers, markers)},
            else: {:error, :bad_root_markers}

        :error ->
          {:ok, partial}
      end
    end
  end

  defp normalize(_entry), do: {:error, :missing_language}

  defp put_extensions(partial, entry) do
    case Map.fetch(entry, :extensions) do
      :error ->
        {:ok, partial}

      {:ok, extensions} ->
        with {:ok, normalized} <- normalize_extensions(extensions, partial.language),
             do: {:ok, Map.put(partial, :extensions, normalized)}
    end
  end

  defp normalize_extensions(extensions, _language) when is_map(extensions) do
    if Enum.all?(extensions, fn {key, value} -> is_binary(key) and is_binary(value) end),
      do: {:ok, extensions},
      else: {:error, :bad_extensions}
  end

  # A bare list of extensions is accepted and each one is given the language's own name as
  # its LSP identifier, which is right for every single-identifier language.
  defp normalize_extensions(extensions, language) when is_list(extensions) do
    if Enum.all?(extensions, &is_binary/1),
      do: {:ok, Map.new(extensions, &{&1, Atom.to_string(language)})},
      else: {:error, :bad_extensions}
  end

  defp normalize_extensions(_extensions, _language), do: {:error, :bad_extensions}

  defp put_candidates(partial, entry) do
    case Map.fetch(entry, :candidates) do
      :error ->
        {:ok, partial}

      {:ok, candidates} when is_list(candidates) and candidates != [] ->
        normalized = Enum.map(candidates, &normalize_candidate/1)

        if Enum.all?(normalized, &is_map/1),
          do: {:ok, Map.put(partial, :candidates, normalized)},
          else: {:error, :bad_candidates}

      {:ok, _other} ->
        {:error, :bad_candidates}
    end
  end

  defp normalize_candidate(candidate) do
    candidate = if Keyword.keyword?(candidate), do: Map.new(candidate), else: candidate

    with %{server_id: server_id, command: command} <- candidate,
         true <- is_binary(server_id) and is_binary(command) do
      %{
        server_id: server_id,
        command: command,
        args: candidate |> Map.get(:args, []) |> List.wrap(),
        local_bins: candidate |> Map.get(:local_bins, []) |> List.wrap(),
        hint: Map.get(candidate, :hint, "install #{server_id} and put it on PATH")
      }
    else
      _invalid -> nil
    end
  end
end
