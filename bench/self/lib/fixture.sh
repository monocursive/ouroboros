#!/bin/sh
# A repository of known shape, for `bench/self/selftest.sh`.
#
#     bench/self/lib/fixture.sh <dir>
#
# Builds a two-file Mix project in `<dir>` with a history that contains, on purpose, one of
# each thing the extractor and the grader have to be able to tell apart. It prints four
# shas, one per line:
#
#   1  TASK        a real fix: its hidden test fails at the parent and passes at the commit
#   2  PASSES      a commit whose hidden test already passes at its parent
#   3  BROKEN      a commit whose hidden test does not pass at the commit either
#   4  MERGE       a merge
#
# Why a fixture at all, when this repository's own history is right there: the extractor's
# two gates — `parent_already_passes` and `commit_does_not_pass` — have no example in the
# corpus by construction, since a commit that trips either is dropped before it becomes a
# task. Proving them against this repository means finding a commit that happens to trip
# them and pinning it, which is a fact about the history rather than about the code. A
# fixture states the case instead of hunting for one, and compiles in a second rather than
# in three minutes, which is what makes a dozen more selftest phases affordable.
#
# It is a *real* Mix project built by the same `Bench.Self.Workspace.prepare/4` as any
# other tree: `test/support` on `elixirc_paths(:test)` and a `defp aliases do` block are
# both here so that the two exploits which use them can be run against it too.

set -eu

dir=${1:?usage: fixture.sh <dir>}

mkdir -p "$dir"
cd "$dir"

git -c init.defaultBranch=main init --quiet .
git config user.email "bench-self@localhost"
git config user.name "bench.self fixture"
git config commit.gpgsign false

commit() {
  git add -A
  git commit --quiet --no-verify -m "$1"
}

cat > mix.exs <<'MIX'
defmodule BenchSelfFixture.MixProject do
  use Mix.Project

  def project do
    [
      app: :bench_self_fixture,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      deps: []
    ]
  end

  def application, do: [extra_applications: []]

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp aliases do
    [
      "deps.patch": ["cmd true"]
    ]
  end
end
MIX

cat > .formatter.exs <<'FMT'
[inputs: ["{mix,.formatter}.exs", "{lib,test}/**/*.{ex,exs}"]]
FMT

cat > .gitignore <<'IGN'
/_build/
/deps/
IGN

mkdir -p lib test

cat > lib/fixture.ex <<'LIB'
defmodule BenchSelfFixture do
  @moduledoc "The subject of bench/self's own selftest."

  @doc "Greets somebody."
  def greet(_name), do: "hello"
end
LIB

cat > test/test_helper.exs <<'TH'
ExUnit.start()
TH

cat > test/existing_test.exs <<'EX'
defmodule BenchSelfFixture.ExistingTest do
  use ExUnit.Case, async: true

  test "greet answers with a string" do
    assert is_binary(BenchSelfFixture.greet("anyone"))
  end
end
EX

commit "chore(fixture): the starting point"

# --- 1. the task: fails at the parent, passes here ---------------------------

cat > lib/fixture.ex <<'LIB'
defmodule BenchSelfFixture do
  @moduledoc "The subject of bench/self's own selftest."

  @doc "Greets somebody by name."
  def greet(name), do: "hello " <> name
end
LIB

cat > test/greet_test.exs <<'EX'
defmodule BenchSelfFixture.GreetTest do
  use ExUnit.Case, async: true

  test "greet uses the name it was given" do
    assert BenchSelfFixture.greet("world") == "hello world"
  end
end
EX

# The task modifies a test that already existed as well as adding one, because the cheats
# that blank a *pre-existing* test need one to blank. Both are hidden; both are restored.
cat > test/existing_test.exs <<'EX'
defmodule BenchSelfFixture.ExistingTest do
  use ExUnit.Case, async: true

  test "greet answers with the name in it" do
    assert BenchSelfFixture.greet("anyone") == "hello anyone"
  end
end
EX

commit "fix(fixture): greet the name it was given, not everybody at once"
task=$(git rev-parse HEAD)

# --- 2. a commit whose hidden test already passes at its parent --------------

cat > lib/fixture.ex <<'LIB'
defmodule BenchSelfFixture do
  @moduledoc "The subject of bench/self's own selftest."

  @doc "Greets somebody by name."
  def greet(name), do: "hello " <> name

  @doc "Greets somebody loudly."
  def shout(name), do: String.upcase(greet(name))
end
LIB

cat > test/passes_test.exs <<'EX'
defmodule BenchSelfFixture.PassesTest do
  use ExUnit.Case, async: true

  test "greet already did this before the change" do
    assert BenchSelfFixture.greet("world") == "hello world"
  end
end
EX

commit "fix(fixture): a hidden test that already passes at the parent"
passes=$(git rev-parse HEAD)

# --- 3. a commit whose hidden test does not pass at the commit ---------------

cat > lib/fixture.ex <<'LIB'
defmodule BenchSelfFixture do
  @moduledoc "The subject of bench/self's own selftest."

  @doc "Greets somebody by name."
  def greet(name), do: "hello " <> name

  @doc "Greets somebody loudly."
  def shout(name), do: String.upcase(greet(name))

  @doc "Answers wrongly, on purpose."
  def answer, do: 1
end
LIB

cat > test/broken_test.exs <<'EX'
defmodule BenchSelfFixture.BrokenTest do
  use ExUnit.Case, async: true

  test "the answer, which this commit does not deliver" do
    assert BenchSelfFixture.answer() == 2
  end
end
EX

commit "fix(fixture): a hidden test that does not pass at its own commit"
broken=$(git rev-parse HEAD)

# --- 4. a merge -------------------------------------------------------------

git checkout --quiet -b side "$task"

cat > lib/side.ex <<'LIB'
defmodule BenchSelfFixture.Side do
  @moduledoc false

  def branch, do: :side
end
LIB

cat > test/side_test.exs <<'EX'
defmodule BenchSelfFixture.SideTest do
  use ExUnit.Case, async: true

  test "the side branch is the side branch" do
    assert BenchSelfFixture.Side.branch() == :side
  end
end
EX

commit "fix(fixture): a change on a side branch"

git checkout --quiet main
git merge --quiet --no-ff --no-edit -m "merge(fixture): the side branch" side
merge=$(git rev-parse HEAD)

echo "$task"
echo "$passes"
echo "$broken"
echo "$merge"
