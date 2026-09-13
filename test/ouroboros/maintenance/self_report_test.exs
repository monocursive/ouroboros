defmodule Ouroboros.Maintenance.SelfReportTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.{Epoch, SelfReport}

  setup do
    root = Path.join(System.tmp_dir!(), "self-report-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    epoch = start_supervised!({Epoch, name: nil, data_dir: Path.join(root, "epoch")})
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, epoch: epoch}
  end

  test "target writes controller-compatible Epoch and self-report observations", %{
    root: root,
    epoch: epoch
  } do
    assert {:ok, %{"epoch" => 0, "pending" => []}} = SelfReport.write_epoch(root, epoch)

    attrs = %{
      transaction_id: "transaction-1",
      pid: 42,
      birth: "test:42:1",
      port: 45_678,
      generation_digest: "sha256:" <> String.duplicate("a", 64),
      build_id: "build-1"
    }

    assert {:ok, report} = SelfReport.write(root, attrs, epoch)
    assert report["write_epoch"] == 0
    assert report["node"] == "nonode@nohost"
    assert report["distribution"] == false

    for name <- ["maintenance-epoch-observation.json", "maintenance-self-report.json"] do
      path = Path.join(root, name)
      assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
      assert is_map(JSON.decode!(File.read!(path)))
    end
  end

  test "pending Epoch prevents a target self-report", %{root: root, epoch: epoch} do
    assert {:ok, _} = Epoch.reserve("pending", String.duplicate("a", 64), epoch)

    attrs = %{
      transaction_id: "transaction-1",
      pid: 42,
      birth: "test:42:1",
      port: 45_678,
      generation_digest: "sha256:" <> String.duplicate("a", 64),
      build_id: "build-1"
    }

    assert {:error, :pending_epoch_write} = SelfReport.write(root, attrs, epoch)
    refute File.exists?(Path.join(root, "maintenance-self-report.json"))
  end
end
