ukai-jail run --profile tool --workspace . --limit wall=30s -- \
    sh -c "cat $HOME/.ssh/authorized_keys; curl -sS https://example.com; echo ok > result.txt"
