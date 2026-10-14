#!/bin/sh
# Greywall security spot-check (pass-5 probe subset analogs).
export PATH=$HOME/.local/bin:$PATH
cd /tmp || exit 1

echo "=== 1. default read deny (~/.ssh) ==="
greywall -- cat ~/.ssh/authorized_keys 2>&1 | tail -1
echo "=== 2. default write deny (outside cwd) ==="
greywall -- sh -c 'echo x > ~/greytest-hostfile' 2>&1 | tail -1; ls ~/greytest-hostfile 2>&1
echo "=== 3. pidns: host processes visible? ==="
greywall -- sh -c 'ps aux | wc -l; ls /proc | grep -c "^[0-9]"' 2>&1 | tail -2
echo "=== 4. syscall probe under greywall ==="
gcc -O1 -o /tmp/a5_gwsys /tmp/a5_gwsys.c 2>/dev/null
greywall --allow-path /tmp -- /tmp/a5_gwsys 2>/dev/null
echo "=== 5. syscall probe under ouro-jail tool (comparison) ==="
cd /tmp && ouro-jail run --profile tool -- ./a5_gwsys 2>&1 | tail -20
echo "=== 6. config location ==="
ls -la ~/.config/greywall 2>&1 | head -4
echo "=== 7. config plant via --allow-path ==="
greywall --allow-path ~/.config/greywall -- sh -c 'ls ~/.config/greywall/ 2>&1 | head; touch ~/.config/greywall/pwn-marker && echo PLANTED-CONFIG' 2>&1 | tail -3
ls -la ~/.config/greywall/ 2>/dev/null | head -5
echo "=== 8. binary replace via --allow-path ~/.local/bin (C3 analog) ==="
greywall --allow-path ~/.local/bin -- sh -c 'cd ~/.local/bin && cp greywall gw.real && printf "#!/bin/sh\nexec /home/ubuntu/.local/bin/gw.real \"\$@\"\n" > wrap && chmod 755 wrap && mv wrap greywall && echo REPLACED-GREYWALL' 2>&1 | tail -1
echo "--- operator next greywall invocation:"
greywall --version 2>&1 | head -2
echo "--- restore:"
mv ~/.local/bin/gw.real ~/.local/bin/greywall && echo RESTORED && greywall --version 2>&1 | head -1
rm -f ~/.config/greywall/pwn-marker
echo "=== 9. opencode e2e under greywall (network-dead check) ==="
mkdir -p ~/ocgw && cd ~/ocgw && rm -f greeting.txt
timeout 90 greywall --auto-profile --profile opencode -- ~/.opencode/bin/opencode run "Create a file named greeting.txt containing the single word hello" 2>&1 | tail -4
ls -la ~/ocgw/greeting.txt 2>&1
echo SPOTCHECK-DONE
