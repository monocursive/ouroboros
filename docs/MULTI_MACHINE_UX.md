# Working on a few computers

Start with the computer and project you want to use. Your files and AI connection belong to that computer, even when you control it from another one.

## Everyday use

- **Web:** open **New session**, choose **Computer**, then **Browse** for a project folder. Connect the AI account in the form if needed, describe the task, and start. The form remembers the computer and folder from a successful start.
- **Terminal app:** press **F5** on the task screen. Choose a computer, open its folders, and select **Use this folder**. Your task draft stays in place. Type the task and press Enter; ChatGPT sign-in is guided if that computer needs it. The chosen computer and folder are remembered together.
- If a computer is offline, reconnect it or explicitly choose another one. Setup and task requests never fall back to the local computer.
- Keep **Machines** available for connection checks. The web navigation shows both Machines and connection status on small screens, including inside a conversation.

## Connecting another computer

Open `ouro`, enter `/machines`, and choose a discovered computer or **Add a reachable machine**. The guided setup currently needs SSH access, or an invitation you transfer yourself. Connection method, Tailscale installation, and alternate binaries live behind **F6 advanced options** in the add form. Review the suggested names and addresses before confirming.

After connecting, choose that computer in F5 or the web task form to select a project and finish its AI setup. A network connection alone does not mean an AI account is connected.

**Keep this machine running** installs, starts, and verifies automatic recovery. A failed activation is reported as a failure with a retry path. Enabling recovery keeps Ouroboros available after closing the terminal; it does not prevent a computer from sleeping or losing its network connection.

## Audit follow-up and limits

These changes address destination selection, destination-specific setup and browsing, draft preservation, recovery activation, mobile navigation, and unnamed conversation labels from the [multi-machine UX board](https://www.figma.com/design/Ju68DuHSiioFFnUO866yar?node-id=2-2).

Browser-only pairing is still missing. The web Machines page provides a guided terminal handoff rather than claiming it can pair computers itself.

The repository's public release signing key is still unprovisioned. Signed installation and updates remain unavailable until the release owner completes [release signing setup](DISTRIBUTION.md). Signature checks have not been weakened.

Local validation covers gateway routing between separate runtime processes, remote folder boundaries, device-code routing, offline refusal, TUI draft and account isolation, existing onboarding scenarios, and rendered desktop/mobile layouts. Real provider sign-in, two physical computers, sleep/reconnect, reboot recovery, and signed installation/update still require a live acceptance run.
