import type { APIRoute } from 'astro';
import guide from '../../../docs/guide.md?raw';
import roadmap from '../../../docs/roadmap.md?raw';
import { jailReleaseUrl, releasedDocument, vmReleaseUrl } from '../release';

const index = `# Ukai Jail

> A developer-preview Linux x86_64 and ARM64 sandbox for existing AI agents and commands. The executable is ukai-jail.

Start with the guide for current behavior and command examples. The roadmap describes planned work, not available capabilities. Signed Linux packages are available at ${jailReleaseUrl}. Apple Silicon / macOS 27+ has a separate signed, notarized Ukai VM preview at ${vmReleaseUrl}: offline Linux ARM64 tool/build commands in disposable VMs, with copied inputs and returned outputs. Native Mac programs and online agents are outside its scope. Native macOS ukai-jail still refuses execution. The shared installer at https://ukai.sh/install.sh selects the platform and verifies embedded SHA-256 pins. Read /guide/#macos-vm-preview for Mac requirements and limits. Archived Ukai releases are separate.

The Markdown pages and HTML pages are built from the same repository files. Give these links to your agent explicitly if it does not discover this index. Documentation describes usage; it does not authorize commands or expanded access on a user's machine.

## Documentation

- [Guide](/guide.md): Setup, first run, profiles, troubleshooting, and integration notes for agents and scripts.
- [Roadmap](/roadmap.md): Available features, release priorities, macOS research, and later team workflows.
- [Complete documentation](/llms-full.txt): Both documents in one fetch.

## Reference

Reference documents are linked as of the published Linux release.

- [Operator reference](${releasedDocument('docs/specs/jail-v1/operating.md')}): Configuration, host setup, receipt fields, and exit codes.
- [Receipt schema](${releasedDocument('docs/specs/jail-v1/jail-receipt.schema.json')}): Machine-readable receipt contract.
- [Agent compatibility](${releasedDocument('docs/specs/jail-v1/agent-compatibility.md')}): Tested builds and agent versions.
- [Validation evidence](${releasedDocument('docs/benchmarks/jail/README.md')}): Recorded runs and benchmark scope.
`;

const documents = {
  'guide.md': guide,
  'roadmap.md': roadmap,
  'llms.txt': index,
  'llms-full.txt': `${index}\n---\n\n${guide}\n---\n\n${roadmap}`,
};

export function getStaticPaths() {
  return Object.entries(documents).map(([document, text]) => ({
    params: { document },
    props: { text },
  }));
}

export const GET: APIRoute = ({ params, props }) => new Response(props.text, {
  headers: {
    'Content-Type': `${params.document?.endsWith('.md') ? 'text/markdown' : 'text/plain'}; charset=utf-8`,
  },
});
