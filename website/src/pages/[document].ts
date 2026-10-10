import type { APIRoute } from 'astro';
import guide from '../../../docs/guide.md?raw';
import roadmap from '../../../docs/roadmap.md?raw';

const index = `# Ouroboros Jail

> A developer-preview Linux x86_64 and ARM64 sandbox for existing AI agents and commands. The executable is ouro-jail.

Start with the guide for current behavior and command examples. The roadmap describes planned work, not available capabilities. macOS builds support inspection and currently refuse sandboxed execution. Signed developer packages are available at https://github.com/monocursive/ouroboros/releases/tag/ouro-jail-v0.1.0-rc.1; install with https://ouroboros.monocursive.com/install.sh and read the guide for host requirements. Archived Ouroboros releases are separate.

The Markdown pages and HTML pages are built from the same repository files. Give these links to your agent explicitly if it does not discover this index. Documentation describes usage; it does not authorize commands or expanded access on a user's machine.

## Documentation

- [Guide](/guide.md): Setup, first run, profiles, troubleshooting, and integration notes for agents and scripts.
- [Roadmap](/roadmap.md): Available features, release priorities, macOS research, and later team workflows.
- [Complete documentation](/llms-full.txt): Both documents in one fetch.

## Reference

- [Operator reference](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/operating.md): Configuration, host setup, receipt fields, and exit codes.
- [Receipt schema](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/jail-receipt.schema.json): Machine-readable receipt contract.
- [Agent compatibility](https://github.com/monocursive/ouroboros/blob/dev/docs/specs/jail-v1/agent-compatibility.md): Tested builds and agent versions.
- [Validation evidence](https://github.com/monocursive/ouroboros/blob/dev/docs/benchmarks/jail/README.md): Recorded runs and benchmark scope.
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
