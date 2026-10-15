// Release coordinates come from the one file the packaging scripts also read.
import release from '../../crates/ukai-jail/dist/release.json';

export const repositoryUrl = `https://github.com/${release.repository}`;
const releases = `${repositoryUrl}/releases/tag`;

export const jailVersion = release.jail.version;
// Published previews retain their immutable pre-rename tags. Packaging uses
// tag_prefix for future Ukai releases; publishing also updates published_tag.
export const jailTag = release.jail.published_tag;
export const jailCommand = jailTag.replace(/-v\d.*$/, '');
export const jailReleaseUrl = `${releases}/${jailTag}`;
export const vmVersion = release.vm.version;
export const vmCommand = release.vm.published_tag.replace(/-v\d.*$/, '');
export const vmReleaseUrl = `${releases}/${release.vm.published_tag}`;

// Reference documents as of the published Linux release, so a reader sees the
// contract the released binary implements rather than later development.
export const releasedDocument = (path: string) => `${repositoryUrl}/blob/${jailTag}/${path}`;
