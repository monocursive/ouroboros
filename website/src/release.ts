// Release coordinates come from the one file the packaging scripts also read.
import release from '../../crates/ukai-jail/dist/release.json';

export const repositoryUrl = `https://github.com/${release.repository}`;
const releases = `${repositoryUrl}/releases/tag`;

export const jailVersion = release.jail.version;
export const jailTag = `${release.jail.tag_prefix}${release.jail.version}`;
export const jailReleaseUrl = `${releases}/${jailTag}`;
export const vmVersion = release.vm.version;
export const vmReleaseUrl = `${releases}/${release.vm.tag_prefix}${release.vm.version}`;

// Reference documents as of the published Linux release, so a reader sees the
// contract the released binary implements rather than later development.
export const releasedDocument = (path: string) => `${repositoryUrl}/blob/${jailTag}/${path}`;
