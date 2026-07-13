# FirstCall security backport

This directory is the source published as `wayland-scanner` 0.31.10 on
crates.io. It is temporarily patched because that release constrains
`quick-xml` to the vulnerable 0.39 series.

The local delta intentionally contains only the upstream compatibility changes
needed for `quick-xml` 0.41:

- change the dependency from `quick-xml = "0.39"` to `"0.41"`;
- use `BytesRef::xml10_content()` in place of the renamed `xml_content()` API.

The API change is taken from upstream commit
`ec2d932855593d48aa83c76820f3efbcfea86d39`; the subsequent security version
bump is upstream commit `d07c4f91f28b42e5a485823ffd9d8d5a210b1053`.

Remove this directory and the root `[patch.crates-io]` entry after a fixed
`wayland-scanner` release reaches crates.io.
