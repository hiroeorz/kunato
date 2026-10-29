# Upload inspection fixtures

Real-world images that were once rejected by `limits.upload_inspection` as
script content. Compressed image data contains byte sequences such as `<%` and
`<?=` by chance (fifteen `<%` occurrences in the PNG and three in the WebP,
including `<%Wt=`), so these files pin the marker-specificity logic in
`src/upload.rs`.

- `real-world-infographic.png` — 1672x941 PNG, 2.1 MB. Contains fifteen `<%`
  and one `<?=` sequence in the compressed data; none is a scriptlet opening.
- `real-world-response-diagram.webp` — 2447x1713 VP8 WebP, 260 KB. Contains
  three `<%` sequences, one of them `<%Wt=`; none is a scriptlet opening.

Both are checked by the unit test `real_world_images_with_marker_like_bytes_pass`
and the integration test
`upload_inspection_accepts_real_world_images_with_marker_bytes`. A polyglot with
a real marker (`<?php`, `<% out.print(...) %>`, `<?= $x ?>`) must still be
rejected, which the neighbouring tests cover.

Replace a fixture only when it no longer reproduces the case; a re-encoded copy
changes the byte sequences the test depends on.
