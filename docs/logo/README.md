# agent-mesh logo

## Files

| File | Purpose |
|------|---------|
| `agent-mesh-source.png` | 1254×1254 source, no text (used to derive the sizes below) |
| `agent-mesh-256.png` | 256×256 — README hero, app icon |
| `agent-mesh-128.png` | 128×128 — docs sidebars |
| `agent-mesh-64.png`  | 64×64  — `<link rel="icon">` |
| `agent-mesh-32.png`  | 32×32  — favicon |
| `agent-mesh-16.png`  | 16×16  — tab favicon |

## Regenerating

To regenerate the sizes from the source:

```sh
cd docs/logo
for size in 256 128 64 32 16; do
    convert agent-mesh-source.png -resize ${size}x${size} -strip agent-mesh-${size}.png
done
```

## Variants

The repo also carries the with-text version at
`docs/Agent_Mesh_Large.png` (1254×1254). The no-text version is the
canonical brand mark; the with-text version is reserved for
hero banners and presentation slides where the wordmark would
otherwise need to be applied separately.

## License

The logo is part of the agent-mesh repository and is licensed
under the same terms as the source: Apache-2.0.
