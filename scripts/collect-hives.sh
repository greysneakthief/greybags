#!/usr/bin/env bash
# Extract NTUSER.DAT and UsrClass.dat (plus .LOG/.LOG1/.LOG2 transaction
# logs) from a disk image with The Sleuth Kit, without mounting it.
#
#   scripts/collect-hives.sh -i disk.E01 -d ./case42/hives
#   scripts/collect-hives.sh -i disk.raw -o 2048 -d ./case42/hives
#   greybags analyze ./case42/hives
#
# Options:
#   -i IMAGE   raw/dd, E01 or other image format supported by your TSK build
#   -o OFFSET  partition start in sectors (default: every NTFS partition from mmls)
#   -d OUTDIR  output directory (created; must not already contain files)
#   -a         include deleted (unallocated) directory entries as well
#
# Output layout: OUTDIR/p<offset>/<original path>, plus OUTDIR/manifest.tsv
# with SHA-256, size, MFT address and source path for each extracted file.
#
# Requires: sleuthkit (mmls, fls, icat) — `apt-get install sleuthkit`.
# Debian/Ubuntu's sleuthkit is built with libewf, so E01 works directly.
set -euo pipefail

IMAGE="" OFFSET="" OUT="" ALL=0
while getopts "i:o:d:ah" opt; do
    case "$opt" in
        i) IMAGE="$OPTARG" ;;
        o) OFFSET="$OPTARG" ;;
        d) OUT="$OPTARG" ;;
        a) ALL=1 ;;
        h) sed -n '2,22p' "$0"; exit 0 ;;
        *) exit 2 ;;
    esac
done
if [ -z "$IMAGE" ] || [ -z "$OUT" ]; then
    sed -n '2,22p' "$0"
    exit 2
fi
for t in mmls fls icat sha256sum; do
    command -v "$t" >/dev/null || { echo "missing $t (apt-get install sleuthkit)" >&2; exit 1; }
done
[ -r "$IMAGE" ] || { echo "cannot read $IMAGE" >&2; exit 1; }
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
    echo "$OUT is not empty; refusing to mix evidence sets" >&2
    exit 1
fi
mkdir -p "$OUT"
MANIFEST="$OUT/manifest.tsv"
printf 'sha256\tsize\tpartition_offset\tmft_address\tdeleted\tsource_path\toutput_path\n' > "$MANIFEST"

offsets=()
if [ -n "$OFFSET" ]; then
    offsets=("$OFFSET")
else
    # mmls rows: slot start end length description. Keep NTFS/Basic data partitions.
    while read -r start; do
        offsets+=("$((10#$start))")
    done < <(mmls "$IMAGE" 2>/dev/null | awk '/NTFS|exFAT|Basic data|0x07/ {print $3}')
    if [ ${#offsets[@]} -eq 0 ]; then
        echo "no NTFS partitions found by mmls; assuming a bare volume image (offset 0)" >&2
        offsets=(0)
    fi
fi

pattern='(^|/)(ntuser\.dat|usrclass\.dat)(\.log[12]?)?$'
count=0
for off in "${offsets[@]}"; do
    echo "== partition at sector $off"
    # fls -r -p: recursive, full paths. Lines look like
    #   r/r 12345-128-1:<TAB>Users/bob/NTUSER.DAT
    #   r/r * 12345-128-1(realloc):<TAB>Users/old/NTUSER.DAT   (deleted)
    while IFS=$'\t' read -r meta path; do
        [[ "$meta" == r/r* ]] || continue
        deleted=0
        [[ "$meta" == *"*"* ]] && deleted=1
        [ "$deleted" -eq 1 ] && [ "$ALL" -eq 0 ] && continue
        echo "$path" | grep -qiE "$pattern" || continue
        addr="$(echo "$meta" | sed -E 's/^r\/r (\* )?//; s/\(realloc\)//; s/:$//')"
        dest="$OUT/p$off/$path"
        [ "$deleted" -eq 1 ] && dest="$dest.deleted-$addr"
        mkdir -p "$(dirname "$dest")"
        if icat -o "$off" "$IMAGE" "$addr" > "$dest" 2>/dev/null; then
            size=$(stat -c %s "$dest")
            hash=$(sha256sum "$dest" | awk '{print $1}')
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$hash" "$size" "$off" "$addr" "$deleted" "$path" "${dest#"$OUT"/}" >> "$MANIFEST"
            echo "   $path ($size bytes)"
            count=$((count + 1))
        else
            echo "   ! failed to extract $path ($addr)" >&2
            rm -f "$dest"
        fi
    done < <(fls -r -p -o "$off" "$IMAGE" 2>/dev/null || true)
done

echo "Extracted $count file(s) to $OUT (manifest: $MANIFEST)"
[ "$count" -gt 0 ] && echo "Next: greybags analyze -f markdown -o report.md $OUT"
