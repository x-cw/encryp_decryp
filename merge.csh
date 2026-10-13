#!/usr/bin/csh

set out = "all_files.txt"
rm -f "$out"

foreach f ( $argv )
    if ( -f "$f" && "$f" != "$out" ) then
        echo "========================================" >> "$out"
        echo "merged_file:$f" >> "$out"
        echo "========================================" >> "$out"
        cat "$f" >> "$out"
        echo "" >> "$out"
        echo "" >> "$out"
    endif
end
echo "finish : $out"
