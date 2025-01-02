#!/bin/bash

# Create necessary directories
mkdir -p SysDaemonAI.iconset

# Convert SVG to PNG at different sizes
for size in 16 32 64 128 256 512; do
    sips -z $size $size resources/icon.svg --out SysDaemonAI.iconset/icon_${size}x${size}.png
    if [ $size -le 256 ]; then
        sips -z $((size*2)) $((size*2)) resources/icon.svg --out SysDaemonAI.iconset/icon_${size}x${size}@2x.png
    fi
done

# Create icns file
iconutil -c icns SysDaemonAI.iconset

# Clean up
rm -rf SysDaemonAI.iconset
