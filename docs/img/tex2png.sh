#!/bin/sh

# Convert tex to pdf
pdflatex $1.tex

# Use ImageMagic's convert to get png. 
# density determines the resolution and size.
# flatten ensures white background
convert -flatten -trim -density 150 -quality 100 $1.pdf $1.png

