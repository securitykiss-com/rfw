#!/bin/sh

# Convert tex to pdf
pdflatex $1.tex

# Use ImageMagic's convert to get png. 
# density determines the resolution and size.
# flatten ensures white background
convert -flatten -density 150 -quality 100 $1.pdf $1_page.png

# trim margins
convert $1_page.png -trim $1_trim.png

convert $1_trim.png -bordercolor white -border 40 $1.png


