#!/bin/sh

# Convert tex to pdf
pdflatex $1.tex

# The resulting svg is converted correctly but text looks bad in svg
# inkscape -l rfw_example_1.svg rfw_example_1.pdf

# Much better results also for text
pdf2svg $1.pdf $1.svg

# The problem is that svg is not fully supported by browsers
# The example generated for rfw displays in firefox but does not display in chrome (it saves the file instead)


