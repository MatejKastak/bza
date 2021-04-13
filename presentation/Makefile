# usage: make filename.pdf
%.pdf: %.tex
	pdflatex $<
	pdflatex $<
AUTHOR=xkasta02

.PHONY: watch doc prez

all: doc prez

watch: show
	fd -e tex -e png | entr make doc

show: doc
	zathura presentation.pdf &

doc:
	# pandoc --bibliography bibligraphy.bib --csl template/ieee.csl --citeproc -V "geometry:top=2.5cm, bottom=2.5cm, left=3.5cm, right=3.5cm" -N project.md -o $(AUTHOR).pdf
	pdflatex presentation.tex
	pdflatex presentation.tex

normo:
	@wc -w project.md
