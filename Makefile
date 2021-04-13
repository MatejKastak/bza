AUTHOR=xkasta02

.PHONY: watch doc prez

all: doc prez

watch: show
	fd -e bib -e md -e png | entr make doc

show: doc
	zathura $(AUTHOR).pdf &

doc:
	pandoc --bibliography bibligraphy.bib --csl template/ieee.csl --citeproc -V "geometry:top=2.5cm, bottom=2.5cm, left=3.5cm, right=3.5cm" -N project.md -o $(AUTHOR).pdf

pack:
	zip $(AUTHOR).zip $(AUTHOR).pdf README.md dec/src/main.rs dec/Cargo.toml

clean:
	rm $(AUTHOR).pdf
	rm $(AUTHOR).zip

normo:
	@wc -w project.md
