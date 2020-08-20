OUTPUT_DIR=.build
SOURCE_DIRS=arango arango-plugin
SHELL := '/bin/bash'

build: clean
	go build -o ${OUTPUT_DIR}/arango-plugin ./arango-plugin

.PHONY: clean
clean:
	@: if [ -f ${OUTPUT_DIR} ] then rm -rf ${OUTPUT_DIR} fi

.PHONY: sa
sa:

.PHONY: test
test: