default: all

lint:
	tflint -c .tflint.hcl

docs:
	terraform-docs markdown table --output-file README.md --output-mode inject .

all: lint docs
