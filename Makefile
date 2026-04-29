PYTHON     ?= python3
TARGETS    ?= targets.txt
OUTPUT     ?= run.json
ARGS       ?= -f 1 -m 30 -q 1 -w 0.05 -s 60

## Default target — run the analyzer (requires root for raw sockets)
run:
	sudo $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) $(ARGS)

## Run with verbose logging
run-verbose:
	sudo $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) -v $(ARGS)

## Run and open the topology visualizer when done
run-open:
	sudo $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) --open $(ARGS)

## Remove output files
clean:
	rm -f run.json traceroute_*.json out.json out.csv

help:
	@echo "Targets:"
	@echo "  make run           Run the analyzer (default)"
	@echo "  make run-verbose   Run with verbose logging"
	@echo "  make run-open      Run and open topology in browser"
	@echo "  make clean         Remove generated output files"
	@echo ""
	@echo "Overrides (e.g.  make run TARGETS=my_ips.txt OUTPUT=result.json):"
	@echo "  TARGETS   Input file  (default: targets.txt)"
	@echo "  OUTPUT    Output file (default: run.json)"
	@echo "  ARGS      Extra flags (e.g. ARGS='-q 2 -m 20')"
