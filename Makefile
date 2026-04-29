TARGETS    ?= targets.txt
OUTPUT     ?= run.json
ARGS       ?= -f 1 -m 15

ifeq ($(OS),Windows_NT)
    PYTHON ?= python
    SUDO   :=
    RM     := del /f /q
else
    PYTHON ?= python3
    SUDO   := sudo
    RM     := rm -f
endif

## Default target — run the analyzer (requires elevated privileges for raw sockets)
run:
	$(SUDO) $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) $(ARGS)

## Run with verbose logging
run-verbose:
	$(SUDO) $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) -v $(ARGS)

## Run and open the topology visualizer when done
run-open:
	$(SUDO) $(PYTHON) traceroute_main.py $(TARGETS) -o $(OUTPUT) --open $(ARGS)

## Remove output files
clean:
	-$(RM) run.json traceroute_*.json out.json out.csv

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
	@echo ""
ifeq ($(OS),Windows_NT)
	@echo "Note: Run this shell as Administrator for raw socket access."
else
	@echo "Note: sudo is used automatically for raw socket access."
endif
