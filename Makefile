all: knocker backdoor
	@chmod +x knocker
	@chmod +x backdoor

clean: knocker backdoor
	@chmod -x backdoor
	@chmod -x knocker