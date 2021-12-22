VERSION?=3.1

clean:
	git clean -fdx

tarball: clean
	cd .. && tar czf denyhosts-$(VERSION).tar.gz denyhosts --exclude=.git

