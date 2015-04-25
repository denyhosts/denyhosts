VERSION?=3.0

clean:
	rm -rf build
	rm -rf DenyHosts/*.pyc

tarball: clean
	cd .. && tar czf denyhosts-$(VERSION).tar.gz denyhosts --exclude=.git

