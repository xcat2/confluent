
PKGNAME=confluent_xcat
VERNUM=`cat VERSION`

all: clean prepare confluent_xcat 

prepare: 
	@echo [${PKGNAME}] preparing...
	mkdir -p rpmbuild/BUILD
	mkdir -p rpmbuild/BUILDROOT
	mkdir -p rpmbuild/RPMS
	mkdir -p rpmbuild/SOURCES
	mkdir -p rpmbuild/SPECS
	mkdir -p rpmbuild/SRPMS


confluent_xcat: 
	@echo [${PKGNAME}] building...
	sed -e "s/#VERSION#/${VERNUM}/" setup.py.tmpl > setup.py
	python setup.py sdist > /dev/null 2>&1
	cp dist/*.tar.gz rpmbuild/SOURCES
	sed -e "s/#VERSION#/${VERNUM}/" ${PKGNAME}.spec.tmpl > rpmbuild/SPECS/${PKGNAME}.spec
	rpmbuild -ba rpmbuild/SPECS/${PKGNAME}.spec 

clean: 
	@echo [${PKGNAME}] cleaning...
	rm -rf rpmbuild
	rm -f setup.py
	rm -rf ${PKGNAME}.egg-info
	rm -rf dist

	
