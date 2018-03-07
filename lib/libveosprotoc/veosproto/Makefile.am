veosproto_PYTHON = __init__.py ived_pb2.py
veosprotodir = $(pythondir)/veosproto

CLEANFILES = ived_pb2.py

ived_pb2.py: ../ived.proto Makefile
	cd ..; protoc --python_out=veosproto ived.proto
