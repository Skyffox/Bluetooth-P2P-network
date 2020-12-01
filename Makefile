setup:
	bash -c '\
	bash setup.sh && \
	source ./venv/bin/activate && \
	python -m pip install -r requirements.txt && \
	deactivate'

run:
	$(test_existence) \
	bash -c '\
	source venv/bin/activate && \
	bash bluetooth_visibility.sh && \
	python run.py $(MON) $(ARG) && \
	deactivate'

run-simulation:
	$(test_existence) \
	bash -c '\
	source venv/bin/activate && \
	python run.py $(MON) $(ARG) $(SIM) && \
	deactivate'

run-gui-simulation:
	bash -c '\
	source venv/bin/activate && \
	python ./src/simulator/graph_gui.py $(MON) $(ARG) && \
	deactivate'
