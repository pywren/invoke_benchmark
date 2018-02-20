# benchmarking invocation performance

usage: ./invoker_socket_clean.py num_connections num_threads

## Results from a EC2 node

python invoker_socket_clean.py 5000 1
num connections: 5000 threads: 1
connection: 26.853372097
sent: 0.0873599052429
recv: 11.457463026

python invoker_socket_clean.py 5000 10
num connections: 5000 threads: 10
connection: 4.61677002907
sent: 0.133472919464
recv: 10.0993602276