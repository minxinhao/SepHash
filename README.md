# SepHash: A Write-Optimized Hash Index On Disaggregated Memory via Separate Segment Structure

SepHash is a write-optimized hash index designed for emerging disaggregated memory. SepHash uses several techniques to optimize write operations and index expansion on disaggregated memory while maintaining balanced read performance. SepHash proposes a two-level separate segment structure that significantly reduces the bandwidth consumption during resizing. SepHash reduces latency on each write operation using append writes and coroutine. With optimized filter and cache structures, SepHash maintains good read performance.

## Feature Highlights

- Write performance much higher than RACE under write intensive load, 3.3x for write only workload.
- Read performance close to RCE, much better than other leveling hash indexes ported to disaggregated memory.
- High space utilization with very low metadata overhead.
- Good scalability with number of clients and servers.

## Usage

- Arbitrary length key and value organized as a Slice.
- Provides high-performance single-point insert, search, delete, and update operations.
- Conveniently extends the number of servers and clients

## Building

### Prepare and build dependencies

- g++-11
- C++20
- MLNX_OFED higher than 5.0
- pip install fabric

### Build

- Configuring server/ip information:
    - Edit the list of client-nodes in run.py and sync.sh.
    - set server's ip in ser_cli.sh.
- Generate executable and copy to all client nodes.

```bash
$ mkdir build 
$ cd build
$ cmake ..
$ make ser_cli
$ ../sync.sh out #client-nodes
```

- run servers

```bash
$ ../ser_cli.sh server
```

- run clients

```bash
$ python3 ../run.py #client-nodes client #client-per-node #coroutine-per-client
```

- Collecting data

```bash
$ ../sync.sh in #client-nodes
```

## WorkLoads and comparison objects

### Workloads

Modify the parameters in ser_cli.sh to apply different workloads. 
- load_num: amount of pre-loaded data.
- num_op: amount of operations during run phase.
- XXX_frac: ratios of corresponding operations in the run phase, need to sum to 1.0.
- pattern_type: different distributions of keys. 0 represents sequential workloads, 1 represents uniformly workloads, 2 represents zipfian workloads, and 3 represents lastest workloads.

### Comparison
Modify the called executable in ser_cli.sh to replace different comparison objects.
- ser_cli.cc : fixed length KV test
- ser_cli_var_kv.cc : variable length KV test
- Change the ClientType and ServerType in ser_cli.cc and ser_cli_var_kv.cc to switch between different comparison objects.