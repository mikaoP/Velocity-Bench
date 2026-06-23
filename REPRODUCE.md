# Reproducing the single-CPU pocl-vs-Intel Velocity-Bench comparison

This fork of [Velocity-Bench](https://github.com/oneapi-src/Velocity-Bench) carries the
source/config changes used to run a **single-core (1 CPU) comparison of the pocl OpenCL
runtime against the Intel oneAPI (icpx/libintelocl) runtime** across the SYCL benchmarks.

This document explains what is in the repo, what is **not** (and how to get it), and the
exact per-benchmark configuration so results can be reproduced on another machine.

---

## 1. What this repo contains

* The benchmark **source/config edits** (CMakeLists, kernel/correctness fixes, build
  makefiles, probe-tuned input files). See the git history and the table in §4.
* Small **probe input files** committed directly:
  * `bitcracker/hash_pass/user_passwords_{300,500,750,1500,3000}.txt`
  * `SeisAcoMod2D/input/sigsbee2a_3201x1201z_probe.json`
  * `QuickSilver/Examples/CORAL2_Benchmark/Problem1/Coral2_P1_1_probe.inp`

## 2. What this repo does NOT contain (out of scope by design)

These pieces are required to actually build/run the comparison but live **outside** this
repository:

1. **The patched pocl build.** The comparison uses a custom pocl branch
   (`svml-veclib-clean`: SVML/libmvec veclib swap, `UniformizeDivergentExits` fix,
   `FuseVectorSincos` pass, etc.). Build it separately and expose it as an OpenCL ICD.
2. **The run orchestration** (`runall.sh`, `env.sh`, `plot.py`, the ICD selector, probe
   timing harness). These calibrate each bench to ~60 s on one core, pin with
   `numactl --physcpubind=0`, and apply per-bench lenient exit-code handling.
3. **The Intel oneAPI HPC Toolkit** (`icpx`, `libintelocl`, oneMKL/oneDNN/TBB/MPI). This
   is proprietary and must be installed separately; it is **not** reproducible via the nix
   toolchain. Point the build env at your own install.
4. **Large datasets** — see §3.

## 3. Datasets to provision (excluded from git)

None of the following are versioned (see `.gitignore`). Download each and place it at the
indicated path before running the corresponding benchmark.

| Benchmark | Place at | Approx size | How to obtain |
|---|---|---:|---|
| dl-cifar | `dl-cifar/datasets/cifar-10-batches-bin/` | ~339 MB | CIFAR-10 **binary** version from <https://www.cs.toronto.edu/~kriz/cifar.html>; unzip into this dir (`data_batch_1..5.bin`, `test_batch.bin`). |
| dl-mnist | `dl-mnist/datasets/` | ~53 MB | MNIST idx files from <http://yann.lecun.com/exdb/mnist/>: `t10k-images.idx3-ubyte`, `t10k-labels.idx1-ubyte`, `train-images.idx3-ubyte(.dat)`, `train-labels.idx1-ubyte`. |
| easywave | `easywave/data/` | ~134 MB | Grids + faults from <https://git.gfz-potsdam.de/id2/geoperil/easyWave/-/tree/master/data>. |
| reverse_time_migration | `reverse_time_migration/data/` | ~2.0 GB | Run `reverse_time_migration/prerequisites/data-download/download_bp_data_iso.sh` (BP model `.segy`). A minimal variant exists: `download_bp_data_iso_minimal.sh`. |
| SeisAcoMod2D | `SeisAcoMod2D/data/` | ~221 MB | The four `*.bin` velocity/density models from <https://github.com/richaras/SeisAcoMod2D/tree/master/data> (`sigsbee2a_cp.bin`, `sigsbee2a_den.bin`, `twolayer_model_cp.bin`, `twolayer_model_den.bin`). |
| lc0 | `lc0/networks/maia-1100.pb.gz` | ~1.3 MB | Maia Chess network `maia-1100` (Maia Chess project / lczero.org networks). |
| svm | `svm/SYCL/build/a9a_big` | ~3 MB | `a9a` from the LIBSVM datasets, concatenated ×30: `for i in $(seq 30); do cat a9a; done > a9a_big`. |
| voxelizer | (none) | — | Input `bunny.OBJ` is already tracked; the `*.binvox` files are generated outputs. |

Generated outputs (`reverse_time_migration/results/`, `SeisAcoMod2D/output/`, `*.binvox`)
are recreated by the runs and are intentionally ignored.

## 4. Per-benchmark probe-tuned configuration

Calibrated so each bench runs ~60 s on a single core. Where the config lives under an
ignored `bin/`/`build/` path it is listed here explicitly (not committed).

| Bench | Knob | Where |
|---|---|---|
| bitcracker | `user_passwords_300.txt` (300 of 60000) | committed input |
| hashtable | `kHashTableCapacity = 64*1024*1024` (was 256M) | `hashtable/SYCL/src/linearprobing.h` (committed) |
| QuickSilver | `nx=ny=nz=lx=ly=lz=8`, `nParticles=20480`, `nSteps=30` | `Coral2_P1_1_probe.inp` (committed) |
| sobel_filter | `-n 2300` | runtime CLI |
| tsne | `-n 70` | runtime CLI |
| voxelizer | `-i 130` | runtime CLI |
| svm | `a9a_big` = `a9a` ×30 | dataset, see §3 |
| reverse_time_migration | stencil-order **16** (canonical), window left 220 / right 150 | `workloads/bp_model/computation_parameters.json` (committed). **Keep order 16**; tune runtime via the window only. |
| dl-cifar | `iterations = 1` (upstream) | `common/vit/vit.h`, `common/cait/cait.h` (committed) |
| SeisAcoMod2D | `Time = 0.4` | `input/sigsbee2a_3201x1201z_probe.json` (committed) |
| hpl | `P = Q = 1`, `N = 12500` | `hplinpack/dpcpp/hpl-2.3/bin/intel64/HPL.dat` (ignored path — set manually) |

## 5. Notes

* lc0 on pocl is excluded from the comparison (produces garbage / crashes; Intel-only).
  The `winograd_helper.h` SE-FC1 loop-bound fix here is real but the run is still unstable
  on pocl. See the project notes.
* svm/hpl/dl-cifar can be built against either oneMKL (Intel) or oneMath generic_blas;
  the oneMath variant is what lets pocl run those benches. The BLAS backend choice is a
  build-time decision made outside this repo.
* For warm timings, the SYCL JIT cache must be persistent
  (`SYCL_CACHE_PERSISTENT=1` + `SYCL_CACHE_DIR`), otherwise every run re-JITs SPIR-V.
