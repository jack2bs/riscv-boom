// Oracle branch predictor: runahead cosimulation.
//
// A private Spike (riscv-isa-sim, linked into every Chipyard Verilator build
// via -lriscv) executes the SAME ELF ($ORACLE_ELF) ahead of the RTL's commit
// point. Every control-flow instruction (CFI) it executes becomes one record
// (pc, direction, target) in a FIFO ordered by program order. Because the
// correct path is fetched in program order, a prediction is answered by
// POSITION in that stream, not by looking up the pc:
//
//   - the frontend tap (oracle_tap.v, wired in frontend.scala) publishes each
//     fetch packet's address one cycle before its slots query the predictor,
//     the FTQ enqueue stream, every CPU redirect, and s1 kills;
//   - a cursor serves fetch: a packet that continues the path of the previous
//     packet takes the next records in order; a re-fetch of a packet still
//     in flight is answered from the records already handed out; a
//     wrong-path fetch matches nothing and changes nothing;
//   - each FTQ enqueue attaches the records it covers to the entry, and a
//     redirect to entry k recomputes the serve position from that entry;
//   - commit updates (direction stream for conditionals, target stream for
//     unconditionals) mark records committed and prune the FIFO, verifying
//     the runahead against the machine.
//
// Divergence policy: the cosim runs with its own CSRs/HTIF, so once the
// program passes the measurement ROI and prints (digit loops keyed on mcycle
// values) or spins on fromhost, the streams may split. On the first
// unexplainable commit the model DESYNCS permanently: predictions answer
// unknown and commits are counted, not verified. d3_desync_pc in the stats
// says where; it must lie outside the ROI.
//
// When the runahead reaches the program's exit call it stops growing; the
// records already in the FIFO (up to 512 CFIs ahead of the machine) are still
// served through the normal packet path, and only then do slots get "no
// claim". Frontend geometry (bank count, bank/fetch/line bytes, FTQ size)
// comes from the tap blackbox's parameters, so one model serves every BOOM
// size.
//
// Quality metric: d3_unserved — correct-path records the machine enqueued
// that the model had not served. Each one is a guaranteed default
// prediction. It is 0 inside the ROI on every embench benchmark.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <riscv/cfg.h>
#include <riscv/processor.h>
#include <riscv/simif.h>
#include <fesvr/elfloader.h>
#include <fesvr/memif.h>

typedef unsigned long long ull;

// Printed in ORACLE_STATS (ver=) so every result log identifies the model
// that produced it. Bump on any behavioral change.
#define ORACLE_VERSION "7.1"

// ---------------------------------------------------------------------------
// Flat memory + minimal simif/memif for Spike
// ---------------------------------------------------------------------------

static const reg_t MEM_BASE = 0x80000000ull;
static const size_t MEM_SIZE = 1ull << 30;  // 1 GiB, MAP_NORESERVE-sparse
static char *cosim_mem = nullptr;

class oracle_simif_t : public simif_t
{
public:
  char *addr_to_mem(reg_t addr) override {
    if (addr >= MEM_BASE && addr < MEM_BASE + MEM_SIZE)
      return cosim_mem + (addr - MEM_BASE);
    return nullptr;
  }
  bool reservable(reg_t addr) override { return addr_to_mem(addr) != nullptr; }
  bool mmio_fetch(reg_t, size_t, uint8_t *) override { return false; }
  bool mmio_load(reg_t, size_t, uint8_t *) override { return false; }
  bool mmio_store(reg_t, size_t, const uint8_t *) override { return false; }
  void proc_reset(unsigned) override {}
  const char *get_symbol(uint64_t) override { return nullptr; }
  const cfg_t &get_cfg() const override { return cfg; }
  const std::map<size_t, processor_t *> &get_harts() const override {
    return harts;
  }
  cfg_t cfg;
  std::map<size_t, processor_t *> harts;
};

class flat_memif_t : public chunked_memif_t
{
public:
  void read_chunk(addr_t taddr, size_t len, void *dst) override {
    memcpy(dst, cosim_mem + (taddr - MEM_BASE), len);
  }
  void write_chunk(addr_t taddr, size_t len, const void *src) override {
    if (taddr >= MEM_BASE && taddr + len <= MEM_BASE + MEM_SIZE)
      memcpy(cosim_mem + (taddr - MEM_BASE), src, len);
  }
  size_t chunk_align() override { return 1; }
  size_t chunk_max_size() override { return 4096; }
  void clear_chunk(addr_t taddr, size_t len) override {
    if (taddr >= MEM_BASE && taddr + len <= MEM_BASE + MEM_SIZE)
      memset(cosim_mem + (taddr - MEM_BASE), 0, len);
  }
};

// ---------------------------------------------------------------------------
// CFI decode (RV64GC)
// ---------------------------------------------------------------------------

struct CfiInfo { bool is_cfi, cond, indirect; };

static CfiInfo cosim_cfi(uint32_t insn)
{
  if ((insn & 3) == 3) {
    uint32_t op = insn & 0x7F;
    if (op == 0x63) return {true, true, false};          // Bxx
    if (op == 0x6F) return {true, false, false};         // jal
    if (op == 0x67) return {true, false, true};          // jalr
    return {false, false, false};
  }
  uint32_t q = insn & 3, f3 = (insn >> 13) & 7;
  if (q == 1) {
    if (f3 == 5) return {true, false, false};            // c.j
    if (f3 == 6 || f3 == 7) return {true, true, false};  // c.beqz / c.bnez
    return {false, false, false};
  }
  if (q == 2 && f3 == 4) {
    uint32_t rs1 = (insn >> 7) & 0x1F, rs2 = (insn >> 2) & 0x1F;
    if (rs2 == 0 && rs1 != 0) return {true, false, true};  // c.jr / c.jalr
  }
  return {false, false, false};
}

// ---------------------------------------------------------------------------
// Records and the event log
// ---------------------------------------------------------------------------

struct Rec {
  ull pc;
  ull target;      // next pc when taken (uncond: always)
  bool cond;
  bool indirect;   // jalr / c.jr / c.jalr: the target is data-dependent
  bool taken;
  bool committed;
  bool resolved;   // execute-time resolution seen (mispredict update)
  bool served;     // handed to a fetch on the current path
  ull seq;         // absolute position in the correct-path CFI stream
};

// Event log for offline replay/debugging (ORACLE_COSIM_LOG=<path>):
//   R seq pc cond taken target ind    record created by the runahead
//   Q cycle pc                        direction-predictor slot query
//   P cycle pc n=<recs> [refetch] exit=<pc> flag=<s2 replay flag>
//                                     packet built at the cycle's first query
//   S cycle pc verdict [seq] c=<pos>  serve decision (hit / wrong)
//   U cycle pc taken kind [verdict]   direction update and how it matched
//   T cycle pc target verdict [seq]   target update and how it matched
//   F cycle pc idx start after cfi=<v>/<idx> unserved=<n> ahead=<n>
//                                     FTQ enqueue and the records attached
//   X cycle idx npc pos               redirect and the recomputed position
//   K cycle rewind <seq> | pending    s1 kill
//   DESYNC ...                        permanent desync with the window dump
static FILE *cosim_logf()
{
  static FILE *f = nullptr;
  static bool tried = false;
  if (!tried) {
    tried = true;
    const char *p = getenv("ORACLE_COSIM_LOG");
    if (p && *p) f = fopen(p, "w");
  }
  return f;
}
#define CLOG(...) do { if (FILE *_lf = cosim_logf()) \
                         fprintf(_lf, __VA_ARGS__); } while (0)

// The harness reports a bank-straddling CFI's pc as true_pc + 2 (a 32-bit
// instruction starting at the last halfword of a bank: the frontend's
// edge_inst). Records are KEYED by this harness-visible pc and matched
// exactly. Defined after the geometry state below.
static inline ull cosim_visible_pc(ull pc, unsigned len);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static processor_t *cosim_proc = nullptr;
static oracle_simif_t *cosim_simif = nullptr;
static bool cosim_desynced = false;
static bool cosim_synced = false;     // first commit matched a record
static bool cosim_halted = false;     // guest wrote tohost exit
static ull cosim_tohost = 0, cosim_fromhost = 0;  // guest-phys addresses

// The record window: oldest uncommitted record .. runahead frontier.
static std::deque<Rec> cosim_fifo;
static size_t cosim_cursor = 0;       // serve position, index INTO cosim_fifo
static const size_t LOOKAHEAD = 512;  // records kept ahead of the cursor
static const size_t STEP_CAP = 200000;  // instructions per runahead burst

// Frontend geometry, from the tap blackbox's Verilog parameters (set once by
// oracle_init_geometry before any query). Defaults are MegaBoomV3; Small and
// Medium have one 8-byte bank per fetch, Large/Mega two.
static ull g_nbanks = 2, g_bank_bytes = 8, g_fetch_bytes = 16;
static ull g_block_bytes = 64, g_ftq_entries = 40;
static bool g_geom_set = false;

// A fetch packet starting at pc covers [pc, packet_end(pc)): the bank that
// holds pc plus, on a two-bank frontend, the next bank — unless pc is in the
// last bank of a cache line (BOOM's mayNotBeDualBanked: no wrap into the
// next line). Mirrors nextFetch/fetchMask in frontend.scala.
static inline ull bank_align(ull pc) { return pc & ~(g_bank_bytes - 1); }
static inline bool last_bank_in_block(ull pc)
{
  return g_nbanks == 2 &&
         ((pc % g_block_bytes) / g_bank_bytes) == (g_block_bytes / g_bank_bytes - 1);
}
static inline ull packet_end(ull pc)
{
  ull base = bank_align(pc);
  return base + ((g_nbanks == 2 && !last_bank_in_block(pc)) ? g_fetch_bytes
                                                            : g_bank_bytes);
}
static inline ull cosim_visible_pc(ull pc, unsigned len)
{
  return (len == 4 && (pc & (g_bank_bytes - 1)) == g_bank_bytes - 2) ? pc + 2 : pc;
}

// Every conditional-branch pc the runahead has executed: off-path fetches of
// a known branch must still be flagged is_br, or the frontend's global
// history bookkeeping pays a repair flush.
static std::unordered_set<ull> cosim_cond_pcs;

// Per-cycle serve memo. The direction and target harnesses of one slot, and
// the ~16 harness instances of one packet, call in arbitrary order within a
// cycle; every query of a (cycle, pc) gets the same answer.
static ull memo_cycle = ~0ull;
static std::unordered_map<ull, Rec> memo_hits;   // pc -> served record
static std::unordered_set<ull> memo_misses;      // pcs answered "no claim"
static Rec memo_rec;

// FTQ anchoring. Each enqueued bundle is attached to the run of records it
// covers; a redirect to entry k recomputes the serve position from that
// attachment. cosim_pos is one past the newest enqueued bundle's records.
struct FtqEnt { ull start_seq, after_seq, pc; bool used; };
static std::vector<FtqEnt> cosim_ftq(64);   // resized by oracle_init_geometry
static ull cosim_pos = 0;
static ull tap_last_cycle = ~0ull;  // one delivery per cycle
static bool tap_bootstrapped = false;

// Packet context. The tap publishes each fetch pc one cycle before that
// packet's slots query the predictor. The 16 harness DPI calls and the tap
// call of one cycle run in arbitrary order, so the pc for cycle c+1
// (published at c) is kept in a small cycle-keyed window, not a single slot.
static std::unordered_map<ull, ull> fetch_pc_at;  // cycle -> fetch pc
static std::unordered_set<ull> fetch_replay_at;   // cycles flagged s2 re-fetch
static ull pkt_cycle = ~0ull, pkt_pc = 0;
static bool pkt_built = false;
static std::unordered_map<ull, ull> pkt_recs;  // pc -> seq for this packet

// Path continuity: a fetch is a NEW in-order packet only if its pc continues
// the path of the previous in-order packet (that packet's taken target, its
// fall-through end, or a redirect target).
static ull last_exit = ~0ull;

// In-flight depth: packets served in order but not yet enqueued. Fetch runs
// at most s1..f4 (4 packets) ahead of the FTQ; one more is margin for an
// enqueue delayed by f4_delay. A further in-order-looking fetch must be a
// stall re-fetch.
struct InFlight { ull end_seq, cycle, pre_cursor_seq, pre_exit; };
static std::deque<InFlight> inflight;
static const size_t INFLIGHT_MAX = 5;

// f1_clear with a valid s1: the packet queried THIS cycle is killed and will
// be fetched again, so its records must be given back.
static ull kill_s1_at = ~0ull;

// Commit-side memories for phantom recognition (see cosim_update_*).
static std::unordered_map<ull, ull> recent_commit;  // pc -> commit cycle
// Recently committed taken conditionals (pc -> target, cycle): their target
// update arrives with the direction commit, but same-cycle updates from
// different packets interleave, so the record may already be pruned.
static std::unordered_map<ull, std::pair<ull, ull>> recent_cond;

// Statistics.
static ull c_d_pred = 0, c_d_upd = 0, c_t_pred = 0, c_t_upd = 0;
static ull c_post_desync = 0, c_wrongpath = 0, c_steps = 0, c_presync_drop = 0;
static ull c_syscalls = 0, c_skew = 0, c_phantom = 0, c_tgt_bogus = 0;
static ull c_u_misp = 0, c_u_repair = 0;
static ull c_desync_pc = 0;
static std::unordered_map<ull, ull> c_misp_by_pc;
static ull c_tap_enq = 0, c_tap_red = 0, c_tap_lag = 0, c_tap_orphan = 0;
static ull c_unserved = 0, c_ahead8 = 0, c_ahead_max = 0;
static ull c_pkt = 0, c_pkt_replay = 0, c_pkt_empty = 0, c_pkt_nofetch = 0;
static ull c_pkt_forced = 0, c_pkt_depth = 0, c_pkt_flagged = 0, c_kill = 0;

static void recent_cond_note(ull pc, ull target, ull cycle)
{
  recent_cond[pc] = {target, cycle};
  if (recent_cond.size() > 64) {
    for (auto it = recent_cond.begin(); it != recent_cond.end();)
      it = (cycle - it->second.second > 16) ? recent_cond.erase(it) : ++it;
  }
}

static void cosim_print_stats()
{
  if (FILE *f = cosim_logf()) fflush(f);
  printf("ORACLE_STATS ver=" ORACLE_VERSION " d_pred=%llu d_upd=%llu "
         "t_pred=%llu t_upd=%llu "
         "d3_desync=%d d3_desync_pc=%llx d3_post_desync=%llu "
         "d3_wrongpath=%llu d3_steps=%llu d3_presync=%llu d3_window=%zu "
         "d3_syscalls=%llu d3_skew=%llu d3_phantom=%llu d3_tgt_bogus=%llu "
         "d3_tap_enq=%llu d3_tap_red=%llu d3_tap_lag=%llu d3_tap_orphan=%llu "
         "d3_unserved=%llu d3_pkt=%llu d3_pkt_replay=%llu d3_pkt_empty=%llu "
         "d3_pkt_nofetch=%llu d3_pkt_forced=%llu d3_pkt_depth=%llu "
         "d3_pkt_flagged=%llu d3_kill=%llu d3_ahead8=%llu d3_ahead_max=%llu "
         "u_misp=%llu u_repair=%llu\n",
         c_d_pred, c_d_upd, c_t_pred, c_t_upd,
         cosim_desynced ? 1 : 0, c_desync_pc, c_post_desync,
         c_wrongpath, c_steps, c_presync_drop, cosim_fifo.size(),
         c_syscalls, c_skew, c_phantom, c_tgt_bogus,
         c_tap_enq, c_tap_red, c_tap_lag, c_tap_orphan,
         c_unserved, c_pkt, c_pkt_replay, c_pkt_empty,
         c_pkt_nofetch, c_pkt_forced, c_pkt_depth,
         c_pkt_flagged, c_kill, c_ahead8, c_ahead_max,
         c_u_misp, c_u_repair);
  printf("ORACLE_GEOM nbanks=%llu bank_bytes=%llu fetch_bytes=%llu "
         "block_bytes=%llu ftq=%llu set=%d\n", g_nbanks, g_bank_bytes,
         g_fetch_bytes, g_block_bytes, g_ftq_entries, g_geom_set ? 1 : 0);
  // Per-pc mispredict blame, complete: which branches the machine resolved
  // as mispredicted (fanned out per FTQ entry, see oracle_predictor.scala).
  std::vector<std::pair<ull, ull>> blame;  // (count, pc)
  for (auto &kv : c_misp_by_pc) blame.push_back({kv.second, kv.first});
  if (!blame.empty()) {
    std::sort(blame.rbegin(), blame.rend());
    printf("ORACLE_TOP_MISP");
    for (auto &b : blame) printf(" %llx:%llu", b.second, b.first);
    printf("\n");
  }
  fflush(stdout);
}

// ---------------------------------------------------------------------------
// Init + runahead
// ---------------------------------------------------------------------------

// From the tap blackbox's initial block (Verilog parameters of the frontend
// that instantiates it). Must run before the first query; the harnesses'
// initial blocks only call cosim_init_once, which does not need geometry.
extern "C" void oracle_init_geometry(ull nbanks, ull bank_bytes,
                                     ull fetch_bytes, ull block_bytes,
                                     ull ftq_entries)
{
  g_nbanks = nbanks; g_bank_bytes = bank_bytes; g_fetch_bytes = fetch_bytes;
  g_block_bytes = block_bytes; g_ftq_entries = ftq_entries;
  cosim_ftq.assign(ftq_entries, FtqEnt{});
  g_geom_set = true;
  CLOG("G nbanks=%llu bank_bytes=%llu fetch_bytes=%llu block_bytes=%llu "
       "ftq=%llu\n", nbanks, bank_bytes, fetch_bytes, block_bytes, ftq_entries);
}

void cosim_init_once()
{
  static bool done = false;
  if (done) return;
  done = true;

  const char *elf = getenv("ORACLE_ELF");
  if (!elf || !elf[0]) {
    fprintf(stderr, "ORACLE: ORACLE_ELF environment variable not set\n");
    exit(1);
  }
  cosim_mem = (char *)mmap(nullptr, MEM_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (cosim_mem == MAP_FAILED) {
    fprintf(stderr, "ORACLE: mmap of cosim memory failed\n");
    exit(1);
  }
  cosim_simif = new oracle_simif_t();
  cosim_simif->cfg.priv = "MSU";
  cosim_simif->cfg.misaligned = false;
  cosim_simif->cfg.pmpregions = 0;
  cosim_simif->cfg.hartids = {0};

  flat_memif_t chunks;
  memif_t memif(&chunks);
  reg_t entry = 0;
  std::map<std::string, uint64_t> syms = load_elf(elf, &memif, &entry, 0);
  if (syms.count("tohost")) cosim_tohost = syms["tohost"];
  if (syms.count("fromhost")) cosim_fromhost = syms["fromhost"];

  cosim_proc = new processor_t("rv64gc", "MSU", &cosim_simif->cfg,
                               cosim_simif, 0, false, nullptr, std::cerr);
  cosim_simif->harts[0] = cosim_proc;
  cosim_proc->reset();
  cosim_proc->get_state()->pc = entry;

  atexit(cosim_print_stats);
}

static ull cosim_ld64(ull addr)
{
  ull v = 0;
  memcpy(&v, cosim_mem + (addr - MEM_BASE), 8);
  return v;
}

static void cosim_st64(ull addr, ull v)
{
  memcpy(cosim_mem + (addr - MEM_BASE), &v, 8);
}

// riscv-newlib `struct stat` layout, as fesvr's sys_fstat fills it.
struct riscv_stat {
  uint64_t dev; uint64_t ino; uint32_t mode; uint32_t nlink;
  uint32_t uid; uint32_t gid; uint64_t rdev; uint64_t __pad1;
  int64_t size; int32_t blksize; int32_t __pad2; int64_t blocks;
  int64_t atime; int64_t __pad3; int64_t mtime; int64_t __pad4;
  int64_t ctime; int64_t __pad5; int32_t __unused4; int32_t __unused5;
};

// Minimal in-process HTIF host mirroring fesvr's magic-mem syscall proxy.
// Return values come from REAL host syscalls in this very process (same
// stdout fd the RTL's fesvr proxies to), so guest control flow that depends
// on them (printf buffering setup after fstat, write return counts) matches
// the RTL run. Output itself is suppressed — the RTL prints the real copy.
static void cosim_handle_htif()
{
  if (!cosim_tohost) return;
  ull v = cosim_ld64(cosim_tohost);
  if (v == 0) return;
  if (v & 1) {                       // exit(code)
    cosim_halted = true;
    return;
  }
  c_syscalls++;
  ull mm = v;                        // magic-mem block: n, a0..a6
  ull n = cosim_ld64(mm);
  ull a0 = cosim_ld64(mm + 8), a1 = cosim_ld64(mm + 16),
      a2 = cosim_ld64(mm + 24);
  long ret = 0;
  switch (n) {
    case 64:                         // write(fd, buf, len): swallow, ack len
      ret = (long)a2;
      break;
    case 80: {                       // fstat(fd, st)
      struct stat st;
      ret = fstat((int)a0, &st);
      if (ret == 0 && a1 >= MEM_BASE) {
        riscv_stat rs = {};
        rs.dev = st.st_dev; rs.ino = st.st_ino; rs.mode = st.st_mode;
        rs.nlink = st.st_nlink; rs.uid = st.st_uid; rs.gid = st.st_gid;
        rs.rdev = st.st_rdev; rs.size = st.st_size;
        rs.blksize = st.st_blksize; rs.blocks = st.st_blocks;
        rs.atime = st.st_atime; rs.mtime = st.st_mtime;
        rs.ctime = st.st_ctime;
        memcpy(cosim_mem + (a1 - MEM_BASE), &rs, sizeof(rs));
      }
      break;
    }
    case 57: ret = 0; break;         // close
    case 63: ret = 0; break;         // read: EOF
    default: ret = 0; break;
  }
  cosim_st64(mm, (ull)ret);
  cosim_st64(cosim_tohost, 0);
  cosim_st64(cosim_fromhost, 1);     // guest zeroes it after reading
}

static uint32_t cosim_fetch_bits(ull pc)
{
  uint32_t lo = 0, hi = 0;
  memcpy(&lo, cosim_mem + (pc - MEM_BASE), 2);
  if ((lo & 3) == 3)
    memcpy(&hi, cosim_mem + (pc - MEM_BASE) + 2, 2);
  return lo | (hi << 16);
}

static void cosim_runahead()
{
  if (cosim_desynced || cosim_halted) return;
  size_t steps = 0;
  while (cosim_fifo.size() < cosim_cursor + LOOKAHEAD && steps < STEP_CAP) {
    cosim_handle_htif();
    if (cosim_halted) break;
    ull pc0 = cosim_proc->get_state()->pc;
    if (pc0 < MEM_BASE || pc0 >= MEM_BASE + MEM_SIZE) {
      // wandered outside our memory (trap vector, HTIF wildness): stop
      // growing; commits will eventually desync and report it
      break;
    }
    uint32_t insn = cosim_fetch_bits(pc0);
    cosim_proc->step(1);
    steps++;
    c_steps++;
    ull pc1 = cosim_proc->get_state()->pc;
    CfiInfo ci = cosim_cfi(insn);
    if (ci.is_cfi) {
      unsigned len = ((insn & 3) == 3) ? 4 : 2;
      ull fall = pc0 + len;
      bool taken = ci.cond ? (pc1 != fall) : true;
      ull vpc = cosim_visible_pc(pc0, len);
      static ull rec_seq = 0;
      cosim_fifo.push_back(Rec{vpc, pc1, ci.cond, ci.indirect, taken, false, false, false, rec_seq});
      CLOG("R %llu %llx %d %d %llx %d\n", rec_seq, vpc, (int)ci.cond,
           (int)taken, pc1, (int)ci.indirect);
      rec_seq++;
      if (ci.cond) cosim_cond_pcs.insert(vpc);
    }
  }
}

static void cosim_desync(ull pc)
{
  cosim_desynced = true;
  c_desync_pc = pc;
  if (FILE *f = cosim_logf()) {
    fprintf(f, "DESYNC pc=%llx cursor=%zu window:\n", pc, cosim_cursor);
    size_t lim = cosim_fifo.size() < 24 ? cosim_fifo.size() : 24;
    for (size_t j = 0; j < lim; j++) {
      const Rec &r = cosim_fifo[j];
      fprintf(f, "  w%zu seq=%llu pc=%llx cond=%d taken=%d tgt=%llx%s%s\n",
              j, r.seq, r.pc, (int)r.cond, (int)r.taken, r.target,
              r.committed ? " COMMITTED" : "",
              r.resolved ? " RESOLVED" : "");
    }
    fflush(f);
  }
}

// Pre-sync: RTL bootrom commits precede the ELF entry, and the program's
// first CFI may be conditional OR unconditional (crt0's first call), so
// sync engages from whichever update stream first matches one of the first
// few runahead records.
static bool cosim_try_sync(ull ip, bool cond, bool taken, ull target)
{
  size_t lim = cosim_fifo.size() < 4 ? cosim_fifo.size() : 4;
  for (size_t j = 0; j < lim; j++) {
    Rec &r = cosim_fifo[j];
    bool m = cond ? (r.cond && r.pc == ip && r.taken == taken)
                  : (!r.cond && r.pc == ip && r.target == target);
    if (m) {
      cosim_synced = true;
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Window helpers
// ---------------------------------------------------------------------------

static Rec *cosim_rec_at(ull seq)
{
  if (cosim_fifo.empty() || seq < cosim_fifo.front().seq) return nullptr;
  size_t j = seq - cosim_fifo.front().seq;
  return j < cosim_fifo.size() ? &cosim_fifo[j] : nullptr;
}

static inline ull cosim_front_seq()
{
  return cosim_fifo.empty() ? cosim_pos : cosim_fifo.front().seq;
}

static void cosim_set_cursor_seq(ull seq)
{
  ull f = cosim_front_seq();
  size_t c = seq > f ? seq - f : 0;
  cosim_cursor = c < cosim_fifo.size() ? c : cosim_fifo.size();
}

// Prune committed records off the front, keeping the cursor window-local.
static void cosim_prune()
{
  while (!cosim_fifo.empty() && cosim_fifo.front().committed) {
    cosim_fifo.pop_front();
    if (cosim_cursor > 0) cosim_cursor--;
  }
}

// ---------------------------------------------------------------------------
// Fetch-side taps: fetch pc, s2 re-fetch flag, s1 kill
// ---------------------------------------------------------------------------

static void cosim_note_fetch(ull cycle, ull pc, bool replay)
{
  fetch_pc_at[cycle] = pc;
  if (replay) fetch_replay_at.insert(cycle); else fetch_replay_at.erase(cycle);
  if (fetch_pc_at.size() > 64) {
    for (auto it = fetch_pc_at.begin(); it != fetch_pc_at.end();)
      it = (it->first + 16 < cycle) ? fetch_pc_at.erase(it) : ++it;
    for (auto it = fetch_replay_at.begin(); it != fetch_replay_at.end();)
      it = (*it + 16 < cycle) ? fetch_replay_at.erase(it) : ++it;
  }
}

static void cosim_note_kill_s1(ull cycle)
{
  c_kill++;
  if (!inflight.empty() && inflight.back().cycle == cycle) {
    // built already this cycle: give its records back
    InFlight k = inflight.back();
    inflight.pop_back();
    cosim_set_cursor_seq(k.pre_cursor_seq);
    for (size_t j = cosim_cursor; j < cosim_fifo.size(); j++)
      cosim_fifo[j].served = false;
    last_exit = k.pre_exit;
    CLOG("K %llu rewind %llu\n", cycle, k.pre_cursor_seq);
  } else {
    kill_s1_at = cycle;  // not built yet: build it transiently
    CLOG("K %llu pending\n", cycle);
  }
}

// ---------------------------------------------------------------------------
// Serving a slot query
// ---------------------------------------------------------------------------

// Build the packet for this cycle: the set of records the fetch packet at
// pkt_pc covers. Called once per cycle, at its first query.
static void cosim_build_packet(ull cycle)
{
  pkt_built = true;
  pkt_recs.clear();
  c_pkt++;
  ull lo = pkt_pc, hi = packet_end(pkt_pc);
  while (!inflight.empty() &&
         (inflight.front().end_seq <= cosim_pos ||
          inflight.front().cycle + 16 < cycle))
    inflight.pop_front();

  // Is this the next packet in program order? Three tests.
  bool inorder = (last_exit == ~0ull) || (pkt_pc == last_exit);
  if (inorder && inflight.size() >= INFLIGHT_MAX) {
    inorder = false;
    c_pkt_depth++;
  }
  if (inorder && fetch_replay_at.count(cycle)) {
    inorder = false;   // the frontend says so: an s2 re-fetch of the same packet
    c_pkt_flagged++;
  }

  ull exit_pc = hi;
  size_t j = cosim_cursor, prev = 0;
  auto collect_from_cursor = [&]() {
    for (; j < cosim_fifo.size(); j++) {
      Rec &r = cosim_fifo[j];
      if (r.pc < lo || r.pc >= hi || r.pc < prev) break;
      pkt_recs[r.pc] = r.seq;
      prev = r.pc;
      if (r.cond ? r.taken : true) { exit_pc = r.target; j++; break; }
    }
  };
  auto commit_packet = [&]() {
    inflight.push_back(InFlight{cosim_front_seq() + j, cycle,
                                cosim_front_seq() + cosim_cursor, last_exit});
    cosim_cursor = j;
    last_exit = exit_pc;
  };

  if (inorder) {
    collect_from_cursor();
    if (kill_s1_at == cycle) {
      // killed before it was built: answer its slots, commit nothing
      if (pkt_recs.empty()) c_pkt_empty++;
    } else {
      commit_packet();
      if (pkt_recs.empty()) c_pkt_empty++;
    }
  } else {
    // Not the next packet: a re-fetch of records still in flight (stall
    // replay, post-squash refetch) — serve the latest in-flight run inside
    // the window; a wrong-path fetch finds nothing.
    ull f = cosim_front_seq();
    size_t j0 = cosim_pos > f ? cosim_pos - f : 0;
    size_t k = std::min(cosim_cursor, cosim_fifo.size());
    while (k > j0 && (cosim_fifo[k - 1].pc < lo || cosim_fifo[k - 1].pc >= hi))
      k--;
    if (k > j0) {
      // k-1 is the run's last record; walk back to its start
      size_t b = k - 1;
      while (b > j0 && cosim_fifo[b - 1].pc >= lo &&
             cosim_fifo[b - 1].pc < cosim_fifo[b].pc &&
             !(cosim_fifo[b - 1].cond ? cosim_fifo[b - 1].taken : true))
        b--;
      for (size_t q = b; q < k; q++) pkt_recs[cosim_fifo[q].pc] = cosim_fifo[q].seq;
      c_pkt_replay++;
    } else if (kill_s1_at != cycle && cosim_cursor < cosim_fifo.size() &&
               cosim_fifo[cosim_cursor].pc == pkt_pc) {
      // Nothing in flight for this window and the fetch starts exactly at
      // the cursor's record: path tracking lost the thread (a redirect the
      // tap did not see); accept it as in-order rather than starve it. The
      // test is deliberately strict — "cursor record anywhere in the window"
      // let wrong-path sequential fetches consume records.
      c_pkt_forced++;
      collect_from_cursor();
      commit_packet();
    } else {
      c_pkt_empty++;
    }
  }
  CLOG("P %llu %llx n=%zu%s exit=%llx flag=%d\n", cycle, pkt_pc,
       pkt_recs.size(), inorder ? "" : " refetch", last_exit,
       (int)fetch_replay_at.count(cycle));
}

// One serve per (cycle, pc): the direction and target harnesses share it.
static Rec *cosim_serve(ull pc, ull cycle)
{
  if (cycle != memo_cycle) {
    memo_cycle = cycle;
    memo_hits.clear();
    memo_misses.clear();
  } else {
    auto it = memo_hits.find(pc);
    if (it != memo_hits.end()) { memo_rec = it->second; return &memo_rec; }
    if (memo_misses.count(pc)) return nullptr;
  }
  if (cosim_desynced) return nullptr;
  cosim_runahead();
  auto fp = fetch_pc_at.find(cycle);
  if (fp == fetch_pc_at.end() && pkt_cycle != cycle) {
    // No fetch pc published for this cycle (Should Never Happen in ROI).
    c_pkt_nofetch++;
    memo_misses.insert(pc);
    CLOG("S %llu %llx wrong c=%llu\n", cycle, pc,
         cosim_front_seq() + cosim_cursor);
    return nullptr;
  }
  if (pkt_cycle != cycle) {
    pkt_cycle = cycle;
    pkt_pc = fp->second;
    pkt_built = false;
  }
  if (!pkt_built) cosim_build_packet(cycle);
  auto it = pkt_recs.find(pc);
  if (it == pkt_recs.end()) {
    c_wrongpath++;
    memo_misses.insert(pc);
    CLOG("S %llu %llx wrong c=%llu\n", cycle, pc,
         cosim_front_seq() + cosim_cursor);
    return nullptr;
  }
  Rec *r = cosim_rec_at(it->second);
  if (!r) { memo_misses.insert(pc); return nullptr; }
  r->served = true;
  memo_rec = *r;
  memo_hits[pc] = memo_rec;
  CLOG("S %llu %llx hit %llu c=%llu\n", cycle, pc, memo_rec.seq,
       cosim_front_seq() + cosim_cursor);
  return &memo_rec;
}

// ---------------------------------------------------------------------------
// FTQ taps: enqueue and redirect
// ---------------------------------------------------------------------------

// A bundle entered the FTQ: attach the correct-path records it covers. The
// bundle is [pc, bankAlign(pc) + 16), single-banked in the last bank of a
// 64B line. cfi_idx counts slots from the bank base. The walk is cut by the
// machine's own cfi_idx (the slot it believed ended the bundle) and by the
// first record that is actually taken. Wrong-path bundles match nothing and
// consume nothing.
static void cosim_tap_enq(ull idx, ull pc, bool cfiv, ull cfi_idx, ull cycle)
{
  cosim_runahead();
  ull f = cosim_front_seq();
  if (cosim_pos < f) cosim_pos = f;  // cannot be behind the commit frontier
  ull base = bank_align(pc), end = packet_end(pc);
  ull cut_pc = cfiv ? base + 2 * cfi_idx : ~0ull;
  if (!tap_bootstrapped) {
    // Sync engaged mid-stream (first commit), so bundles enqueued before it
    // were never seen: skip already-served records that cannot belong here.
    ull served = f + cosim_cursor;
    ull q = cosim_pos;
    while (q < served) {
      Rec *r = cosim_rec_at(q);
      if (!r || (r->pc >= pc && r->pc < end)) break;
      q++;
    }
    if (q < served) { cosim_pos = q; tap_bootstrapped = true; }
  }
  ull start = cosim_pos, pos = start, prev = 0;
  for (;;) {
    Rec *r = cosim_rec_at(pos);
    if (!r) break;
    if (r->pc < pc || r->pc >= end) break;                // outside bundle
    if (r->pc < prev) break;                                // wrapped around
    if (cfiv && r->pc > cut_pc) break;                      // past the cut
    prev = r->pc;
    bool taken = r->cond ? r->taken : true;
    pos++;
    if (taken) break;                     // a taken CFI ends the bundle
    if (cfiv && r->pc == cut_pc) break;   // the machine cut here
  }
  cosim_ftq[idx % cosim_ftq.size()] = FtqEnt{start, pos, pc, true};
  cosim_pos = pos;
  c_tap_enq++;
  ull unserved = 0;
  for (ull q = start; q < pos; q++) {
    Rec *r = cosim_rec_at(q);
    if (r && !r->served) { unserved++; c_unserved++; }
  }
  if (f + cosim_cursor < pos) {  // speculative serving fell behind reality
    c_tap_lag++;
    cosim_set_cursor_seq(pos);
  }
  ull ahead = f + cosim_cursor - pos;
  if (ahead > 8) c_ahead8++;
  if (ahead > c_ahead_max) c_ahead_max = ahead;
  CLOG("F %llu %llx %llu %llu %llu cfi=%d/%llu unserved=%llu ahead=%llu\n",
       cycle, pc, idx, start, pos, cfiv ? 1 : 0, cfi_idx, unserved, ahead);
}

// Fetch redirected to npc because of the instruction in FTQ entry k
// (mispredict resolution, exception, CSR/fence flush). Everything younger
// than that instruction is dead; recompute the serve position from entry
// k's attachment: records up to the redirecting instruction stay consumed.
static void cosim_tap_redirect(ull idx, ull npc, ull cycle)
{
  FtqEnt &e = cosim_ftq[idx % cosim_ftq.size()];
  if (!e.used) { c_tap_orphan++; return; }
  // Resolution rule first: the CFI whose resolution explains npc (a
  // mispredict redirect); records through it stay consumed. Flush rule
  // second: no record explains npc, so this is a flush (exception,
  // CSR/fence) refetching from npc, and records at or past npc are
  // un-consumed. The order matters — a loop back-edge's target lies BELOW
  // the branch, so the flush rule alone would orphan the whole bundle.
  ull pos = e.after_seq;
  bool explained = false;
  for (ull q = e.start_seq; q < e.after_seq; q++) {
    Rec *r = cosim_rec_at(q);
    if (!r) break;
    bool taken = r->cond ? r->taken : true;
    if ((taken && r->target == npc) ||
        (r->cond && !r->taken && npc > r->pc && npc <= r->pc + 4)) {
      pos = q + 1;
      explained = true;
      break;
    }
  }
  if (!explained) {
    for (ull q = e.start_seq; q < e.after_seq; q++) {
      Rec *r = cosim_rec_at(q);
      if (!r || r->pc >= npc) { pos = q; break; }
    }
  }
  cosim_pos = pos;
  cosim_set_cursor_seq(pos);
  last_exit = npc;                         // the refetch continues here
  inflight.clear();
  for (size_t j = cosim_cursor; j < cosim_fifo.size(); j++) {
    cosim_fifo[j].resolved = false;        // killed occurrences re-execute
    cosim_fifo[j].served = false;          // ... and get refetched
  }
  c_tap_red++;
  CLOG("X %llu %llu %llx %llu\n", cycle, idx, npc, pos);
}

// One call per cycle from oracle_tap.v, whenever any tap input is active.
extern "C" void oracle_tap(ull cycle, unsigned char enq_fire, ull enq_idx,
                           ull enq_pc, unsigned char enq_cfi_valid,
                           ull enq_cfi_idx, unsigned char red_valid,
                           ull red_pc, ull red_idx, unsigned char f0_valid,
                           ull f0_pc, unsigned char f0_replay,
                           unsigned char f1_kill)
{
  if (!cosim_proc || cosim_desynced) return;
  if (cycle == tap_last_cycle) return;  // one delivery per cycle
  tap_last_cycle = cycle;
  // f0 is next cycle's s1 packet: publish it under that cycle.
  if (f0_valid) cosim_note_fetch(cycle + 1, f0_pc, f0_replay);
  if (!cosim_synced) return;
  if (f1_kill) cosim_note_kill_s1(cycle);
  if (enq_fire) cosim_tap_enq(enq_idx, enq_pc, enq_cfi_valid, enq_cfi_idx, cycle);
  if (red_valid) cosim_tap_redirect(red_idx, red_pc, cycle);
}

// ---------------------------------------------------------------------------
// Predictor-socket entry points (called from oracle_socket.cc)
// ---------------------------------------------------------------------------

void cosim_predict_branch(ull ip, ull cycle, unsigned char *pred,
                          unsigned char *known)
{
  c_d_pred++;
  CLOG("Q %llu %llx\n", cycle, ip);
  Rec *r = cosim_serve(ip, cycle);
  if (r && r->cond) {
    *pred = r->taken;
    *known = 1;
    return;
  }
  // Off-path (or non-conditional slot): satisfy the ghist contract for
  // branches we have ever seen; predict not-taken.
  *pred = 0;
  *known = cosim_cond_pcs.count(ip) ? 1 : 0;
}

void cosim_predict_target(ull ip, ull cycle, unsigned char *valid,
                          ull *target, unsigned char *is_br,
                          unsigned char *is_jal)
{
  c_t_pred++;
  Rec *r = cosim_serve(ip, cycle);
  if (!r) {
    *valid = 0; *target = 0; *is_br = 0; *is_jal = 0;
    return;
  }
  *valid = 1;
  *target = r->target;
  *is_br = r->cond;
  *is_jal = !r->cond;
}

// Direction update: commit (the truth), mispredict (resolution; the redirect
// tap has already re-anchored the position, so only blame is recorded), or
// repair (squashed younger packet; counted).
void cosim_update_branch(ull ip, ull cycle, unsigned char taken,
                         unsigned char is_mispredict, unsigned char is_repair)
{
  if (is_mispredict) {
    c_u_misp++; c_misp_by_pc[ip]++;
    CLOG("U %llu %llx %d misp\n", cycle, ip, (int)taken);
    return;
  }
  if (is_repair) {
    c_u_repair++;
    CLOG("U %llu %llx %d repair\n", cycle, ip, (int)taken);
    return;
  }
  if (cosim_desynced) { c_post_desync++; return; }
  cosim_runahead();
  if (!cosim_synced && !cosim_try_sync(ip, true, taken, 0)) {
    c_presync_drop++;  // bootrom commits precede the ELF entry
    CLOG("U %llu %llx %d commit presync\n", cycle, ip, (int)taken);
    return;
  }
  // Match a conditional record in a small window of uncommitted records.
  // Same-packet updates can arrive out of program order within one Verilator
  // eval (instance scheduling), so we search rather than demand the oldest.
  c_d_upd++;
  size_t seen = 0;
  for (size_t j = 0; j < cosim_fifo.size() && seen < 12; j++) {
    Rec &r = cosim_fifo[j];
    if (r.committed) continue;
    seen++;
    if (r.cond && r.pc == ip && r.taken == (bool)taken) {
      r.committed = true;
      if (r.taken) recent_cond_note(ip, r.target, cycle);
      recent_commit[ip] = cycle;
      CLOG("U %llu %llx %d commit ok %llu\n", cycle, ip, (int)taken, r.seq);
      if (cosim_cursor < j + 1) cosim_cursor = j + 1;
      cosim_prune();
      return;
    }
  }
  // Run-length skew: HTIF poll loops spin a host-timing-dependent number of
  // iterations, so the RTL and the runahead disagree only on run LENGTHS of
  // the same branch. An extra taken spin (RTL spun longer) is absorbed
  // without consuming anything; a missing spin commits the record early.
  seen = 0;
  for (size_t j = 0; j < cosim_fifo.size() && seen < 12; j++) {
    Rec &r = cosim_fifo[j];
    if (r.committed) continue;
    seen++;
    if (r.cond && r.pc == ip) {
      c_skew++;
      CLOG("U %llu %llx %d commit skew %llu\n", cycle, ip, (int)taken, r.seq);
      if (taken && !r.taken) return;  // RTL still spinning; keep the record
      r.committed = true;             // RTL exited a spin the cosim has
      if (r.taken) recent_cond_note(ip, r.target, cycle);
      recent_commit[ip] = cycle;
      if (cosim_cursor < j + 1) cosim_cursor = j + 1;
      cosim_prune();
      return;
    }
  }
  // CSR/fence flush-on-commit phantom: a bundle cut by a commit-time flush
  // still sends a commit-kind update for its (killed and refetched) CFI,
  // tens of cycles after the real commit. Seen at every embench ROI boundary
  // (start_trigger's csrr mcycle/minstret).
  auto rc = recent_commit.find(ip);
  if (rc != recent_commit.end() && cycle - rc->second <= 64) {
    c_phantom++;
    CLOG("U %llu %llx %d commit phantom\n", cycle, ip, (int)taken);
    return;
  }
  CLOG("U %llu %llx %d commit DESYNC\n", cycle, ip, (int)taken);
  cosim_desync(ip);
}

// Target update: commit of a taken CFI (the truth for unconditionals; a
// taken conditional's commit is owned by the direction stream), or a
// mispredict/repair (counted on the direction stream, ignored here).
void cosim_update_btb(ull ip, ull cycle, ull target,
                      unsigned char is_mispredict, unsigned char is_repair)
{
  if (is_mispredict || is_repair) return;
  if (cosim_desynced) { c_post_desync++; return; }
  cosim_runahead();
  if (!cosim_synced && !cosim_try_sync(ip, false, true, target)) {
    c_presync_drop++;
    CLOG("T %llu %llx %llx presync\n", cycle, ip, target);
    return;
  }
  // Taken conditionals raise a target update too; their record may already
  // be committed AND pruned by the direction stream (same cycle, or a couple
  // of cycles earlier when updates interleave across packets).
  {
    auto it = recent_cond.find(ip);
    if (it != recent_cond.end() && it->second.first == target &&
        cycle - it->second.second <= 16) {
      CLOG("T %llu %llx %llx recentcond\n", cycle, ip, target);
      return;
    }
  }
  c_t_upd++;
  size_t seen = 0;
  for (size_t j = 0; j < cosim_fifo.size() && seen < 12; j++) {
    Rec &r = cosim_fifo[j];
    // Any in-window conditional at this pc (committed or not, matching
    // outcome or run-length skew): the DIRECTION stream owns its commit;
    // this target update is acknowledged silently.
    if (r.cond && r.pc == ip) {
      CLOG("T %llu %llx %llx condack %llu\n", cycle, ip, target, r.seq);
      return;
    }
    if (r.committed) continue;
    seen++;
    if (!r.cond && r.pc == ip && r.target == target) {
      r.committed = true;
      recent_commit[ip] = cycle;
      CLOG("T %llu %llx %llx ok %llu\n", cycle, ip, target, r.seq);
      if (cosim_cursor < j + 1) cosim_cursor = j + 1;
      cosim_prune();
      return;
    }
    if (!r.cond && r.pc == ip && (!r.indirect || target == 0)) {
      // A direct jump has exactly one target, so this update commits it
      // whatever target the FTQ reports. The FTQ takes the target from the
      // NEXT entry's pc (bpd_target = pcs(bpd_idx + 1)); on the narrow
      // configs (MediumBoomV3 primecount: 59 in 150k cycles) that read is
      // sometimes 0, and treating it as a flush phantom left one jump
      // record uncommitted per event until the commit search window was
      // clogged and the model desynced. Never seen on Mega. A target-0
      // update for an indirect jump gets the same treatment.
      c_tgt_bogus++;
      r.committed = true;
      recent_commit[ip] = cycle;
      CLOG("T %llu %llx %llx ok-badtgt %llu\n", cycle, ip, target, r.seq);
      if (cosim_cursor < j + 1) cosim_cursor = j + 1;
      cosim_prune();
      return;
    }
    if (!r.cond && r.pc == ip) {
      // Indirect jump, different nonzero target: the flush phantom's target
      // flavor reports the flush redirect pc as the "target" before the real
      // commit arrives — keep the record.
      c_phantom++;
      CLOG("T %llu %llx %llx phantom-pre %llu\n", cycle, ip, target, r.seq);
      return;
    }
  }
  auto rc = recent_commit.find(ip);
  if (rc != recent_commit.end() && cycle - rc->second <= 64) {
    c_phantom++;
    CLOG("T %llu %llx %llx phantom\n", cycle, ip, target);
    return;
  }
  CLOG("T %llu %llx %llx DESYNC\n", cycle, ip, target);
  cosim_desync(ip);
}
