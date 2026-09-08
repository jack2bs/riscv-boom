package boom.v3.ifu

import chisel3._
import chisel3.util._
import chisel3.experimental.IntParam

import org.chipsalliance.cde.config.{Field, Parameters, Config}
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.subsystem.{TilesLocated, InSubsystem}
import freechips.rocketchip.tilelink._

import boom.v3.common._
import boom.v3.exu.{CommitExceptionSignals}
import boom.v3.util.{BoomCoreStringPrefix}

// ---------------------------------------------------------------------------
// Oracle branch predictor (runahead cosimulation, oracle_cosim.cc).
//
// A predictor bank in the same socket shape as the stock software predictor
// (sw_predictor.scala / WithSWBPD), but with its own harnesses, DPI symbols
// and config mixin so the two live side by side: WithSWBPD keeps running the
// stock software predictor, WithSWOracleBPD runs the oracle. Nothing in
// stock BOOM refers to these classes except the guarded tap block at the end
// of frontend.scala (SWOracleTapKey).
// ---------------------------------------------------------------------------

class OracleBranchPredictorBank(implicit p: Parameters) extends BranchPredictorBank()(p)
{
  val mems = Nil

  // Forward commit updates (architectural verify+advance) AND
  // mispredict/repair updates (speculative-pointer rollback) to the DPI
  // model; drop f4 btb-correction updates (btb_mispredicts), which carry no
  // squash or commit meaning for the oracle.
  val u = io.update
  val u_fwd = u.valid && (u.bits.is_commit_update ||
                          u.bits.is_mispredict_update ||
                          u.bits.is_repair_update)

  for (w <- 0 until bankWidth) {
    val tgt_harness = Module(new OracleTgtHarness)
    val dir_harness = Module(new OracleDirHarness)

    tgt_harness.io.clock := clock
    tgt_harness.io.reset := reset.asBool

    dir_harness.io.clock := clock
    dir_harness.io.reset := reset.asBool

    // Predict at the architectural PC of slot w of this bank (s1_pc is
    // already bank-aligned by the outer BranchPredictor). Gate on the fetch
    // mask so slots below the fetch offset (never actually fetched, and
    // masked out of the f2 response by fetchMask in the frontend) do not
    // advance the oracle's speculative pointers.
    tgt_harness.io.req_valid    := s1_valid && s1_mask(w)
    tgt_harness.io.req_pc       := bankAlign(s1_pc) + (w << 1).U

    dir_harness.io.req_valid    := s1_valid && s1_mask(w)
    dir_harness.io.req_pc       := bankAlign(s1_pc) + (w << 1).U

    // Update addressing: io.update.bits.pc is this bank's aligned base, and
    // io.update.bits.cfi_idx.bits is bank-local (the outer BranchPredictor's
    // nBanks==2 update splitting truncates the packet-level index to
    // log2Ceil(bankWidth) bits and re-bases pc per bank, for both the
    // packet-starts-in-bank-0 and packet-starts-in-bank-1 cases), so
    // pc + (cfi_idx << 1) is the architectural PC of the CFI's slot.
    //
    // Target updates: commit updates are gated on cfi_taken (for a not-taken
    // conditional CFI the update's `target` is the fall-through address,
    // which must not consume an entry of the oracle's taken-target stream);
    // mispredict/repair updates are forwarded whenever the entry recorded a
    // CFI, since they exist only to roll speculative state back. Only the
    // slot-0 instance forwards (the pc is recomputed from cfi_idx, so one
    // DPI call per bank update suffices).
    tgt_harness.io.update_valid  := u_fwd && u.bits.cfi_idx.valid &&
                                    (u.bits.cfi_taken || u.bits.is_mispredict_update || u.bits.is_repair_update) &&
                                    (w == 0).B
    tgt_harness.io.update_pc     := u.bits.pc + (u.bits.cfi_idx.bits << 1)
    tgt_harness.io.update_target := u.bits.target
    tgt_harness.io.update_is_mispredict := u.bits.is_mispredict_update
    tgt_harness.io.update_is_repair     := u.bits.is_repair_update

    // Direction updates go to every conditional-branch slot of the packet
    // (br_mask is already truncated at the taken CFI by the FTQ, in both the
    // commit and the mispredict/repair paths).
    dir_harness.io.update_valid := u_fwd && u.bits.br_mask(w)
    dir_harness.io.update_pc    := u.bits.pc + (w << 1).U
    dir_harness.io.update_taken := w.U === u.bits.cfi_idx.bits &&
                                      u.bits.cfi_idx.valid && u.bits.cfi_taken
    dir_harness.io.update_is_mispredict := u.bits.is_mispredict_update
    dir_harness.io.update_is_repair     := u.bits.is_repair_update

    // f1 passes through from resp_in (e.g. a composed FA-uBTB) via the
    // base-class default connection. The harness registers the DPI results
    // once, so the answer to the s1 request is visible in f2; the oracle
    // overrides f2 only when it knows this slot's CFI, and f3 repeats f2 so
    // the authoritative stage carries targets as well as directions.
    //
    // Crucially, a known conditional branch is flagged with
    // is_br && predicted_pc.valid EVEN WHEN it has never committed taken
    // (no target entry). The frontend's global-history bookkeeping
    // (f1/f2_predicted_ghist and the f3_correct_*_ghist repair checks in
    // frontend.scala) counts not-taken branches via exactly that mask, and
    // f3 recomputes it from the decoded br_mask; a predictor that stays
    // silent on not-taken branches makes every such packet fail the ghist
    // consistency check and pay a full f1/f2 clear. The baseline BTB has the
    // same behavior: it allocates tag+is_br meta for every br_mask slot and
    // reports hits with a possibly-meaningless target. The dummy target is
    // never consumed: conditional-branch redirects require taken (a branch
    // with no taken commits always predicts not-taken), and f3 takes
    // conditional-branch targets from decode.
    io.resp.f2(w) := io.resp_in(0).f2(w)
    when (tgt_harness.io.req_target_valid) {
      io.resp.f2(w).predicted_pc.valid := true.B
      io.resp.f2(w).predicted_pc.bits  := tgt_harness.io.req_target_pc
      io.resp.f2(w).is_br              := tgt_harness.io.req_is_br
      io.resp.f2(w).is_jal             := tgt_harness.io.req_is_jal
      io.resp.f2(w).taken              := Mux(tgt_harness.io.req_is_br,
                                              dir_harness.io.req_taken, true.B)
    } .elsewhen (dir_harness.io.req_known) {
      io.resp.f2(w).predicted_pc.valid := true.B
      io.resp.f2(w).predicted_pc.bits  := 0.U
      io.resp.f2(w).is_br              := true.B
      io.resp.f2(w).is_jal             := false.B
      io.resp.f2(w).taken              := dir_harness.io.req_taken
    }
    io.resp.f3(w) := RegNext(io.resp.f2(w))
  }
}

class WithSWOracleBPD extends Config((site, here, up) => {
  case SWOracleTapKey => true
  case TilesLocated(InSubsystem) => up(TilesLocated(InSubsystem), site) map {
    case tp: BoomTileAttachParams => tp.copy(tileParams = tp.tileParams.copy(core = tp.tileParams.core.copy(
      bpdMaxMetaLength = 120,
      globalHistoryLength = 64,
      localHistoryLength = 1,
      localHistoryNSets = 0,
      branchPredictor = ((resp_in: BranchPredictionBankResponse, p: Parameters) => {
        // Compose the stock FA-uBTB in front of the oracle so hot taken
        // branches redirect at f1 exactly as in the baseline; the oracle's
        // f2/f3 outputs stay authoritative.
        val ubtb = Module(new FAMicroBTBBranchPredictorBank()(p))
        val sw   = Module(new OracleBranchPredictorBank()(p))
        val preds = Seq(ubtb, sw)
        preds.map(_.io := DontCare)

        ubtb.io.resp_in(0) := resp_in
        sw.io.resp_in(0)   := ubtb.io.resp

        (preds, sw.io.resp)
      })
    )))
    case other => other
  }
})

class OracleDirHarness(implicit p: Parameters)
    extends BlackBox with HasBlackBoxResource {
  val io = IO(new Bundle {
    val clock = Input(Clock())
    val reset = Input(Bool())

    val req_valid = Input(Bool())
    val req_pc = Input(UInt(64.W))
    val req_taken = Output(Bool())
    val req_known = Output(Bool())

    val update_valid = Input(Bool())
    val update_pc = Input(UInt(64.W))
    val update_taken = Input(Bool())
    val update_is_mispredict = Input(Bool())
    val update_is_repair = Input(Bool())
  })

  addResource("/vsrc/oracle_dir_harness.v")
  addResource("/csrc/oracle_socket.cc")
  addResource("/csrc/oracle_cosim.cc")
}

class OracleTgtHarness(implicit p: Parameters)
    extends BlackBox with HasBlackBoxResource {
  val io = IO(new Bundle {
    val clock = Input(Clock())
    val reset = Input(Bool())

    val req_valid = Input(Bool())
    val req_pc = Input(UInt(64.W))
    val req_target_valid = Output(Bool())
    val req_target_pc = Output(UInt(64.W))
    val req_is_br = Output(Bool())
    val req_is_jal = Output(Bool())

    val update_valid = Input(Bool())
    val update_pc = Input(UInt(64.W))
    val update_target = Input(UInt(64.W))
    val update_is_mispredict = Input(Bool())
    val update_is_repair = Input(Bool())
  })

  addResource("/vsrc/oracle_tgt_harness.v")
}

// ---------------------------------------------------------------------------
// Passive frontend taps (fetch-occurrence identification)
// ---------------------------------------------------------------------------
//
// The predictor socket alone cannot tell the oracle WHICH dynamic occurrence
// of a pc a fetch query is for (replays, squashes and wrong-path fetches are
// unlabeled). frontend.scala instantiates this DPI blackbox — under
// SWOracleTapKey only — and feeds it the s0 fetch pc and s2 re-fetch flag,
// s1 kills, the FTQ enqueue stream and the CPU redirects. Read-only: no
// machine behavior depends on it.

case object SWOracleTapKey extends Field[Boolean](false)

// nBanks/bankBytes/fetchBytes/blockBytes/ftqEntries: the instantiating
// frontend's geometry (HasBoomFrontendParameters), handed to the C model as
// Verilog parameters so one model serves Small, Medium, Large and Mega.
class OracleTapHarnessBB(nBanks: Int, bankBytes: Int, fetchBytes: Int,
                         blockBytes: Int, ftqEntries: Int)(implicit p: Parameters)
    extends BlackBox(Map("NBANKS" -> IntParam(nBanks),
                         "BANK_BYTES" -> IntParam(bankBytes),
                         "FETCH_BYTES" -> IntParam(fetchBytes),
                         "BLOCK_BYTES" -> IntParam(blockBytes),
                         "FTQ_ENTRIES" -> IntParam(ftqEntries)))
    with HasBlackBoxResource {
  val io = IO(new Bundle {
    val clock = Input(Clock())
    val reset = Input(Bool())
    val enq_fire = Input(Bool())
    val enq_idx = Input(UInt(64.W))
    val enq_pc = Input(UInt(64.W))
    val enq_cfi_valid = Input(Bool())
    val enq_cfi_idx = Input(UInt(64.W))
    val red_valid = Input(Bool())
    val red_pc = Input(UInt(64.W))
    val red_idx = Input(UInt(64.W))
    val f0_valid = Input(Bool())
    val f0_pc = Input(UInt(64.W))
    val f0_replay = Input(Bool())
    val f1_kill = Input(Bool())
  })
  addResource("/vsrc/oracle_tap.v")
}
