//******************************************************************************
// Copyright (c) 2015 - 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE and LICENSE.SiFive for license details.
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
// RISCV Processor Issue Logic
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

package boom.v3.exu

import chisel3._
import chisel3.util.{log2Ceil, PopCount}

import org.chipsalliance.cde.config.Parameters
import freechips.rocketchip.util.Str

import FUConstants._
import boom.v3.common._

/**
 * Specific type of issue unit
 *
 * @param params issue queue params
 * @param numWakeupPorts number of wakeup ports for the issue queue
 */
class IssueUnitCollapsing(
  params: IssueParams,
  numWakeupPorts: Int)
  (implicit p: Parameters)
  extends IssueUnit(params.numEntries, params.issueWidth, numWakeupPorts, params.iqType, params.dispatchWidth)
{
  //-------------------------------------------------------------
  // Figure out how much to shift entries by

  val maxShift = dispatchWidth
  val vacants = issue_slots.map(s => !(s.valid)) ++ io.dis_uops.map(_.valid).map(!_.asBool)
  val shamts_oh = Array.fill(numIssueSlots+dispatchWidth) {Wire(UInt(width=maxShift.W))}
  // Parallel-prefix (Hillis-Steele) saturating vacancy count.
  // Replaces the original O(numIssueSlots)-deep serial SaturatingCounterOH
  // chain with an O(log) depth tree. Functionally identical: shamts_oh(i)
  // encodes min(#vacants in [0, i-1], maxShift) one-hot as
  // (count==0 -> 0, count c in [1,maxShift] -> (1 << (c-1))).
  shamts_oh(0) := 0.U
  locally {
    val n  = numIssueSlots + dispatchWidth
    val cw = log2Ceil(maxShift + 1)
    def satAdd(a: UInt, b: UInt): UInt = {
      val s = a +& b
      (Mux(s > maxShift.U, maxShift.U, s))(cw - 1, 0)
    }
    var lvl: IndexedSeq[UInt] = (0 until n).map(i => Mux(vacants(i), 1.U(cw.W), 0.U(cw.W)))
    var stride = 1
    while (stride < n) {
      val s = stride
      lvl = (0 until n).map(i => if (i >= s) satAdd(lvl(i), lvl(i - s)) else lvl(i))
      stride *= 2
    }
    for (i <- 1 until n) {
      val cnt = lvl(i - 1)  // exclusive prefix count of vacants in [0, i-1]
      shamts_oh(i) := Mux(cnt === 0.U, 0.U(maxShift.W), ((1.U << (cnt - 1.U)))(maxShift - 1, 0))
    }
  }

  //-------------------------------------------------------------

  // which entries' uops will still be next cycle? (not being issued and vacated)
  val will_be_valid = (0 until numIssueSlots).map(i => issue_slots(i).will_be_valid) ++
                      (0 until dispatchWidth).map(i => io.dis_uops(i).valid &&
                                                        !dis_uops(i).exception &&
                                                        !dis_uops(i).is_fence &&
                                                        !dis_uops(i).is_fencei)

  val uops = issue_slots.map(s=>s.out_uop) ++ dis_uops.map(s=>s)
  for (i <- 0 until numIssueSlots) {
    issue_slots(i).in_uop.valid := false.B
    issue_slots(i).in_uop.bits  := uops(i+1)
    for (j <- 1 to maxShift by 1) {
      when (shamts_oh(i+j) === (1 << (j-1)).U) {
        issue_slots(i).in_uop.valid := will_be_valid(i+j)
        issue_slots(i).in_uop.bits  := uops(i+j)
      }
    }
    issue_slots(i).clear        := shamts_oh(i) =/= 0.U
  }

  //-------------------------------------------------------------
  // Dispatch/Entry Logic
  // did we find a spot to slide the new dispatched uops into?

  val will_be_available = (0 until numIssueSlots).map(i =>
                            (!issue_slots(i).will_be_valid || issue_slots(i).clear) && !(issue_slots(i).in_uop.valid))
  // Saturating popcount capped at dispatchWidth. The dispatch-ready signals
  // only ever test num_available against 0..dispatchWidth-1, so counting higher
  // is unnecessary; capping keeps every adder narrow and avoids the long carry
  // chain a full-width PopCount produced on this registered path.
  val num_available = {
    val cap = dispatchWidth
    val cw  = log2Ceil(cap + 1)
    def satAddA(a: UInt, b: UInt): UInt = {
      val s = a +& b
      (Mux(s > cap.U, cap.U, s))(cw - 1, 0)
    }
    def reduceSat(xs: IndexedSeq[UInt]): UInt =
      if (xs.length == 1) xs.head
      else { val (lo, hi) = xs.splitAt(xs.length / 2); satAddA(reduceSat(lo), reduceSat(hi)) }
    reduceSat(will_be_available.map(b => Mux(b, 1.U(cw.W), 0.U(cw.W))).toIndexedSeq)
  }
  for (w <- 0 until dispatchWidth) {
    io.dis_uops(w).ready := RegNext(num_available > w.U)
  }

  //-------------------------------------------------------------
  // Issue Select Logic

  // set default
  for (w <- 0 until issueWidth) {
    io.iss_valids(w) := false.B
    io.iss_uops(w)   := NullMicroOp
    // unsure if this is overkill
    io.iss_uops(w).prs1 := 0.U
    io.iss_uops(w).prs2 := 0.U
    io.iss_uops(w).prs3 := 0.U
    io.iss_uops(w).lrs1_rtype := RT_X
    io.iss_uops(w).lrs2_rtype := RT_X
  }

  val requests = issue_slots.map(s => s.request)
  val port_issued = Array.fill(issueWidth){Bool()}
  for (w <- 0 until issueWidth) {
    port_issued(w) = false.B
  }

  for (i <- 0 until numIssueSlots) {
    issue_slots(i).grant := false.B
    var uop_issued = false.B

    for (w <- 0 until issueWidth) {
      val can_allocate = (issue_slots(i).uop.fu_code & io.fu_types(w)) =/= 0.U

      when (requests(i) && !uop_issued && can_allocate && !port_issued(w)) {
        issue_slots(i).grant := true.B
        io.iss_valids(w) := true.B
        io.iss_uops(w) := issue_slots(i).uop
      }
      val was_port_issued_yet = port_issued(w)
      port_issued(w) = (requests(i) && !uop_issued && can_allocate) | port_issued(w)
      uop_issued = (requests(i) && can_allocate && !was_port_issued_yet) | uop_issued
    }
  }
}
