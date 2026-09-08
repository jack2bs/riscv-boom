// Passive frontend tap feeding the oracle model (oracle_cosim.cc) with the
// facts the predictor socket cannot carry: the fetch pc of the packet about
// to query (s0, one cycle early), the s2 re-fetch flag, s1 kills, the FTQ
// enqueue stream, and CPU redirects. Wired in frontend.scala under
// SWOracleTapKey; read-only, one instance per frontend.

import "DPI-C" function void oracle_init_geometry(input longint unsigned nbanks,
                                                  input longint unsigned bank_bytes,
                                                  input longint unsigned fetch_bytes,
                                                  input longint unsigned block_bytes,
                                                  input longint unsigned ftq_entries);

import "DPI-C" function void oracle_tap(input longint unsigned cycle,
                                        input bit              enq_fire,
                                        input longint unsigned enq_idx,
                                        input longint unsigned enq_pc,
                                        input bit              enq_cfi_valid,
                                        input longint unsigned enq_cfi_idx,
                                        input bit              red_valid,
                                        input longint unsigned red_pc,
                                        input longint unsigned red_idx,
                                        input bit              f0_valid,
                                        input longint unsigned f0_pc,
                                        input bit              f0_replay,
                                        input bit              f1_kill);

module OracleTapHarnessBB #(parameter NBANKS = 2,
                            parameter BANK_BYTES = 8,
                            parameter FETCH_BYTES = 16,
                            parameter BLOCK_BYTES = 64,
                            parameter FTQ_ENTRIES = 40)
                          (input        clock,
                           input        reset,
                           input        enq_fire,
                           input [63:0] enq_idx,
                           input [63:0] enq_pc,
                           input        enq_cfi_valid,
                           input [63:0] enq_cfi_idx,
                           input        red_valid,
                           input [63:0] red_pc,
                           input [63:0] red_idx,
                           input        f0_valid,
                           input [63:0] f0_pc,
                           input        f0_replay,
                           input        f1_kill);

   // Frontend geometry to the model, once, before any DPI query.
   initial begin
      oracle_init_geometry(NBANKS, BANK_BYTES, FETCH_BYTES, BLOCK_BYTES, FTQ_ENTRIES);
   end

   // Free-running counter with the same reset/increment as the predictor
   // harness counters, so tap events share their timeline.
   reg [63:0] cycle_cnt;

   always @(posedge clock) begin
      if (reset) begin
         cycle_cnt <= 0;
      end else begin
         cycle_cnt <= cycle_cnt + 1;
         if (enq_fire || red_valid || f0_valid || f1_kill)
           oracle_tap(cycle_cnt, enq_fire, enq_idx, enq_pc,
                      enq_cfi_valid, enq_cfi_idx,
                      red_valid, red_pc, red_idx,
                      f0_valid, f0_pc, f0_replay, f1_kill);
      end
   end
endmodule
