// Oracle direction harness: one instance per fetch slot per bank. The
// query for slot pc is made at s1; the DPI answer is registered and read by
// the f2 response (sw_predictor.scala). Updates come from the FTQ.

import "DPI-C" function void oracle_init_dir();

import "DPI-C" function void oracle_predict_branch(input longint unsigned ip,
                                            input longint unsigned cycle,
                                            output bit pred,
                                            output bit known);

import "DPI-C" function void oracle_update_branch(input longint unsigned ip,
                                           input longint unsigned cycle,
                                           input bit taken,
                                           input bit is_mispredict,
                                           input bit is_repair);

module OracleDirHarness (input        clock,
                               input        reset,

                               input        req_valid,
                               input [63:0] req_pc,
                               output       req_taken,
                               output       req_known,

                               input        update_valid,
                               input [63:0] update_pc,
                               input        update_taken,
                               input        update_is_mispredict,
                               input        update_is_repair);

   initial begin
      oracle_init_dir();
   end

   bit _req_taken;
   bit _req_known;

   reg reg_req_taken;
   reg reg_req_known;

   // Free-running cycle counter, identical by construction (same clock,
   // reset, init and increment) in every harness instance and in
   // OracleTapHarnessBB: the model keys all of its state by this count.
   reg [63:0] cycle_cnt;

   assign req_taken = reg_req_taken;
   assign req_known = reg_req_known;

   always @(posedge clock) begin
      if (reset) begin
         _req_taken = 0;
         _req_known = 0;
         reg_req_taken <= 0;
         reg_req_known <= 0;
         cycle_cnt <= 0;
      end else begin
         if (req_valid) begin
            oracle_predict_branch(req_pc, cycle_cnt, _req_taken, _req_known);
         end
         if (update_valid) begin
            oracle_update_branch(update_pc, cycle_cnt, update_taken,
                          update_is_mispredict, update_is_repair);
         end
         reg_req_taken <= _req_taken;
         reg_req_known <= _req_known;
         cycle_cnt <= cycle_cnt + 64'd1;
      end
   end

endmodule
