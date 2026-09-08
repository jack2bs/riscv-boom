// Oracle target harness: one instance per fetch slot per bank. Same
// timing as OracleDirHarness: query at s1, registered answer read at
// f2. Updates come from the FTQ (slot-0 instance only, see
// oracle_predictor.scala).

import "DPI-C" function void oracle_init_tgt();

import "DPI-C" function void oracle_predict_target(input longint unsigned ip,
                                            input longint unsigned cycle,
                                            output bit              valid,
                                            output longint unsigned target,
                                            output bit              is_br,
                                            output bit              is_jal);

import "DPI-C" function void oracle_update_btb(input longint unsigned ip,
                                        input longint unsigned cycle,
                                        input longint unsigned target,
                                        input bit              is_mispredict,
                                        input bit              is_repair);

module OracleTgtHarness (input         clock,
                   input         reset,

                   input         req_valid,
                   input [63:0]  req_pc,
                   output        req_target_valid,
                   output [63:0] req_target_pc,
                   output        req_is_br,
                   output        req_is_jal,

                   input         update_valid,
                   input [63:0]  update_pc,
                   input [63:0]  update_target,
                   input         update_is_mispredict,
                   input         update_is_repair);

   initial begin
      oracle_init_tgt();
   end

   bit     _req_target_valid;
   longint _req_target_pc;
   bit     _req_is_br;
   bit     _req_is_jal;

   reg        reg_req_target_valid;
   reg [63:0] reg_req_target_pc;
   reg        reg_req_is_br;
   reg        reg_req_is_jal;

   // Free-running cycle counter, identical by construction to the one in
   // OracleDirHarness and OracleTapHarnessBB.
   reg [63:0] cycle_cnt;

   assign req_target_valid = reg_req_target_valid;
   assign req_target_pc = reg_req_target_pc;
   assign req_is_br = reg_req_is_br;
   assign req_is_jal = reg_req_is_jal;

   always @(posedge clock) begin
      if (reset) begin
         _req_target_valid = 0;
         _req_target_pc = 0;
         _req_is_br = 0;
         _req_is_jal = 0;
         reg_req_target_valid <= 0;
         reg_req_target_pc <= 0;
         reg_req_is_br <= 0;
         reg_req_is_jal <= 0;
         cycle_cnt <= 0;
      end else begin
         if (req_valid) begin
            oracle_predict_target(req_pc, cycle_cnt, _req_target_valid,
                           _req_target_pc, _req_is_br, _req_is_jal);
         end
         if (update_valid) begin
            oracle_update_btb(update_pc, cycle_cnt, update_target,
                       update_is_mispredict, update_is_repair);
         end
         reg_req_target_valid <= _req_target_valid;
         reg_req_target_pc <= _req_target_pc;
         reg_req_is_br <= _req_is_br;
         reg_req_is_jal <= _req_is_jal;
         cycle_cnt <= cycle_cnt + 64'd1;
      end
   end

endmodule
