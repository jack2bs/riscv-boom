// Predictor-socket DPI entry points for the oracle branch predictor.
//
// oracle_dir_harness.v (direction) and oracle_tgt_harness.v (target) import these six
// functions; each forwards to the runahead-cosimulation model in
// oracle_cosim.cc. One harness instance exists per fetch slot per bank
// (~16), so the initializers are called ~16 times; the model initializes
// once.

typedef unsigned long long ull;

// oracle_cosim.cc
void cosim_init_once();
void cosim_predict_branch(ull ip, ull cycle, unsigned char *pred,
                          unsigned char *known);
void cosim_predict_target(ull ip, ull cycle, unsigned char *valid,
                          ull *target, unsigned char *is_br,
                          unsigned char *is_jal);
void cosim_update_branch(ull ip, ull cycle, unsigned char taken,
                         unsigned char is_mispredict, unsigned char is_repair);
void cosim_update_btb(ull ip, ull cycle, ull target,
                      unsigned char is_mispredict, unsigned char is_repair);

// ---- direction (oracle_dir_harness.v) ---------------------------------------

extern "C" void oracle_init_dir()
{
  cosim_init_once();
}

extern "C" void oracle_predict_branch(ull ip, ull cycle, unsigned char *pred,
                               unsigned char *known)
{
  cosim_predict_branch(ip, cycle, pred, known);
}

extern "C" void oracle_update_branch(ull ip, ull cycle, unsigned char taken,
                              unsigned char is_mispredict,
                              unsigned char is_repair)
{
  cosim_update_branch(ip, cycle, taken, is_mispredict, is_repair);
}

// ---- target (oracle_tgt_harness.v) -------------------------------------------------

extern "C" void oracle_init_tgt()
{
  cosim_init_once();
}

extern "C" void oracle_predict_target(ull ip, ull cycle, unsigned char *valid,
                               ull *target, unsigned char *is_br,
                               unsigned char *is_jal)
{
  cosim_predict_target(ip, cycle, valid, target, is_br, is_jal);
}

extern "C" void oracle_update_btb(ull ip, ull cycle, ull target,
                           unsigned char is_mispredict, unsigned char is_repair)
{
  cosim_update_btb(ip, cycle, target, is_mispredict, is_repair);
}
